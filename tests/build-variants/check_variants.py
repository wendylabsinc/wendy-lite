#!/usr/bin/env python3
"""Check the variants that CI compiles, without compile and without ESP-IDF.

Read tests/build-variants/variants.yaml (written by hand) and the master
configuration (master_config.yaml). For each variant:

- the combination and each alias must be OK: the checks of solve.py (no
  conflict, no missing value, no "valid: false" rule) pass, so they give
  sdkconfig lines;
- each alias must give the same result as the combination: the same chip,
  idf_version, idf_preview and the same sdkconfig lines, in the same order.
  Then the sdkconfig after idf.py set-target is the same too, so CI does not
  compile the aliases;
- chip, idf_version and idf_preview in the file must be the values that the
  combination gives (CI selects the ESP-IDF container with idf_version).

The variants with tested: false are checked too.

Exit code: 1 when there is a problem, else 0.

Examples:

    tests/build-variants/check_variants.py
    tests/build-variants/check_variants.py --conf my_master_config.yaml other_variants.yaml
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import sys
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))  # tests/build-variants/ -> root
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "configurator"))

import all_combinations  # noqa: E402
from all_combinations import CONFIGURE_NEEDS, ERROR, NOT_ALLOWED, OK, check_combination, result_key  # noqa: E402
import conf_model  # noqa: E402
from conf_model import SDKCONFIG, ConfError, Model, Solution  # noqa: E402
from esp_idf import CHIP, IDF_PREVIEW, IDF_VERSION  # noqa: E402
import solve  # noqa: E402

VARIANTS_FILE = os.path.join(_HERE, "variants.yaml")
VARIANTS_FORMAT = "1.0"


@dataclass
class Entry:
    """A variant of the variants file."""

    combination: str
    aliases: list[str]
    fields: dict[str, Any]  # chip, idf_version and idf_preview, as written
    tested: bool


def read_variants(path: str) -> list[Entry]:
    """Read and check the format of the variants file."""
    shown = solve.relative(path, os.getcwd())
    data = conf_model.read_yaml(path)
    if not isinstance(data, dict) or not isinstance(data.get("variants"), list):
        raise ConfError(f"{shown}: expected a map with format_version and variants")
    if str(data.get("format_version")) != VARIANTS_FORMAT:
        raise ConfError(f'{shown}: format_version must be "{VARIANTS_FORMAT}"')
    entries = []
    for i, item in enumerate(data["variants"]):
        where = f"{shown}: variants[{i}]"
        if not isinstance(item, dict):
            raise ConfError(f"{where}: expected a map")
        combination, tested, aliases = item.get("combination"), item.get("tested"), item.get("aliases")
        if not isinstance(combination, str) or not combination.strip():
            raise ConfError(f"{where}: combination must be NAME=VALUE text")
        if not isinstance(tested, bool):
            raise ConfError(f"{where}: tested must be true or false")
        if aliases is None:  # "aliases:" with no item
            aliases = []
        if not isinstance(aliases, list) or not all(isinstance(a, str) for a in aliases):
            raise ConfError(f"{where}: aliases must be a list of NAME=VALUE texts")
        missing = [name for name in CONFIGURE_NEEDS if name not in item]
        if missing:
            raise ConfError(f"{where}: {', '.join(missing)} missing")
        entries.append(Entry(combination, aliases, {name: item[name] for name in CONFIGURE_NEEDS}, tested))
    return entries


def _difference(main: Solution, alias: Solution) -> list[str]:
    """Return how the result of an alias is different from the result of its combination."""
    lines = []
    for name in (CHIP, IDF_VERSION, IDF_PREVIEW):
        if main.values[name] != alias.values[name]:
            lines.append(f"{name}: {alias.values[name]} instead of {main.values[name]}")
    if main.sdkconfig != alias.sdkconfig:
        more = [line for line in alias.sdkconfig if line not in main.sdkconfig]
        fewer = [line for line in main.sdkconfig if line not in alias.sdkconfig]
        if not more and not fewer:
            lines.append(f"same {SDKCONFIG} lines, in another order")
        lines += [f"+ {line}" for line in more] + [f"- {line}" for line in fewer]
    return lines


def check_entries(model: Model, entries: list[Entry]) -> list[tuple[str, list[str]]]:
    """Solve each combination and alias of the variants file. Return the problems."""
    graph = conf_model.build_graph(model)
    required = all_combinations.required_attributes(model, graph)

    def solve_text(text: str) -> tuple[str, Any]:
        try:
            values = conf_model.parse_assignments(model, text.split())
        except ConfError as e:
            return ERROR, str(e)
        inputs = {name: value for name, value in values.items() if value is not None}
        return check_combination(model, graph, required, inputs)

    def status_text(status: str, text: str) -> str:
        return text if status == NOT_ALLOWED else f"{status}: {text}"  # text: "not allowed: ..."

    problems = []
    for entry in entries:
        status, main = solve_text(entry.combination)
        if status != OK:
            problems.append((entry.combination, [f"combination, {status_text(status, main)}"]))
            continue
        wrong = []
        for name, raw in entry.fields.items():
            attr = model.attributes[name]
            try:
                same = attr.normalize(raw) == main.values[name]
            except ConfError:
                same = False
            if not same:
                wrong.append(f"{name}: {raw} in the file, the combination gives {attr.format(main.values[name])}")
        if wrong:
            problems.append((entry.combination, wrong))
        for alias in entry.aliases:
            status, value = solve_text(alias)
            if status != OK:
                problems.append((alias, [f"alias of {entry.combination}, {status_text(status, value)}"]))
            elif result_key(value) != result_key(main):
                problems.append(
                    (alias, [f"alias of {entry.combination}: not the same result", *_difference(main, value)])
                )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the variants that CI compiles: each combination and alias is allowed, "
        "each alias gives the same chip, ESP-IDF version and sdkconfig lines as its combination, "
        "and chip, idf_version and idf_preview are correct. No compile, no ESP-IDF."
    )
    parser.add_argument(
        "variants",
        nargs="?",
        default=solve.relative(VARIANTS_FILE, os.getcwd()),
        help="variants file (default: %(default)s)",
    )
    parser.add_argument(
        "--conf",
        default=solve.relative(os.path.join(REPO_ROOT, "master_config.yaml"), os.getcwd()),
        help="master configuration (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    def body() -> int:
        model = conf_model.load(args.conf)
        entries = read_variants(args.variants)
        print(f"== Variants in {args.variants} (master configuration: {args.conf})")
        for entry in entries:
            aliases = len(entry.aliases)
            note = f"{aliases} alias{'es' if aliases != 1 else ''}" + ("" if entry.tested else ", not tested")
            print(f"  {entry.combination}  ({note})")

        problems = check_entries(model, entries)
        print("\n== Problems")
        for combination, lines in problems:
            print(f"  {combination}")
            for line in lines:
                print(f"      {line}")
        if not problems:
            print("  (none)")
        aliases = sum(len(e.aliases) for e in entries)
        print(f"\n{len(entries)} variants, {aliases} aliases: {len(problems)} problems")
        return 1 if problems else 0

    return solve.run_cli(body)


if __name__ == "__main__":
    sys.exit(main())
