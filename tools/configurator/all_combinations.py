#!/usr/bin/env python3
"""Try all the combinations of input values of the master configuration.

Read master_config.yaml (repository root). Go through the attributes as the
Wendy CLI does (docs/configurator.md, "Order of the questions"): in the order
of the dependency graph, each needed attribute that no rule sets gets each of
its values in turn. A needed attribute is one that the sdkconfig lines, chip,
idf_version or idf_preview need, directly or through the rules (the values
that tools/configure.py needs). The other attributes are never given.

The values of an attribute are its enum, or true and false for a boolean. For
an attribute without enum, the script uses one value of each set of values
that the conditions cannot tell apart: for a size, 0 and v-1, v, v+1 for each
size v in a condition; for a string, each string in a condition and one other
value.

Each full combination gets the checks of solve.py:

    OK           the configuration is allowed
    not allowed  a "valid: false" rule matches: the combination is skipped
    error        a conflict or a missing value: a problem in the master
                 configuration

It is also an error when the Wendy CLI must ask an internal attribute (one
that is not in the display section): when 2 or more of its values give an OK
combination.

Variants. The OK combinations that give the same result make one variant. The
same result is the same chip, idf_version, idf_preview and the same sdkconfig
lines, in the same order. CONFIG_WENDY_BUILD_PROFILE (the input values) and
CONFIG_WENDY_VERSION are not part of the result. For example,
board=esp32c6_devkit_m_1 gives the same firmware as board=custom with
chip=esp32c6 and flash_size=4MiB. The main combination of a variant is the one
with the fewest input values (on a tie, the first one). The other combinations
are its aliases. The script prints the variants with aliases (--all: all the
variants).

Each combination is written as NAME=VALUE arguments of solve.py.

Exit code: 1 when there is an error, else 0.

tests/build-variants/check_variants.py uses the functions of this file
(check_combination, result_key) to check the variants that CI compiles.

Examples:

    tools/configurator/all_combinations.py
    tools/configurator/all_combinations.py --all
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from typing import Any

import conf_model
from conf_model import SDKCONFIG, BoolOp, Compare, ConfError, Model, Node, Not, Solution
from esp_idf import CHIP, IDF_PREVIEW, IDF_VERSION
import solve

# What configure.py needs besides the sdkconfig lines (as its extra_required).
CONFIGURE_NEEDS = {
    CHIP: ["idf.py set-target"],
    IDF_VERSION: ["ESP-IDF version check"],
    IDF_PREVIEW: ["idf.py --preview"],
}

OK = "OK"
NOT_ALLOWED = "not allowed"
ERROR = "error"


@dataclass
class Results:
    ok: list[tuple[dict[str, Any], Solution]] = field(default_factory=list)
    not_allowed: list[tuple[dict[str, Any], str]] = field(default_factory=list)
    errors: list[tuple[dict[str, Any], str]] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.ok) + len(self.not_allowed) + len(self.errors)


@dataclass
class Variant:
    """The OK combinations with the same result."""

    main: dict[str, Any]  # the main combination
    aliases: list[dict[str, Any]]  # the other combinations
    solution: Solution  # of the main combination


# --- Walk ------------------------------------------------------------------


def _compares(node: Node | None) -> list[Compare]:
    """Return the comparisons in a condition."""
    if isinstance(node, Compare):
        return [node]
    if isinstance(node, Not):
        return _compares(node.operand)
    if isinstance(node, BoolOp):
        return [c for o in node.operands for c in _compares(o)]
    return []


def attribute_values(model: Model, name: str) -> list[Any]:
    """Return the values to try for an attribute.

    The enum, or true and false for a boolean. Without enum: one value of
    each set of values that the conditions cannot tell apart.
    """
    attr = model.attributes[name]
    if attr.enum is not None:
        return list(attr.enum)
    if attr.type == "boolean":
        return [True, False]
    literals = {c.value for rule in model.rules for c in _compares(rule.condition) if c.attr.name == name}
    if attr.type == "size":
        values = {0}
        for v in literals:
            values |= {n for n in (v - 1, v, v + 1) if n >= 0}
        return sorted(values)
    other = "other"
    while other in literals:
        other += "_"
    return [*sorted(literals), other]


def needed_attributes(graph: dict[str, list[str]]) -> set[str]:
    """Return the attributes that the sdkconfig lines and configure.py need.

    An attribute is needed directly or through the rules: a rule that sets a
    needed attribute reads it.
    """
    needed: set[str] = set()
    todo = [SDKCONFIG, *CONFIGURE_NEEDS]
    while todo:
        node = todo.pop()
        if node not in needed:
            needed.add(node)
            todo.extend(graph[node])
    needed.discard(SDKCONFIG)
    return needed


def required_attributes(model: Model, graph: dict[str, list[str]]) -> dict[str, list[str]]:
    """Return the attributes that must be defined, as configure.py requires them."""
    required = conf_model.sdkconfig_requirements(graph)
    for name, needed_by in CONFIGURE_NEEDS.items():
        if name not in model.attributes:
            raise ConfError(f'{", ".join(needed_by)} needs attribute "{name}", but {model.path} does not declare it')
        required.setdefault(name, []).extend(needed_by)
    return required


def check_combination(
    model: Model, graph: dict[str, list[str]], required: dict[str, list[str]], inputs: dict[str, Any]
) -> tuple[str, Any]:
    """Do the checks of solve.py on a full combination.

    Return (OK, solution), (NOT_ALLOWED, text) or (ERROR, text).
    """
    try:
        solution = conf_model.evaluate(model, graph, inputs)
    except ConfError as e:
        return ERROR, str(e)
    if not solution.allowed:
        return NOT_ALLOWED, conf_model.not_allowed_text(solution.forbidden)
    missing = conf_model.find_missing(graph, solution.values, required)
    if missing:
        return ERROR, f"missing value(s): {', '.join(missing)}"
    return OK, solution


def display_names(path: str) -> set[str]:
    """Return the attributes in the display section (the visible ones)."""
    data = conf_model.read_yaml(path)
    display = data.get(conf_model.DISPLAY) if isinstance(data, dict) else None
    return set(display) if isinstance(display, dict) else set()


def combination_text(model: Model, inputs: dict[str, Any]) -> str:
    """Return the inputs as NAME=VALUE arguments of solve.py, in declaration order."""
    parts = []
    for name, attr in model.attributes.items():
        if name in inputs:
            value = inputs[name]
            text = ("true" if value else "false") if attr.type == "boolean" else attr.to_yaml(value)
            parts.append(f"{name}={text}")
    return " ".join(parts) if parts else "(no input)"


def walk_all(model: Model, display: set[str]) -> Results:
    """Try all the combinations. Return the OK, not allowed and error combinations."""
    graph = conf_model.build_graph(model)
    rank = {node: i for i, node in enumerate(conf_model.topo_order(graph))}
    order = [node for node in rank if node != SDKCONFIG]
    needed = needed_attributes(graph)
    required = required_attributes(model, graph)

    # The value of an attribute is final after the rules whose first target
    # is at or before it: their conditions read only attributes before it.
    # A full evaluation with partial inputs is not exact: "!wendy_net" is
    # true while wendy_net is undefined.
    setters = [rule for rule in model.rules if not rule.forbidden]
    first = [min(rank[t] for t in rule.targets()) for rule in setters]
    prefix = {
        name: Model(model.path, model.attributes, [r for r, f in zip(setters, first) if f <= rank[name]])
        for name in order
    }
    results = Results()

    def finish(inputs: dict[str, Any]) -> int:
        """Check a full combination. Return 1 when it is OK."""
        status, value = check_combination(model, graph, required, inputs)
        if status == OK:
            results.ok.append((inputs, value))
            return 1
        (results.not_allowed if status == NOT_ALLOWED else results.errors).append((inputs, value))
        return 0

    def walk(i: int, inputs: dict[str, Any]) -> int:
        """Try the values from order[i]. Return the number of OK combinations."""
        while i < len(order) and order[i] not in needed:
            i += 1
        if i == len(order):
            return finish(inputs)
        name = order[i]
        try:
            values = conf_model.evaluate(prefix[name], graph, inputs).values
        except ConfError as e:
            results.errors.append((inputs, str(e)))
            return 0
        if values[name] is not None:
            return walk(i + 1, inputs)

        counts = [walk(i + 1, {**inputs, name: value}) for value in attribute_values(model, name)]
        allowed = sum(1 for c in counts if c)
        if name not in display and allowed > 1:
            results.errors.append(
                (
                    inputs,
                    f"{name} is internal (not in {conf_model.DISPLAY}), but {allowed} of its values "
                    "give an allowed configuration: the Wendy CLI must ask it and stops",
                )
            )
        return sum(counts)

    walk(0, {})
    return results


# --- Variants --------------------------------------------------------------


def result_key(solution: Solution) -> tuple[Any, ...]:
    """Return what makes the firmware: the target, ESP-IDF and the sdkconfig lines."""
    values = solution.values
    return values[CHIP], values[IDF_VERSION], values[IDF_PREVIEW], tuple(solution.sdkconfig)


def build_variants(results: Results) -> list[Variant]:
    """Group the OK combinations by result, in the order of their first combination.

    The main combination has the fewest input values; on a tie, the first one.
    """
    groups: dict[tuple[Any, ...], list[tuple[dict[str, Any], Solution]]] = {}
    for inputs, solution in results.ok:
        groups.setdefault(result_key(solution), []).append((inputs, solution))
    variants = []
    for members in groups.values():
        main = min(range(len(members)), key=lambda i: (len(members[i][0]), i))
        aliases = [inputs for i, (inputs, _) in enumerate(members) if i != main]
        variants.append(Variant(members[main][0], aliases, members[main][1]))
    return variants


# --- Report ----------------------------------------------------------------


def print_report(model: Model, results: Results, variants: list[Variant], show_all: bool) -> None:
    print("== Summary")
    print(
        f"  {results.count} combinations: {len(results.ok)} OK, "
        f"{len(results.not_allowed)} not allowed, {len(results.errors)} errors"
    )
    with_aliases = sum(1 for v in variants if v.aliases)
    print(f"  {len(variants)} variants (different results), {with_aliases} with aliases")

    for title, items in (("Errors", results.errors), ("Not allowed", results.not_allowed)):
        print(f"\n== {title}")
        for inputs, text in items:
            print(f"  {combination_text(model, inputs)}")
            print(f"      {text}")
        if not items:
            print("  (none)")

    print("\n== All variants" if show_all else "\n== Variants with aliases")
    shown = 0
    attrs = model.attributes
    for number, variant in enumerate(variants, 1):
        if not variant.aliases and not show_all:
            continue
        shown += 1
        values = variant.solution.values
        idf = f"ESP-IDF {attrs[IDF_VERSION].format(values[IDF_VERSION])}{' (preview)' if values[IDF_PREVIEW] else ''}"
        print(f"  [{number}] {CHIP} {attrs[CHIP].format(values[CHIP])}, {idf}, "
              f"{len(variant.solution.sdkconfig)} {SDKCONFIG} lines")
        print(f"      main   {combination_text(model, variant.main)}")
        for alias in variant.aliases:
            print(f"      alias  {combination_text(model, alias)}")
    if not shown:
        print("  (none)")


# --- Main ------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Try all the combinations of input values of the master configuration. "
        "Report the errors and the not allowed combinations, and group the combinations that "
        "give the same firmware (chip, ESP-IDF version and sdkconfig lines) into variants."
    )
    parser.add_argument(
        "--conf",
        default=solve.relative(os.path.join(solve.REPO_ROOT, "master_config.yaml"), os.getcwd()),
        help="master configuration (default: %(default)s)",
    )
    parser.add_argument(
        "--all", action="store_true", help="list all the variants, also the ones without aliases"
    )
    args = parser.parse_args(argv)

    def body() -> int:
        model = conf_model.load(args.conf)
        results = walk_all(model, display_names(args.conf))
        print_report(model, results, build_variants(results), args.all)
        return 1 if results.errors else 0

    return solve.run_cli(body)


if __name__ == "__main__":
    sys.exit(main())
