#!/usr/bin/env python3
"""Compare the sdkconfig of each old configuration with its new configuration.

Read tools/configurator/conf_migration.yaml. Each entry has:

    old_conf  the old configuration: the name of boards/<old_conf>.cfg
    new_conf  the new configuration: configurator attribute values

The target is the chip that the new configuration gives (master_config.yaml).
For each entry, in the project folder:

1. Old conf: idf.py [--preview] "$(cat boards/<old_conf>.cfg);version.defaults" set-target <target>
2. New conf: tools/configure.py <new_conf as NAME=VALUE ...>
3. Compare the two generated sdkconfig files and report the differences.

--preview is added when the new configuration gives idf_preview: true, as
configure.py does.

Each entry also needs the ESP-IDF version that its new configuration gives
(idf_version). An entry that needs another version than the active ESP-IDF
fails at once, without a set-target run. Thus a run of all the entries needs
one run for each ESP-IDF version.

Before each run, dependencies.lock is reset to its committed version (HEAD),
so both runs start from the same file. Uncommitted changes to it are lost.
build/ is deleted before each run: a failed run can leave a build/ that
idf.py refuses to clean, and all the next runs would then fail.

The test changes the project: sdkconfig, build/, dependencies.lock,
managed_components, sdkconfig.defaults.wendy and version.defaults. After the
test, the project has the new configuration of the last entry. The results are
in tools/configurator/test_results/<old_conf>/.

The comparison skips CONFIG_WENDY_VERSION: configure.py sets it from git, and
the old configuration has no source for it.

Activate ESP-IDF first. Each entry needs two set-target runs (about 1 min each).
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any

import conf_model
from conf_model import ConfError, Model, read_yaml
from esp_idf import (
    CHIP,
    IDF_PREVIEW,
    IDF_VERSION,
    active_idf_version,
    idf_command,
    idf_version_matches,
    preview_option,
)
import solve
from wendy_version import WENDY_VERSION

_HERE = os.path.dirname(os.path.abspath(__file__))
ENTRY_LIST = os.path.join(_HERE, "conf_migration.yaml")
MASTER_CONF = os.path.join(solve.REPO_ROOT, "master_config.yaml")
RESULTS = os.path.join(_HERE, "test_results")
LOCK_FILE = "dependencies.lock"
VERSION_DEFAULTS = "# Release version overlay. Empty: no release version.\n"
NOT_SET = "<not set>"
ABSENT = "<absent>"
# configure.py sets these options from git; the old configuration has no source for them.
NOT_COMPARED = frozenset({WENDY_VERSION})
LOG_TAIL = 20
_NOT_SET_RE = re.compile(r"^# (CONFIG_\w+) is not set$")


@dataclass
class Entry:
    old_conf: str
    new_conf: dict[str, Any]
    cfg: str  # text of boards/<old_conf>.cfg
    target: str | None  # chip from the new configuration
    idf_version: str | None  # ESP-IDF version from the new configuration
    idf_preview: bool | None  # idf.py --preview, from the new configuration
    error: str | None  # why the new configuration cannot be solved


def _shown(path: str) -> str:
    return solve.relative(path, os.getcwd())


def conf_arguments(conf: dict[str, Any]) -> list[str]:
    """Return NAME=VALUE arguments. A YAML boolean is written true or false."""
    return [f"{name}={str(value).lower() if isinstance(value, bool) else value}" for name, value in conf.items()]


def solve_target(
    model: Model, graph: dict[str, list[str]], new_conf: dict[str, Any]
) -> tuple[str, str, bool]:
    """Solve the new configuration without printing.

    Return its chip, ESP-IDF version and idf_preview.
    """
    inputs = {}
    for name, raw in new_conf.items():
        attr = model.attributes.get(name)
        if attr is None:
            raise ConfError(f'unknown attribute "{name}"')
        inputs[name] = attr.normalize(raw)
    solution = conf_model.evaluate(model, graph, inputs, {name: "new_conf" for name in inputs})
    if not solution.allowed:
        raise ConfError(conf_model.not_allowed_text(solution.forbidden))
    for name in (CHIP, IDF_VERSION, IDF_PREVIEW):
        if solution.values.get(name) is None:
            raise ConfError(f"{name} is undefined")
    return str(solution.values[CHIP]), str(solution.values[IDF_VERSION]), solution.values[IDF_PREVIEW] is True


def load_entries(list_path: str, model: Model, graph: dict[str, list[str]]) -> list[Entry]:
    """Read the old conf -> new conf list and solve the target of each entry."""
    shown = _shown(list_path)
    data = read_yaml(list_path)
    if data is None:
        data = []
    if not isinstance(data, list):
        raise ConfError(f"{shown}: expected a list of entries, each with old_conf and new_conf")

    entries = []
    seen: set[str] = set()
    for i, item in enumerate(data):
        if not isinstance(item, dict) or set(item) != {"old_conf", "new_conf"}:
            raise ConfError(f"{shown}: [{i}]: expected a map with old_conf and new_conf")
        old_conf, new_conf = item["old_conf"], item["new_conf"]
        if not isinstance(old_conf, str) or not old_conf:
            raise ConfError(f"{shown}: [{i}]: old_conf must be a name")
        if old_conf in seen:
            raise ConfError(f"{shown}: {old_conf}: given twice")
        seen.add(old_conf)
        if not isinstance(new_conf, dict) or not new_conf:
            raise ConfError(f"{shown}: {old_conf}: new_conf must be a map with one or more values")
        cfg_path = os.path.join(solve.REPO_ROOT, "boards", f"{old_conf}.cfg")
        if not os.path.isfile(cfg_path):
            raise ConfError(f"{shown}: {old_conf}: {_shown(cfg_path)} not found")
        with open(cfg_path, encoding="utf-8") as f:
            cfg = f.read().strip()

        target, idf_version, idf_preview, error = None, None, None, None
        try:
            target, idf_version, idf_preview = solve_target(model, graph, new_conf)
        except ConfError as e:
            error = f"new_conf: {e}"
        entries.append(Entry(old_conf, new_conf, cfg, target, idf_version, idf_preview, error))
    return entries


def reset_lock_file() -> None:
    """Reset dependencies.lock to its committed version."""
    try:
        subprocess.run(
            ["git", "restore", "--source=HEAD", "--worktree", "--", LOCK_FILE],
            cwd=solve.REPO_ROOT,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        raise ConfError(f"cannot reset {LOCK_FILE}: {e.stderr.decode().strip()}") from None
    print(f"  reset {LOCK_FILE} to HEAD")


def _print_tail(path: str) -> None:
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()[-LOG_TAIL:]
    for line in lines:
        print(f"    | {line.rstrip()}")


def run_step(label: str, command: list[str], shown: list[str], out: str, stem: str) -> bool:
    """Run one set-target command in the project; keep its sdkconfig as sdkconfig.<stem>."""
    src = solve.REPO_ROOT
    sdkconfig = os.path.join(src, "sdkconfig")
    if os.path.exists(sdkconfig):
        os.remove(sdkconfig)  # so a failed run cannot leave an old file
    # A failed run can leave a build/ without CMakeCache.txt. idf.py then
    # refuses to clean it, and set-target fails at once.
    shutil.rmtree(os.path.join(src, "build"), ignore_errors=True)
    reset_lock_file()
    log = os.path.join(out, f"{stem}.log")
    print(f"  {label}: {shlex.join(shown)}")
    sys.stdout.flush()

    start = time.monotonic()
    with open(log, "w", encoding="utf-8") as f:
        f.write(f"$ {shlex.join(command)}\n(in {src})\n\n")
        f.flush()
        rc = subprocess.call(command, cwd=src, stdout=f, stderr=subprocess.STDOUT)
    seconds = time.monotonic() - start

    if rc != 0 or not os.path.isfile(sdkconfig):
        print(f"  {label}: FAILED, exit code {rc}, after {seconds:.0f} s. Log: {_shown(log)}")
        _print_tail(log)
        return False
    shutil.copy2(sdkconfig, os.path.join(out, f"sdkconfig.{stem}"))
    print(f"  {label}: ok ({seconds:.0f} s)")
    return True


def parse_sdkconfig(path: str) -> dict[str, str]:
    """Return {CONFIG_X: value}. "# CONFIG_X is not set" gives <not set>."""
    values = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("CONFIG_") and "=" in line:
                name, _, value = line.partition("=")
                values[name] = value
            elif m := _NOT_SET_RE.match(line):
                values[m.group(1)] = NOT_SET
    return values


def compare(old: dict[str, str], new: dict[str, str]) -> list[tuple[str, str, str]]:
    """Return (name, old value, new value) for each difference, sorted by name.

    The options in NOT_COMPARED are skipped.
    """
    diffs = []
    for name in sorted((old.keys() | new.keys()) - NOT_COMPARED):
        a, b = old.get(name, ABSENT), new.get(name, ABSENT)
        if a != b:
            diffs.append((name, a, b))
    return diffs


def format_diffs(diffs: list[tuple[str, str, str]]) -> list[str]:
    name_width = max(len(d[0]) for d in diffs)
    old_width = min(max(len(d[1]) for d in diffs), 40)
    return [f"{name:<{name_width}}  old: {a:<{old_width}}  new: {b}" for name, a, b in diffs]


def run_entry(entry: Entry, idf: list[str], active_version: str) -> str:
    """Run the old and the new configuration of one entry and compare. Return its status.

    active_version is the version of the active ESP-IDF.
    """
    out = os.path.join(RESULTS, entry.old_conf)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    if entry.error:
        print(f"  error: {entry.error}")
        return f"failed: {entry.error}"
    assert entry.target is not None and entry.idf_version is not None
    if not idf_version_matches(entry.idf_version, active_version):
        status = f"needs ESP-IDF {entry.idf_version}, active ESP-IDF is {active_version}"
        print(f"  error: {status}")
        return f"failed: {status}"

    with open(os.path.join(solve.REPO_ROOT, "version.defaults"), "w", encoding="utf-8") as f:
        f.write(VERSION_DEFAULTS)
    old_args = [*preview_option(entry.idf_preview is True), f"{entry.cfg};version.defaults", "set-target", entry.target]
    if not run_step("old conf", [*idf, *old_args], ["idf.py", *old_args], out, "old_conf"):
        return "failed: old conf"

    new_args = conf_arguments(entry.new_conf)
    configure_py = os.path.join(solve.REPO_ROOT, "tools", "configure.py")
    shown = ["tools/configure.py", *new_args]
    if not run_step("new conf", [sys.executable, configure_py, *new_args], shown, out, "new_conf"):
        return "failed: new conf"

    diffs = compare(
        parse_sdkconfig(os.path.join(out, "sdkconfig.old_conf")),
        parse_sdkconfig(os.path.join(out, "sdkconfig.new_conf")),
    )
    diff_file = os.path.join(out, "diff.txt")
    if not diffs:
        print("  result: same sdkconfig")
        with open(diff_file, "w", encoding="utf-8") as f:
            f.write("same sdkconfig\n")
        return "same"

    lines = format_diffs(diffs)
    with open(diff_file, "w", encoding="utf-8") as f:
        f.write(f"{entry.old_conf}: {len(diffs)} differences (old conf vs new conf)\n")
        f.write("".join(line + "\n" for line in lines))
    print(f"  result: {len(diffs)} differences (also in {_shown(diff_file)})")
    for line in lines:
        print(f"    {line}")
    return f"{len(diffs)} differences"


def print_entries(entries: list[Entry]) -> None:
    print(f"== Entries in {_shown(ENTRY_LIST)}")
    for entry in entries:
        print(f"  {entry.old_conf}")
        print(f"      old conf: boards/{entry.old_conf}.cfg: {entry.cfg}")
        print(f"      new conf: {' '.join(conf_arguments(entry.new_conf))}")
        if entry.error:
            print(f"      error:    {entry.error}")
        else:
            print(f"      target:   {entry.target}")
            print(f"      ESP-IDF:  {entry.idf_version}{', preview' if entry.idf_preview else ''}")
    if not entries:
        print("  (none)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="For each entry in tools/configurator/conf_migration.yaml, compare the sdkconfig "
        "of the old configuration (boards/<old_conf>.cfg) with the sdkconfig of the new "
        "configuration (configurator values). Runs in the project folder: it changes sdkconfig, "
        "build/, dependencies.lock (reset to HEAD before each run), managed_components, "
        "sdkconfig.defaults.wendy and version.defaults. Results go to "
        "tools/configurator/test_results/.",
    )
    parser.add_argument(
        "--board",
        action="append",
        metavar="OLD_CONF",
        help="test only this entry, by its old_conf name (give it more times for more entries)",
    )
    parser.add_argument(
        "--list", action="store_true", help="list the entries, their targets and ESP-IDF versions, and stop"
    )
    args = parser.parse_args(argv)

    def body() -> int:
        model = conf_model.load(_shown(MASTER_CONF))
        graph = conf_model.build_graph(model)
        entries = load_entries(ENTRY_LIST, model, graph)
        if args.board:
            known = {e.old_conf for e in entries}
            unknown = [name for name in args.board if name not in known]
            if unknown:
                raise ConfError(f"not in {os.path.basename(ENTRY_LIST)}: {', '.join(unknown)}")
            entries = [e for e in entries if e.old_conf in args.board]
        print_entries(entries)
        if args.list or not entries:
            return 1 if any(e.error for e in entries) else 0

        idf = idf_command()
        active_version = active_idf_version()
        print(f"\nactive ESP-IDF: {active_version}")
        statuses: dict[str, str] = {}
        for entry in entries:
            print(f"\n== {entry.old_conf}")
            statuses[entry.old_conf] = run_entry(entry, idf, active_version)

        print(f"\n== Summary (results in {_shown(RESULTS)})")
        width = max(len(name) for name in statuses)
        for name, status in statuses.items():
            print(f"  {name:<{width}}  {status}")
        return 0 if all(s == "same" for s in statuses.values()) else 1

    return solve.run_cli(body)


if __name__ == "__main__":
    sys.exit(main())
