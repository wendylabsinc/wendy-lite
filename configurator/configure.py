#!/usr/bin/env python3
"""Configure the firmware build from the configurator master configuration.

configure.py takes the same arguments as solve.py, for example:

    configurator/configure.py board=seeed_xiao app_type=native
    configurator/configure.py --values my_board.yaml app_type=wasm

It solves the master configuration and writes sdkconfig.wendy with the same
code as solve.py. sdkconfig.wendy also contains CONFIG_WENDY_BUILD_PROFILE,
the input values as flat YAML (see solve.py). Then it runs, in the
repository root:

    idf.py [--preview] -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.wendy" set-target <chip>

--preview is added only when idf_preview is true (master_conf.yaml: the
esp32s31, a preview target of ESP-IDF 6.1).

sdkconfig.wendy comes last, so its lines win over sdkconfig.defaults and
sdkconfig.defaults.<chip> (ESP-IDF adds that file itself).

The chip, the ESP-IDF version (idf_version) and the attributes that the
sdkconfig lines need must be defined, and the combination must be allowed
(no "valid: false" rule matches). The active ESP-IDF (IDF_PATH) must have the
version of idf_version. Otherwise configure.py prints an error and does not
run idf.py. configure.py does not select ESP-IDF: activate the correct
version first.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys

import solve
from conf_model import ConfError

CHIP = "chip"
IDF_VERSION = "idf_version"
IDF_PREVIEW = "idf_preview"

# The ESP-IDF build reads its version from this file. ESP-IDF's
# idf_version_from_cmake() and the eim activation scripts read it too.
_VERSION_CMAKE = os.path.join("tools", "cmake", "version.cmake")
_VERSION_CMAKE_RE = re.compile(r"^\s*set\s*\(\s*IDF_VERSION_(MAJOR|MINOR|PATCH)\s+(\d+)\s*\)")
_VERSION_PARTS = ("MAJOR", "MINOR", "PATCH")

def preview_option(preview: bool) -> list[str]:
    """Return ["--preview"] when preview is true (idf_preview), else [].

    idf.py set-target accepts a preview target (ESP-IDF PREVIEW_TARGETS)
    only with --preview.
    """
    return ["--preview"] if preview else []


def idf_path() -> str:
    """Return IDF_PATH. Raise ConfError when it is not set."""
    path = os.environ.get("IDF_PATH")
    if not path:
        raise ConfError("IDF_PATH is not set, activate ESP-IDF first")
    return path


def idf_command() -> list[str]:
    """Return the command that runs idf.py: [python, $IDF_PATH/tools/idf.py].

    After ESP-IDF activation, idf.py is often not on PATH, but python is the
    ESP-IDF Python. Raise ConfError when IDF_PATH is not usable.
    """
    idf_py = os.path.join(idf_path(), "tools", "idf.py")
    if not os.path.isfile(idf_py):
        raise ConfError(f"{idf_py} not found, check IDF_PATH")
    return [sys.executable, idf_py]


def active_idf_version() -> str:
    """Return the version of the ESP-IDF in IDF_PATH, for example "6.1.0".

    Read $IDF_PATH/tools/cmake/version.cmake. Raise ConfError when the file
    or one of the numbers is missing.
    """
    path = os.path.join(idf_path(), _VERSION_CMAKE)
    parts: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if m := _VERSION_CMAKE_RE.match(line):
                    parts[m.group(1)] = m.group(2)
    except OSError as e:
        raise ConfError(f"{path}: {e.strerror}, check IDF_PATH") from None
    missing = [name for name in _VERSION_PARTS if name not in parts]
    if missing:
        names = ", ".join(f"IDF_VERSION_{name}" for name in missing)
        raise ConfError(f"{path}: {names} not found")
    return ".".join(parts[name] for name in _VERSION_PARTS)


def _version_tuple(text: str) -> tuple[int, int, int]:
    """Return (major, minor, patch). A missing part is 0: "6.1" is (6, 1, 0)."""
    parts = text.split(".")
    if not 1 <= len(parts) <= len(_VERSION_PARTS) or not all(p.isdigit() for p in parts):
        raise ConfError(f'{IDF_VERSION} "{text}" is not a version such as 6.0.3 or 6.1')
    numbers = [int(p) for p in parts]
    numbers += [0] * (len(_VERSION_PARTS) - len(numbers))
    return numbers[0], numbers[1], numbers[2]


def idf_version_matches(wanted: str, active: str) -> bool:
    """Return True when the active ESP-IDF version is the wanted version.

    The match is exact. A missing part is 0, as in the ESP-IDF tags (v6.1 is
    6.1.0): "6.1" accepts 6.1.0, but not 6.1.1.
    """
    return _version_tuple(wanted) == _version_tuple(active)


def check_idf_version(wanted: str) -> None:
    """Raise ConfError when the ESP-IDF in IDF_PATH does not have version wanted."""
    active = active_idf_version()
    if not idf_version_matches(wanted, active):
        raise ConfError(
            f"ESP-IDF {wanted} is needed ({IDF_VERSION}), but IDF_PATH ({idf_path()}) "
            f"has ESP-IDF {active}: activate ESP-IDF {wanted} first"
        )
    print(f"ESP-IDF {active} in {idf_path()} matches {IDF_VERSION} {wanted}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Solve the configurator master configuration, write sdkconfig.wendy, "
        "check the ESP-IDF version and run idf.py set-target with the solved chip."
    )
    solve.add_arguments(parser)
    args = parser.parse_args(argv)

    def body() -> int:
        idf = idf_command()  # check ESP-IDF before anything is written

        solution = solve.solve(
            args,
            extra_required={
                CHIP: ["idf.py set-target"],
                IDF_VERSION: ["ESP-IDF version check"],
                IDF_PREVIEW: ["idf.py --preview"],
            },
        )
        chip = str(solution.values[CHIP])
        preview = solution.values[IDF_PREVIEW] is True
        check_idf_version(str(solution.values[IDF_VERSION]))

        sdkconfig_wendy = solve.relative(args.output, solve.REPO_ROOT)
        command: list[str] = [
            *idf,
            *preview_option(preview),
            "-D",
            f"SDKCONFIG_DEFAULTS=sdkconfig.defaults;{sdkconfig_wendy}",
            "set-target",
            chip,
        ]
        print(f"\nrun in {solve.REPO_ROOT}:\n  {shlex.join(command)}\n")
        sys.stdout.flush()
        rc = subprocess.call(command, cwd=solve.REPO_ROOT)
        return rc if rc >= 0 else 128 - rc

    return solve.run_cli(body)


if __name__ == "__main__":
    sys.exit(main())
