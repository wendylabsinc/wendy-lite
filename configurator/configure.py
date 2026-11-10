#!/usr/bin/env python3
"""Configure the firmware build from the configurator master configuration.

configure.py takes the same arguments as solve.py, for example:

    configurator/configure.py board=seeed_xiao app_type=native
    configurator/configure.py --values my_board.yaml app_type=wasm

It solves the master configuration and writes sdkconfig.wendy with the same
code as solve.py. Then it runs, in the repository root:

    idf.py -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.wendy" set-target <chip>

sdkconfig.wendy comes last, so its lines win over sdkconfig.defaults and
sdkconfig.defaults.<chip> (ESP-IDF adds that file itself).

The chip and the attributes that the sdkconfig lines need must be defined.
Activate ESP-IDF first: configure.py needs IDF_PATH.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

import solve
from conf_model import ConfError

CHIP = "chip"


def idf_command() -> list[str]:
    """Return the command that runs idf.py: [python, $IDF_PATH/tools/idf.py].

    After ESP-IDF activation, idf.py is often not on PATH, but python is the
    ESP-IDF Python. Raise ConfError when IDF_PATH is not usable.
    """
    idf_path = os.environ.get("IDF_PATH")
    if not idf_path:
        raise ConfError("IDF_PATH is not set, activate ESP-IDF first")
    idf_py = os.path.join(idf_path, "tools", "idf.py")
    if not os.path.isfile(idf_py):
        raise ConfError(f"{idf_py} not found, check IDF_PATH")
    return [sys.executable, idf_py]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Solve the configurator master configuration, write sdkconfig.wendy "
        "and run idf.py set-target with the solved chip."
    )
    solve.add_arguments(parser)
    args = parser.parse_args(argv)

    def body() -> int:
        idf = idf_command()  # check ESP-IDF before anything is written

        solution = solve.solve(args, extra_required={CHIP: ["idf.py set-target"]})
        chip = str(solution.values[CHIP])

        sdkconfig_wendy = solve.relative(args.output, solve.REPO_ROOT)
        command: list[str] = [
            *idf,
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
