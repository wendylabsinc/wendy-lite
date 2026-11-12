#!/usr/bin/env python3
"""Configure the firmware build from the configurator master configuration.

configure.py takes the same arguments as tools/configurator/solve.py, for
example:

    tools/configure.py board=seeed_xiao app_type=native
    tools/configure.py --values my_board.yaml app_type=wasm

It solves the master configuration (master_config.yaml) and writes
sdkconfig.wendy with the same code as solve.py. sdkconfig.wendy also
contains CONFIG_WENDY_BUILD_PROFILE, the input values as flat YAML (see
solve.py). Then it runs, in the repository root:

    idf.py [--preview] -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.wendy" set-target <chip>

--preview is added only when idf_preview is true (master_config.yaml: the
esp32s31, a preview target of ESP-IDF 6.1).

sdkconfig.wendy comes last, so its lines win over sdkconfig.defaults and
sdkconfig.defaults.<chip> (ESP-IDF adds that file itself).

The chip, the ESP-IDF version (idf_version) and the attributes that the
sdkconfig lines need must be defined, and the combination must be allowed
(no "valid: false" rule matches). The active ESP-IDF (IDF_PATH) must have the
version of idf_version. Otherwise configure.py prints an error and does not
run idf.py. configure.py does not select ESP-IDF: activate the correct
version first.

The configurator code is in tools/configurator/.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "configurator"))

import solve  # noqa: E402
from esp_idf import CHIP, IDF_PREVIEW, IDF_VERSION, check_idf_version, idf_command, preview_option  # noqa: E402


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
