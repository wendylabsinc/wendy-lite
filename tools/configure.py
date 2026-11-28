#!/usr/bin/env python3
"""Configure the firmware build from the configurator master configuration.

configure.py takes the same arguments as tools/configurator/solve.py, for
example:

    tools/configure.py board=seeed_xiao app_type=native
    tools/configure.py --values my_board.yaml app_type=wasm

It solves the master configuration (master_config.yaml) and writes
sdkconfig.defaults.wendy with the same code as solve.py. The file also
contains CONFIG_WENDY_BUILD_PROFILE, the input values as single-line JSON
(see solve.py), and CONFIG_WENDY_VERSION, the version of the source from git (see
tools/configurator/wendy_version.py). solve.py does not write
CONFIG_WENDY_VERSION. Then configure.py runs, in the repository root:

    idf.py [--preview] -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults.wendy" \\
        set-target <chip>

--preview is added only when idf_preview is true (master_config.yaml: the
esp32s31, a preview target of ESP-IDF 6.1).

Native app (--app): the current folder is a native app project, which
replaces the firmware on the device, so it is built with the configuration of
the firmware. This is what the Wendy CLI (wendy run) does before it builds
the app, without the device:

    cd native_apps/blink-rgb
    ../../tools/configure.py --app board=esp32c6_devkit_c_1_n8 app_type=native
    idf.py gen_project_binary

configure.py then writes ./sdkconfig.defaults.wendy, without the
CONFIG_PARTITION_TABLE_* lines (they name a partition CSV file of this
repository), and runs [--preview] set-target <chip> in the current folder,
without -D: the CMakeLists.txt of the project must have

    set(SDKCONFIG_DEFAULTS "sdkconfig.defaults.wendy;sdkconfig.defaults")

before include($ENV{IDF_PATH}/tools/cmake/project.cmake), and the project
must have a sdkconfig.defaults (the app's own defaults, which win).
configure.py checks this first and does not change the project.
CONFIG_WENDY_VERSION is the version of this wendy-lite checkout: pin the
wendy_core dependency of the app (main/idf_component.yml) to the same commit,
or use override_path to this checkout. -o cannot be used with --app.

sdkconfig.defaults.wendy is the only defaults file: master_config.yaml has all
the settings, also those of sdkconfig.defaults and sdkconfig.defaults.<chip>,
which only the old boards/*.cfg builds read. ESP-IDF also reads
sdkconfig.defaults.wendy.<chip>, but this file does not exist.

The chip, the ESP-IDF version (idf_version) and the attributes that the
sdkconfig lines need must be defined, and the combination must be allowed
(no "valid: false" rule matches). The active ESP-IDF (IDF_PATH) must have the
version of idf_version. Otherwise configure.py prints an error and does not
run idf.py. configure.py does not select ESP-IDF: activate the correct
version first.

A warning ("warn" rule of master_config.yaml) does not stop configure.py: it
prints "warning: <message>" after the solve and again after idf.py.

The configurator code is in tools/configurator/.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "configurator"))

from conf_model import ConfError  # noqa: E402
from native_app import APP_DEFAULTS_FILE, PARTITION_TABLE_PREFIX, check_app_project  # noqa: E402
import solve  # noqa: E402
from esp_idf import CHIP, IDF_PREVIEW, IDF_VERSION, check_idf_version, idf_command, preview_option  # noqa: E402
from wendy_version import WENDY_VERSION, version_line, wendy_version  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Solve the configurator master configuration, write sdkconfig.defaults.wendy "
        "(with CONFIG_WENDY_VERSION from git), check the ESP-IDF version and run "
        "idf.py set-target with the solved chip, for the firmware or (--app) for the "
        "native app project in the current folder."
    )
    solve.add_arguments(parser)
    parser.add_argument(
        "--app",
        action="store_true",
        help="the current folder is a native app project: write ./%s without the "
        "%s* lines and run idf.py set-target here; the project CMakeLists.txt must "
        "list the file in SDKCONFIG_DEFAULTS" % (APP_DEFAULTS_FILE, PARTITION_TABLE_PREFIX),
    )
    args = parser.parse_args(argv)
    if args.app:
        if args.output != parser.get_default("output"):
            parser.error("-o cannot be used with --app: the file is ./" + APP_DEFAULTS_FILE)
        args.output = APP_DEFAULTS_FILE
    project = os.getcwd() if args.app else solve.REPO_ROOT

    def body() -> int:
        idf = idf_command()  # check ESP-IDF before anything is written
        if args.app:
            if os.path.realpath(project) == os.path.realpath(solve.REPO_ROOT):
                raise ConfError("--app: the current folder is the wendy-lite repository, not a native app project")
            check_app_project(project)
        version = wendy_version(solve.REPO_ROOT)
        print(f"Wendy version: {version or '(empty)'} ({WENDY_VERSION}, from git)")

        solution = solve.solve(
            args,
            extra_required={
                CHIP: ["idf.py set-target"],
                IDF_VERSION: ["ESP-IDF version check"],
                IDF_PREVIEW: ["idf.py --preview"],
            },
            extra_lines=[version_line(version)],
            drop_prefixes=(PARTITION_TABLE_PREFIX,) if args.app else (),
        )
        chip = str(solution.values[CHIP])
        preview = solution.values[IDF_PREVIEW] is True
        check_idf_version(str(solution.values[IDF_VERSION]))

        command: list[str] = [*idf, *preview_option(preview)]
        if not args.app:
            # A native app project lists the file in its CMakeLists.txt.
            wendy_defaults = solve.relative(args.output, solve.REPO_ROOT)
            command += ["-D", f"SDKCONFIG_DEFAULTS={wendy_defaults}"]
        command += ["set-target", chip]
        print(f"\nrun in {project}:\n  {shlex.join(command)}\n")
        sys.stdout.flush()
        rc = subprocess.call(command, cwd=project)
        # The idf.py output is long: show the warnings of the solve again.
        solve.print_warnings(solution)
        return rc if rc >= 0 else 128 - rc

    return solve.run_cli(body)


if __name__ == "__main__":
    sys.exit(main())
