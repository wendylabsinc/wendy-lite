"""Native app project checks of tools/configure.py --app.

A native app project gets the configuration of the Wendy Lite build through
sdkconfig.defaults.wendy, in the project folder. Its top-level CMakeLists.txt
must list this file in SDKCONFIG_DEFAULTS before the include of
project.cmake, with the app's own sdkconfig.defaults after it (a line there
wins). The Wendy CLI (wendy run) checks the same project setup:
WendyOS go/internal/cli/espidftoolchain/sdkconfig_defaults.go, which also
adds the line. This module only checks it.
"""

from __future__ import annotations

import os
import re

from conf_model import ConfError

# The sdkconfig defaults file of a native app project (WendyOS
# litebuild.AppDefaultsFile).
APP_DEFAULTS_FILE = "sdkconfig.defaults.wendy"

# The line of the project CMakeLists.txt (WendyOS SdkconfigDefaultsLine).
SDKCONFIG_DEFAULTS_LINE = 'set(SDKCONFIG_DEFAULTS "sdkconfig.defaults.wendy;sdkconfig.defaults")'

# The firmware lines of the partition table name a partition CSV file of the
# wendy-lite repository, which an app project does not have. The app file
# leaves them out (WendyOS litebuild.AppDefaultsText).
PARTITION_TABLE_PREFIX = "CONFIG_PARTITION_TABLE_"

# The same expressions as WendyOS sdkconfig_defaults.go, on comment-masked text.
_PROJECT_INCLUDE = re.compile(
    r'^[\t ]*include[\t ]*\([\t ]*"?\$ENV\{IDF_PATH\}/tools/cmake/project\.cmake"?[\t ]*\)', re.I | re.M
)
_SET_SDKCONFIG_DEFAULTS = re.compile(r"\bset[\t ]*\([\t ]*SDKCONFIG_DEFAULTS\b[^)]*\)", re.I)
_WANT_SDKCONFIG_DEFAULTS = re.compile(
    r'set[\t ]*\([\t ]*SDKCONFIG_DEFAULTS[\t ]+"sdkconfig\.defaults\.wendy;sdkconfig\.defaults"[\t ]*\)', re.I
)
_SDKCONFIG_DEFAULTS_WORD = re.compile(r"\bSDKCONFIG_DEFAULTS\b")


def _bracket_open(text: str, start: int) -> int | None:
    """Return the number of = of a bracket opening [[ or [=...=[ at start, else None."""
    if start >= len(text) or text[start] != "[":
        return None
    eq = 0
    while start + eq + 1 < len(text) and text[start + eq + 1] == "=":
        eq += 1
    if start + eq + 1 < len(text) and text[start + eq + 1] == "[":
        return eq
    return None


def mask_cmake_comments(text: str) -> str:
    """Replace the CMake comments of text with spaces, keep the offsets and newlines.

    A comment is # to the end of the line, or a bracket comment #[[ ... ]]
    (or #[==[ ... ]==]). A # in a quoted argument is not a comment.
    """
    masked = list(text)

    def blank(start: int, end: int) -> None:
        for i in range(start, end):
            if masked[i] not in "\r\n":
                masked[i] = " "

    in_quote = False
    i = 0
    while i < len(text):
        c = text[i]
        if in_quote and c == "\\":
            i += 1
        elif c == '"':
            in_quote = not in_quote
        elif not in_quote and c == "#":
            eq = _bracket_open(text, i + 1)
            if eq is not None:
                closing = "]" + "=" * eq + "]"
                j = text.find(closing, i + 1)
                end = len(text) if j < 0 else j + len(closing)
            else:
                j = text.find("\n", i)
                end = len(text) if j < 0 else j
            blank(i, end)
            i = end - 1
        i += 1
    return "".join(masked)


def check_app_project(project: str) -> None:
    """Check that the project folder is set up for sdkconfig.defaults.wendy.

    The top-level CMakeLists.txt must set SDKCONFIG_DEFAULTS_LINE before the
    include of project.cmake and use SDKCONFIG_DEFAULTS nowhere else, and
    sdkconfig.defaults must exist (ESP-IDF stops when a file of
    SDKCONFIG_DEFAULTS does not exist). Raise ConfError when not.
    """
    path = os.path.join(project, "CMakeLists.txt")
    if not os.path.isfile(path):
        raise ConfError(
            f"{project} has no CMakeLists.txt: run configure.py --app in the folder of the native app project"
        )
    with open(path, encoding="utf-8") as f:
        masked = mask_cmake_comments(f.read())
    manual = (
        f"add {SDKCONFIG_DEFAULTS_LINE} to CMakeLists.txt before "
        "include($ENV{IDF_PATH}/tools/cmake/project.cmake), and use SDKCONFIG_DEFAULTS nowhere else"
    )
    include = _PROJECT_INCLUDE.search(masked)
    if include is None:
        raise ConfError(f"CMakeLists.txt has no include($ENV{{IDF_PATH}}/tools/cmake/project.cmake): {manual}")
    sets = list(_SET_SDKCONFIG_DEFAULTS.finditer(masked))
    for m in sets:
        if not _WANT_SDKCONFIG_DEFAULTS.fullmatch(m.group(0)):
            raise ConfError(f"CMakeLists.txt sets SDKCONFIG_DEFAULTS to another value: {manual}")
        if m.start() > include.start():
            raise ConfError(f"CMakeLists.txt sets SDKCONFIG_DEFAULTS after the include of project.cmake: {manual}")
    if len(_SDKCONFIG_DEFAULTS_WORD.findall(masked)) != len(sets):
        raise ConfError(f"CMakeLists.txt uses SDKCONFIG_DEFAULTS in another way: {manual}")
    if not sets:
        raise ConfError(f"CMakeLists.txt does not set SDKCONFIG_DEFAULTS: {manual}")
    if not os.path.isfile(os.path.join(project, "sdkconfig.defaults")):
        raise ConfError(
            "the project has no sdkconfig.defaults, a file of SDKCONFIG_DEFAULTS: create it, "
            "a comment line is enough (the app's own defaults, which win over sdkconfig.defaults.wendy)"
        )
