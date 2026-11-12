"""ESP-IDF helpers of tools/configure.py and test_configure.py.

Find idf.py in IDF_PATH, read the version of the active ESP-IDF and compare
it with idf_version. The names of the attributes that configure.py needs
besides the sdkconfig lines are here too.
"""

from __future__ import annotations

import os
import re
import sys

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
