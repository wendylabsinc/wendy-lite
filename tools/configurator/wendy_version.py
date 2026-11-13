"""The version of the wendy-lite source, from git, for tools/configure.py.

configure.py writes it to sdkconfig.defaults.wendy as CONFIG_WENDY_VERSION
(components/wendy_core/Kconfig). The value is:

- X.Y.Z when HEAD has the tag vX.Y.Z (the release tag format of
  .github/workflows/build.yml). When HEAD has several of these tags, the
  highest version is used.
- else the short hash of HEAD (git rev-parse --short HEAD), also when HEAD has
  another tag, for example v1.0.0-rc1.
- "-dirty" is added when tracked files have uncommitted changes, as
  git describe --dirty does. Untracked files are ignored.
- "" when git is not available or the folder is not a git checkout.
"""

from __future__ import annotations

import re
import subprocess
import sys

from conf_model import kconfig_string_line

WENDY_VERSION = "CONFIG_WENDY_VERSION"

_VERSION_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def _git(repo: str, *args: str) -> str | None:
    """Return the stripped output of git -C repo args, or None when git fails."""
    try:
        result = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=False)
    except OSError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def version_from_tags(tags: list[str]) -> str | None:
    """Return "X.Y.Z" of the highest vX.Y.Z tag in tags, or None when there is none."""
    versions = [tuple(int(n) for n in m.groups()) for tag in tags if (m := _VERSION_TAG_RE.match(tag))]
    if not versions:
        return None
    return ".".join(str(n) for n in max(versions))


def wendy_version(repo: str) -> str:
    """Return the version of the source in repo (see the module docstring).

    Print a warning and return "" when git cannot give the commit.
    """
    tags = _git(repo, "tag", "--points-at", "HEAD")
    version = version_from_tags(tags.splitlines()) if tags else None
    if version is None:
        version = _git(repo, "rev-parse", "--short", "HEAD")
    if not version:
        print(f"warning: no git commit in {repo}, {WENDY_VERSION} is empty", file=sys.stderr)
        return ""
    if _git(repo, "status", "--porcelain", "--untracked-files=no"):
        version += "-dirty"
    return version


def version_line(version: str) -> str:
    """Return the sdkconfig line that gives version to CONFIG_WENDY_VERSION."""
    return kconfig_string_line(WENDY_VERSION, version)
