#!/usr/bin/env bash
# Build an ESP-Hosted 2.x C6 application image with the Wendy radio bridge.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if [[ $# != 2 ]]; then
    echo "Usage: $0 <esp-hosted-component-directory> <staging-directory>" >&2
    exit 2
fi
mkdir -p "$2"
staging="$(cd "$2" && pwd)"
python3 - "$1" "$staging" "$here" <<'PY'
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys

source, staging, here = (Path(arg).resolve(strict=True) for arg in sys.argv[1:])
if staging.is_relative_to(source):
    raise SystemExit("Choose a staging directory outside the ESP-Hosted source tree")
for name in ("slave", "common"):
    tree = source / name
    target = staging / name
    if not tree.is_dir() or tree.is_symlink():
        raise SystemExit(f"Expected a source directory at {tree}")
    if target.exists() or target.is_symlink():
        raise SystemExit(f"Choose a fresh staging directory. {target} already exists")
    # Preserve links during the copy so reading an input link cannot copy its
    # target. Refuse them before editing or building any staged file.
    shutil.copytree(tree, target, symlinks=True)
    if any(path.is_symlink() for path in target.rglob("*")):
        raise SystemExit(f"Symlinks are unsupported in the staged {name} tree")

subprocess.run(["git", "apply", "--no-index", str(here / "esp-hosted-sdio.patch")],
               cwd=staging, check=True,
               env={**os.environ, "GIT_CEILING_DIRECTORIES": str(staging.parent)})

main = staging / "slave" / "main"
cmake = main / "CMakeLists.txt"
app = main / "esp_hosted_coprocessor.c"
cmake_source, app_source = cmake.read_text(), app.read_text()
component = '"esp_hosted_coprocessor.c"'
entry = "\tesp_hosted_coprocessor_init();"
if cmake_source.count(component) != 1 or app_source.count(entry) != 1:
    raise SystemExit("Could not locate the ESP-Hosted build and initialization hooks")
cmake.write_text(cmake_source.replace(component, f'{component}\n    "bridge.c"'))
app.write_text(app_source.replace(entry, entry + "\n\textern void wendy_espnow_bridge_init(void);\n\twendy_espnow_bridge_init();"))
shutil.copyfile(here / "bridge.c", main / "bridge.c")
include = here.parent.parent / "components" / "wendy_net_peer" / "include"
for name in ("wendy_net_espnow_hosted.h", "wendy_net_espnow_peers.h", "wendy_net_espnow_sdio.h"):
    shutil.copyfile(include / name, main / name)

config = staging / "slave" / "sdkconfig.defaults.esp32c6"
defaults = config.read_text()
for name in ("CONFIG_ESP_HOSTED_ENABLE_PEER_DATA_TRANSFER", "CONFIG_ESP_SDIO_HOST_INTERFACE"):
    defaults = re.sub(rf"^(?:{name}=.*|# {name} is not set)\n?", "", defaults, flags=re.M)
    defaults = f"{defaults.rstrip()}\n{name}=y\n"
config.write_text(defaults)
PY
cd "$staging/slave"
idf.py set-target esp32c6
idf.py build
