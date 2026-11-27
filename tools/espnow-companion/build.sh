#!/usr/bin/env bash
# Build an ESP-Hosted 2.x C6 application image with the Wendy radio bridge.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
hosted_version=2.13.1
idf_version=6.0.3

# Hash the radio sources and build recipe so host-only releases can reuse it.
build_id="$(python3 - "$here" <<'PY'
from hashlib import sha256
from pathlib import Path
import sys

here = Path(sys.argv[1])
include = here.parent.parent / "components" / "wendy_net_peer" / "include"
inputs = [here / name for name in ("build.sh", "bridge.c", "esp-hosted-sdio.patch")]
inputs += [include / f"wendy_net_espnow_{name}.h" for name in ("hosted", "peers", "sdio")]
digest = sha256(b"".join(sha256(path.read_bytes()).digest() for path in inputs))
print(f"wendy-{digest.hexdigest()[:24]}")
PY
)"
if [[ "${1:-}" == --build-id && $# == 1 ]]; then
    echo "$build_id"
    exit 0
fi
if [[ $# != 2 ]]; then
    echo "Usage: $0 <esp-hosted-component-directory> <staging-directory> | --build-id" >&2
    exit 2
fi
if [[ "$(idf.py --version)" != "ESP-IDF v$idf_version" ]]; then
    echo "Activate ESP-IDF v$idf_version to build the companion." >&2
    exit 1
fi
mkdir -p "$2"
staging="$(cd "$2" && pwd)"
python3 - "$1" "$staging" "$here" "$hosted_version" "$build_id" <<'PY'
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import yaml

source, staging, here = (Path(arg).resolve(strict=True) for arg in sys.argv[1:4])
hosted_version, build_id = sys.argv[4:]
manifest = (source / "idf_component.yml").read_text()
if not re.search(rf"^version:\s*{re.escape(hosted_version)}\s*$", manifest, re.M):
    raise SystemExit(f"Expected resolved ESP-Hosted component version {hosted_version}")
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
# These registry dependencies are ranged upstream. Pin the resolved versions
# so an upstream dependency release cannot change the image under one build ID.
component_manifest = main / "idf_component.yml"
component_data = yaml.safe_load(component_manifest.read_text())
for name, version in {
    "esp-qa/ping-cmd": "1.0.0",
    "esp-qa/wifi-cmd": "0.2.12",
    "espressif/iperf": "0.1.4",
    "espressif/iperf-cmd": "0.1.4",
    "espressif/mqtt": "1.1.0",
}.items():
    component_data["dependencies"][name] = {"version": f"={version}"}
component_manifest.write_text(yaml.safe_dump(component_data, sort_keys=False))

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
for name, value in {
    "CONFIG_ESP_HOSTED_ENABLE_PEER_DATA_TRANSFER": "y",
    "CONFIG_ESP_SDIO_HOST_INTERFACE": "y",
    "CONFIG_APP_PROJECT_VER_FROM_CONFIG": "y",
    "CONFIG_APP_PROJECT_VER": f'"{build_id}"',
}.items():
    defaults = re.sub(rf"^(?:{name}=.*|# {name} is not set)\n?", "", defaults, flags=re.M)
    defaults = f"{defaults.rstrip()}\n{name}={value}\n"
config.write_text(defaults)
PY
cd "$staging/slave"
idf.py set-target esp32c6
idf.py build
# Factory FireBeetle radios have 0x180000-byte OTA slots.
if (( $(wc -c < build/network_adapter.bin) > 0x180000 )); then
    echo "Companion image exceeds the factory FireBeetle OTA slot." >&2
    exit 1
fi
