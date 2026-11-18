#!/usr/bin/env bash
# Build an ESP-Hosted 2.x C6 application image with the Wendy radio bridge.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if [[ $# != 2 || ! -f "$1/slave/main/esp_hosted_coprocessor.c" ]]; then
    echo "Usage: $0 <esp-hosted-component-directory> <staging-directory>" >&2
    exit 2
fi
mkdir -p "$2"
staging="$(cd "$2" && pwd)"
if [[ -e "$staging/slave" ]]; then
    echo "Choose a fresh staging directory" >&2
    exit 2
fi
cp -R "$1/slave" "$1/common" "$staging/"
cp "$here/bridge.c" "$here/../../components/wendy_net_peer/include/wendy_net_espnow_hosted.h" "$staging/slave/main/"
python3 - "$staging/slave/main" <<'PY'
from pathlib import Path
import sys

main = Path(sys.argv[1])
cmake = main / "CMakeLists.txt"
source = cmake.read_text()
assert source.count('"esp_hosted_coprocessor.c"') == 1
cmake.write_text(source.replace('"esp_hosted_coprocessor.c"', '"esp_hosted_coprocessor.c"\n    "bridge.c"'))
app = main / "esp_hosted_coprocessor.c"
source = app.read_text()
entry = "\tesp_hosted_coprocessor_init();"
assert source.count(entry) == 1
app.write_text(source.replace(entry, entry + "\n\textern void wendy_espnow_bridge_init(void);\n\twendy_espnow_bridge_init();"))
PY
printf '\nCONFIG_ESP_HOSTED_ENABLE_PEER_DATA_TRANSFER=y\nCONFIG_ESP_SDIO_HOST_INTERFACE=y\n' >> "$staging/slave/sdkconfig.defaults.esp32c6"
cd "$staging/slave"
idf.py set-target esp32c6
idf.py build
