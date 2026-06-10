#!/usr/bin/env bash
# Compare proto files between wendy-lite and WendyOS projects.
# Files live in different directory hierarchies on each project.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WENDY_LITE="$SCRIPT_DIR/.."
WENDY_OS="$SCRIPT_DIR/../../WendyOS"

if [[ ! -d "$WENDY_OS" ]]; then
    echo "ERROR: WendyOS project not found at $WENDY_OS"
    exit 1
fi

# Each entry is "local_path:remote_path"
PAIRS=(
    "components/wendy_com/proto/wendy_com_msg.proto:Proto/wendy/lite/wendy_com_msg.proto"
    "components/wendy_conf/proto/wendy_conf.proto:Proto/wendy/lite/wendy_conf.proto"
)

any_diff=0

for pair in "${PAIRS[@]}"; do
    local_path="${pair%%:*}"
    remote_path="${pair#*:}"
    src="$WENDY_LITE/$local_path"
    dst="$WENDY_OS/$remote_path"

    echo "=== $local_path"
    echo "    wendy-lite : $src"
    echo "    WendyOS    : $dst"

    if [[ ! -f "$src" ]]; then
        echo "    ERROR: file not found in wendy-lite"
        any_diff=1
        continue
    fi
    if [[ ! -f "$dst" ]]; then
        echo "    ERROR: file not found in WendyOS"
        any_diff=1
        continue
    fi

    if diff -q "$dst" "$src" > /dev/null 2>&1; then
        echo "    -> identical"
    else
        any_diff=1
        meld "$dst" "$src"
    fi
    echo
done

exit $any_diff
