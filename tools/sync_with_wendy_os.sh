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
    "go/proto/wendy_com_tunnel_msg.proto:Proto/wendy/lite/wendy_com_tunnel_msg.proto"
    "go/proto/wendy_com_tunnel_service.proto:Proto/wendy/lite/wendy_com_tunnel_service.proto"
    "go/console/liteclient/client.go:go/internal/cli/liteclient/client.go"
    "go/console/liteclient/link.go:go/internal/cli/liteclient/link.go"
    "go/console/liteclient/link_direct.go:go/internal/cli/liteclient/link_direct.go"
    "go/console/liteclient/link_tunnel.go:go/internal/cli/liteclient/link_tunnel.go"
    "go/internal/shared/seriallock/seriallock.go:go/internal/shared/seriallock/seriallock.go"
    "go/internal/shared/seriallock/lock_unix.go:go/internal/shared/seriallock/lock_unix.go"
    "go/internal/shared/seriallock/lock_windows.go:go/internal/shared/seriallock/lock_windows.go"
    "go/internal/shared/seriallock/lock_unix_test.go:go/internal/shared/seriallock/lock_unix_test.go"
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

echo "=== catalog.json -> wlite_variants.go"
catalog_src="$WENDY_LITE/catalog.json"
catalog_dst="$WENDY_OS/go/internal/cli/commands/wlite_variants.go"
echo "    wendy-lite : $catalog_src"
echo "    WendyOS    : $catalog_dst"

if [[ ! -f "$catalog_src" ]]; then
    echo "    ERROR: file not found in wendy-lite"
    any_diff=1
elif [[ ! -f "$catalog_dst" ]]; then
    echo "    ERROR: file not found in WendyOS"
    any_diff=1
else
    embedded=$(awk '
        /^const wendyLiteCatalogJSON = `$/ { capture=1; next }
        capture && /^`$/ { capture=0; next }
        capture { print }
    ' "$catalog_dst")

    if [[ "$embedded" == "$(cat "$catalog_src")" ]]; then
        echo "    -> identical"
    else
        tmp=$(mktemp)
        awk -v jsonfile="$catalog_src" '
            BEGIN {
                while ((getline line < jsonfile) > 0) json = json line "\n"
            }
            /^const wendyLiteCatalogJSON = `$/ {
                print
                printf "%s", json
                skip=1
                next
            }
            skip && /^`$/ {
                print
                skip=0
                next
            }
            skip { next }
            { print }
        ' "$catalog_dst" > "$tmp" && mv "$tmp" "$catalog_dst"
        echo "    -> updated wlite_variants.go from catalog.json"
    fi
fi
echo

exit $any_diff
