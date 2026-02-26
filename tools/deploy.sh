#!/bin/bash
# Build a WASM app and deploy it to a Wendy device over WiFi.
#
# Usage:
#   ./deploy.sh blink                   # build C app + serve + wait
#   ./deploy.sh swift_blink             # build Swift app + serve + wait
#   ./deploy.sh rust_blink              # build Rust app + serve + wait
#   ./deploy.sh wat_blink               # build WAT app + serve + wait
#   ./deploy.sh path/to/app.wasm        # serve prebuilt binary
#   ./deploy.sh --reload                # just trigger re-download
#
# Options:
#   --port PORT       HTTP server port (default: auto)
#   --udp-port PORT   UDP reload port  (default: 4210)
#   --reload          send reload broadcast (to running server) and exit
#   --no-build        skip the build step, serve existing .wasm

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
WASM_APPS_DIR="$PROJECT_DIR/wasm_apps"

PORT=0
UDP_PORT=4210
DO_BUILD=true
RELOAD_ONLY=false
TARGET=""
DEVICE_ARGS=""

# ── Parse arguments ──────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)      PORT="$2"; shift 2 ;;
        --udp-port)  UDP_PORT="$2"; shift 2 ;;
        --device)    DEVICE_ARGS="$DEVICE_ARGS --device $2"; shift 2 ;;
        --reload)    RELOAD_ONLY=true; shift ;;
        --no-build)  DO_BUILD=false; shift ;;
        -h|--help)
            echo "Usage: deploy.sh [OPTIONS] <app-name | path/to/app.wasm>"
            echo ""
            echo "  app-name    C, Swift, Rust, Zig, or WAT app name"
            echo "  .wasm path  serve a prebuilt WASM binary directly"
            echo ""
            echo "Options:"
            echo "  --port PORT       HTTP server port (default: 8080)"
            echo "  --udp-port PORT   UDP reload broadcast port (default: 4210)"
            echo "  --device IP       device IP address (repeatable, skips mDNS)"
            echo "  --reload          send WENDY_RELOAD and exit"
            echo "  --no-build        skip build, serve existing .wasm"
            exit 0
            ;;
        *)           TARGET="$1"; shift ;;
    esac
done

# ── Reload-only mode ─────────────────────────────────────────────────

if $RELOAD_ONLY; then
    echo "Sending WENDY_RELOAD broadcast on UDP port $UDP_PORT..."
    python3 "$SCRIPT_DIR/wendy_serve.py" --reload --udp-port "$UDP_PORT" $DEVICE_ARGS
    exit 0
fi

if [ -z "$TARGET" ]; then
    echo "Error: specify an app name or .wasm path (use --help for usage)" >&2
    exit 1
fi

# ── Resolve the .wasm file ───────────────────────────────────────────

WASM_FILE=""

if [[ "$TARGET" == *.wasm ]]; then
    # Direct path to a .wasm file
    WASM_FILE="$TARGET"
    DO_BUILD=false

elif [ -d "$WASM_APPS_DIR/$TARGET" ] && [ -f "$WASM_APPS_DIR/$TARGET/Package.swift" ]; then
    # Swift app
    PRODUCT=$(grep -m1 'name:' "$WASM_APPS_DIR/$TARGET/Package.swift" \
        | sed 's/.*name: *"\([^"]*\)".*/\1/')
    if $DO_BUILD; then
        echo "Building Swift app '$PRODUCT' from $TARGET..."
        (cd "$WASM_APPS_DIR/$TARGET" && swiftly run +6.2.3 swift build --triple wasm32-unknown-none-wasm -c release)
    fi
    WASM_FILE="$WASM_APPS_DIR/$TARGET/.build/release/$PRODUCT.wasm"

elif [ -d "$WASM_APPS_DIR/$TARGET" ] && [ -f "$WASM_APPS_DIR/$TARGET/Cargo.toml" ]; then
    # Rust app
    if $DO_BUILD; then
        echo "Building Rust app '$TARGET'..."
        make -C "$WASM_APPS_DIR" "$TARGET"
    fi
    WASM_FILE="$WASM_APPS_DIR/$TARGET.wasm"

elif [ -d "$WASM_APPS_DIR/$TARGET" ] && [ -f "$WASM_APPS_DIR/$TARGET/build.zig" ]; then
    # Zig app
    if $DO_BUILD; then
        echo "Building Zig app '$TARGET'..."
        make -C "$WASM_APPS_DIR" "$TARGET"
    fi
    WASM_FILE="$WASM_APPS_DIR/$TARGET.wasm"

elif [ -d "$WASM_APPS_DIR/$TARGET" ] && ls "$WASM_APPS_DIR/$TARGET"/*.wat >/dev/null 2>&1; then
    # WAT app
    if $DO_BUILD; then
        echo "Building WAT app '$TARGET'..."
        make -C "$WASM_APPS_DIR" "$TARGET"
    fi
    WASM_FILE="$WASM_APPS_DIR/$TARGET.wasm"

elif [ -f "$WASM_APPS_DIR/$TARGET/$TARGET.c" ]; then
    # C app
    if $DO_BUILD; then
        echo "Building C app '$TARGET'..."
        make -C "$WASM_APPS_DIR" "$TARGET"
    fi
    WASM_FILE="$WASM_APPS_DIR/$TARGET.wasm"

else
    echo "Error: unknown app '$TARGET'" >&2
    echo "Available apps:"
    for d in "$WASM_APPS_DIR"/*/; do
        name=$(basename "$d")
        if [ -f "$d/Package.swift" ]; then
            echo "  $name (Swift)"
        elif [ -f "$d/Cargo.toml" ]; then
            echo "  $name (Rust)"
        elif [ -f "$d/build.zig" ]; then
            echo "  $name (Zig)"
        elif ls "$d"/*.wat >/dev/null 2>&1; then
            echo "  $name (WAT)"
        elif [ -f "$d/$name.c" ]; then
            echo "  $name (C)"
        fi
    done
    exit 1
fi

if [ ! -f "$WASM_FILE" ]; then
    echo "Error: $WASM_FILE not found" >&2
    exit 1
fi

SIZE=$(wc -c < "$WASM_FILE" | tr -d ' ')
echo "Deploying $WASM_FILE ($SIZE bytes)"

# ── Serve and advertise ──────────────────────────────────────────────

python3 "$SCRIPT_DIR/wendy_serve.py" "$WASM_FILE" --port "$PORT" --udp-port "$UDP_PORT" --reload $DEVICE_ARGS
