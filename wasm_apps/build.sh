#!/bin/bash
# Build Swift WASM app, convert to C header, and rebuild firmware.
#
# Usage: ./build.sh [app_dir]
#
# Example:
#   ./build.sh swift_blink

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APP_DIR="${1:-swift_blink}"
APP_PATH="$SCRIPT_DIR/$APP_DIR"
SWIFT_VERSION="${SWIFT_VERSION:-6.3}"
SWIFT_SDK="${SWIFT_SDK:-swift-6.3-RELEASE_wasm-embedded}"
SWIFT_TRIPLE="${SWIFT_TRIPLE:-wasm32-unknown-wasip1}"

if [ ! -f "$APP_PATH/Package.swift" ]; then
    echo "Error: $APP_PATH/Package.swift not found" >&2
    exit 1
fi

# Derive the product name from Package.swift
PRODUCT=$(grep -m1 'name:' "$APP_PATH/Package.swift" | sed 's/.*name: *"\([^"]*\)".*/\1/')
echo "Building $PRODUCT from $APP_DIR..."

# 1. Build Swift WASM
(cd "$APP_PATH" && swiftly run +"$SWIFT_VERSION" swift build --swift-sdk "$SWIFT_SDK" --triple "$SWIFT_TRIPLE" -c release)

BIN_DIR=$(cd "$APP_PATH" && swiftly run +"$SWIFT_VERSION" swift build --swift-sdk "$SWIFT_SDK" --triple "$SWIFT_TRIPLE" -c release --show-bin-path)

WASM_FILE="$BIN_DIR/$PRODUCT.wasm"
if [ ! -f "$WASM_FILE" ]; then
    echo "Error: $WASM_FILE not found" >&2
    exit 1
fi

# 2. Convert to C header
"$SCRIPT_DIR/wasm2header.sh" "$WASM_FILE" "$PROJECT_DIR/main/demo_wasm.h"

# 3. Rebuild firmware
echo "Rebuilding firmware..."
(cd "$PROJECT_DIR" && idf.py build)

echo "Done. Flash with: cd $PROJECT_DIR && idf.py flash"
