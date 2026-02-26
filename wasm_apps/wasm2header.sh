#!/bin/bash
# Convert a .wasm binary to a C header with an embedded byte array.
#
# Usage: ./wasm2header.sh input.wasm [output.h] [array_name]
#
# Example:
#   ./wasm2header.sh swift_blink/.build/release/SwiftBlink.wasm ../main/demo_wasm.h

set -euo pipefail

WASM_FILE="${1:?Usage: $0 input.wasm [output.h] [array_name]}"
OUTPUT="${2:-demo_wasm.h}"
ARRAY_NAME="${3:-demo_wasm_binary}"

if [ ! -f "$WASM_FILE" ]; then
    echo "Error: $WASM_FILE not found" >&2
    exit 1
fi

SIZE=$(wc -c < "$WASM_FILE" | tr -d ' ')

cat > "$OUTPUT" << HEADER
/**
 * Auto-generated from: $(basename "$WASM_FILE")
 * Size: $SIZE bytes
 * Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
 */

#pragma once

#include <stdint.h>

static const uint8_t ${ARRAY_NAME}[] = {
HEADER

# Convert binary to hex bytes, 16 per line
xxd -i < "$WASM_FILE" | sed 's/^/    /' >> "$OUTPUT"

cat >> "$OUTPUT" << FOOTER
};

static const uint32_t ${ARRAY_NAME}_len = sizeof(${ARRAY_NAME});
FOOTER

echo "Generated $OUTPUT ($SIZE bytes from $(basename "$WASM_FILE"))"
