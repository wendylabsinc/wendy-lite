// WasmKitBridge.c — thin C shim between ESP-IDF (C) and the Swift WasmKit runtime.
//
// The real implementation lives in Runtime.swift / WendyImports.swift, compiled
// with -enable-experimental-feature Embedded.  The @_cdecl-attributed Swift
// functions land in the .o with C linkage, so this file just needs to forward
// the output callback and provide a home for the C-visible state the rest of
// the firmware calls through the wendy_wasm.h API.
//
// All the wendy_wasm_* entry points are emitted as @_cdecl symbols from Swift.
// This file only provides:
//   - wendy_wasmkit_handle_print() — called from Swift when WASM writes output
//   - Weak-linkage stubs so the linker is happy if Swift symbols are not yet
//     present during incremental builds.

#include "WendyCBridge.h"
#include "esp_log.h"

static const char *TAG = "wendy_wasmkit";

// ── Output callback forwarding ────────────────────────────────────────────────

static wendy_wasm_output_cb_t s_output_cb;
static void *s_output_ctx;

// Called from Swift (Runtime.swift) when the WASM guest calls wendy_print.
void wendy_wasmkit_handle_print(const char *buf, int len)
{
    if (!buf || len <= 0) return;
    if (s_output_cb) {
        s_output_cb(buf, (uint32_t)len, s_output_ctx);
    } else {
        fwrite(buf, 1, len, stdout);
        fflush(stdout);
    }
}

// ── Output callback registration (called from wendy_wasm_init on C side) ─────

// Defined in Runtime.swift with C linkage via @_cdecl.
// Declared here for -Wmissing-prototypes.
extern void wendy_wasmkit_set_output_cb(wendy_wasm_output_cb_t cb, void *ctx);

void wendy_wasmkit_set_output_cb(wendy_wasm_output_cb_t cb, void *ctx)
{
    s_output_cb = cb;
    s_output_ctx = ctx;
}
