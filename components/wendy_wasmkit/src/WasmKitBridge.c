// WasmKitBridge.c — minimal C bridge between the Swift WasmKit runtime and ESP-IDF.
//
// This file only provides the output callback glue.  All other entry points
// (wendy_wasm_*) are exported directly from WendyRuntime.swift via @_cdecl.

#include <stdint.h>
#include <stdio.h>
#include "wendy_wasm.h"

static wendy_wasm_output_cb_t s_output_cb;
static void *s_output_ctx;

// Called from Swift (WendyRuntime.swift) when the WASM guest calls wendy_print.
void wendy_wasmkit_handle_print(const char *buf, int len)
{
    if (!buf || len <= 0) return;
    if (s_output_cb) {
        s_output_cb(buf, (uint32_t)len, s_output_ctx);
    } else {
        fwrite(buf, 1, (size_t)len, stdout);
        fflush(stdout);
    }
}

// Stores the output callback; called by WendyRuntime.swift during init.
void wendy_wasmkit_set_output_cb(wendy_wasm_output_cb_t cb, void *ctx)
{
    s_output_cb = cb;
    s_output_ctx = ctx;
}
