// WasmKitBridge.c — minimal C bridge between the Swift WasmKit runtime and ESP-IDF.
//
// This file only provides the output callback glue.  All other entry points
// (wendy_wasm_*) are exported directly from WendyRuntime.swift via @_cdecl.

#include <stdint.h>
#include <stdio.h>
#include "wendy_wasm.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

// Format version string "%d.%d.%d" into buf[0..len-1].
// Returns snprintf-style byte count (excluding NUL), or negative on error.
int wendy_format_version(char *buf, int len) {
    return snprintf(buf, (size_t)len, "%d.%d.%d",
        CONFIG_WENDY_FIRMWARE_VERSION_MAJOR,
        CONFIG_WENDY_FIRMWARE_VERSION_MINOR,
        CONFIG_WENDY_FIRMWARE_VERSION_PATCH);
}

// Format 6-byte MAC address as lowercase hex (12 chars + NUL) into buf[0..len-1].
int wendy_format_mac(char *buf, int len, const uint8_t *mac) {
    return snprintf(buf, (size_t)len, "%02x%02x%02x%02x%02x%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void wendy_log_heap(void) {
    ESP_LOGE("wasmkit", "heap: free=%lu largest=%lu",
        (unsigned long)heap_caps_get_free_size(MALLOC_CAP_8BIT),
        (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}

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
