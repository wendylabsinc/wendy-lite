#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register OpenTelemetry host functions with the WASM runtime.
 */
int wendy_otel_export_init(void);

/* WasmKit-backend public API */
int wendy_otel_guest_log(int32_t level, const char *msg, int32_t len);
int wendy_otel_guest_counter_add(const char *name, int32_t name_len, double delta);
int wendy_otel_guest_span_start(const char *name, int32_t name_len);
int wendy_otel_guest_span_set_status(int32_t span_id, int32_t status);
int wendy_otel_guest_span_end(int32_t span_id);

#ifdef __cplusplus
}
#endif
