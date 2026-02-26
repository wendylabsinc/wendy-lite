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

#ifdef __cplusplus
}
#endif
