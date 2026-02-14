#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register all HAL native functions with the WASM runtime.
 * Calls each module's export function based on Kconfig.
 */
esp_err_t wendy_hal_export_init(void);

#ifdef __cplusplus
}
#endif
