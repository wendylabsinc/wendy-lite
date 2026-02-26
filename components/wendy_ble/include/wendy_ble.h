#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the BLE subsystem (NimBLE stack).
 */
esp_err_t wendy_ble_init(void);

/**
 * Register BLE host functions with the WASM runtime.
 */
int wendy_ble_export_init(void);

#ifdef __cplusplus
}
#endif
