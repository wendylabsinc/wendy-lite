#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register BLE host functions with the WASM runtime.
 *
 * The NimBLE stack itself is brought up by the wendy_ble component; the
 * ble_init() guest import routes there.
 */
int wendy_ble_export_init(void);

#ifdef __cplusplus
}
#endif
