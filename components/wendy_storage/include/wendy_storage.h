#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the NVS storage subsystem.
 */
esp_err_t wendy_storage_init(void);

/**
 * Register storage host functions with the WASM runtime.
 */
int wendy_storage_export_init(void);

#ifdef __cplusplus
}
#endif
