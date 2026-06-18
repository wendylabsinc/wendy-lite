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

/* WasmKit-backend public API */
int wendy_storage_guest_get(const char *key, int key_len, char *val, int32_t val_len);
int wendy_storage_guest_set(const char *key, int key_len, const char *val, int32_t val_len);
int wendy_storage_guest_delete(const char *key, int key_len);
int wendy_storage_guest_exists(const char *key, int key_len);

#ifdef __cplusplus
}
#endif
