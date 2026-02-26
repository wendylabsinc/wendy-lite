#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register app-facing USB host functions with the WASM runtime.
 * Only available on ESP32-S2/S3 with USB OTG.
 */
int wendy_app_usb_export_init(void);

#ifdef __cplusplus
}
#endif
