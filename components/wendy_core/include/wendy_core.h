#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initializes and runs the Wendy MCU firmware: NVS, WASM runtime, HAL,
 * USB/BLE/cloud provisioning, WiFi transport, and the wcom control channel.
 * Called once from app_main(). */
esp_err_t wendy_core_init(void);

#ifdef __cplusplus
}
#endif
