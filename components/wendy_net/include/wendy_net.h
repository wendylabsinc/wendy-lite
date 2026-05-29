#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register networking host functions with the WASM runtime.
 */
int wendy_net_export_init(void);

/**
 * Close all guest-owned async networking resources and clear pending events.
 * Called when a WASM guest stops or is replaced.
 */
void wendy_net_guest_reset(void);

#ifdef __cplusplus
}
#endif
