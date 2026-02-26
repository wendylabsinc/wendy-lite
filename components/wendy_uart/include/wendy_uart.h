#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register UART host functions with the WASM runtime.
 */
int wendy_uart_export_init(void);

#ifdef __cplusplus
}
#endif
