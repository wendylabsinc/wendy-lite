#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register SPI host functions with the WASM runtime.
 */
int wendy_spi_export_init(void);

/* WasmKit-backend public API */
int wendy_spi_guest_open(int host, int mosi, int miso, int sclk, int cs, int clock_hz);
int wendy_spi_guest_close(int dev_id);
int wendy_spi_guest_transfer(int dev_id, int32_t len,
                              const uint8_t *tx_buf, uint8_t *rx_buf);

#ifdef __cplusplus
}
#endif
