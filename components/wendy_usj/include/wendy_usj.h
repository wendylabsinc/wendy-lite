#pragma once

#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the USB Serial/JTAG channel.
 */
esp_err_t wendy_usj_init(void);

/**
 * Write raw bytes to the USB Serial/JTAG port.
 * Only active in console mode; calls in other modes are no-ops.
 */
void wendy_usj_write(const void *data, size_t len);

#ifdef __cplusplus
}
#endif
