#pragma once

#include <stddef.h>
#include <stdarg.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the configured USB Serial/JTAG or UART bridge channel.
 */
esp_err_t wendy_usj_init(void);

/**
 * Write raw bytes to the configured wired port.
 * Only active in console mode; calls in other modes are no-ops.
 */
void wendy_usj_write(const void *data, size_t len);

void wendy_usj_printf(const char *fmt, ...);

void wendy_usj_vprintf(const char *fmt, va_list args);

#ifdef __cplusplus
}
#endif
