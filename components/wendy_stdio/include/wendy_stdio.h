#pragma once

#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*wendy_stdio_out_data_handler_t)(const void *data, size_t size);

/**
 * Replace the system console VFS at /dev/console with one that forwards to
 * the real console device and additionally passes all stdout/stderr data to
 * the handler registered with wendy_stdio_set_out_data_handler().
 */
esp_err_t wendy_stdio_init(void);

/**
 * Register a handler invoked with every chunk of data written to stdout or
 * stderr. Pass NULL to unregister. May be called before wendy_stdio_init().
 * Returns the previously registered handler (NULL if none), allowing the new
 * handler to chain to it.
 */
wendy_stdio_out_data_handler_t
wendy_stdio_set_out_data_handler(wendy_stdio_out_data_handler_t handler);

#ifdef __cplusplus
}
#endif
