#pragma once

#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*wendy_stdio_out_data_handler_t)(const void *data, size_t size);

/**
 * Redirect the system streams through /dev/wstdio, which forwards to
 * the real console device and additionally passes all stdout/stderr data to
 * the handler registered with wendy_stdio_set_out_data_handler(). When Wendy
 * owns the UART transport, only that handler writes and stdin uses injected
 * data, keeping direct console I/O from interfering with management traffic.
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

/**
 * Inject data into stdin. The data becomes readable from stdin, possibly
 * interleaved with input from the real console device unless Wendy owns the
 * UART transport. The internal buffer
 * holds 128 bytes; bytes that don't fit are dropped. Returns the number of
 * bytes accepted. Lock-free and safe to call from multiple tasks (or ISRs)
 * concurrently.
 */
size_t wendy_stdio_put_stdin_data(const void *data, size_t size);

#ifdef __cplusplus
}
#endif
