#ifndef WENDY_COM_STDIO_H
#define WENDY_COM_STDIO_H

#include <stdbool.h>
#include <stddef.h>
#include "esp_log.h"

// types

typedef void (*wcom_stdio_data_handler_t)(void *ctx);

// functions

/**
 * Capture all stdout/stderr data into an internal ring buffer by registering
 * a handler via wendy_stdio_set_out_data_handler(). Any previously registered
 * handler is chained. Starts in non-blocking mode.
 */
void wcom_stdio_init(void);

/**
 * Select the behavior of writers when the buffer is full: in blocking mode
 * they block until the com thread frees space by reading; in non-blocking
 * mode the oldest buffered data is overwritten and the loss is reported by
 * wcom_stdio_read(). Writers currently blocked are woken and complete in
 * the new mode. This function is thread-safe.
 */
void wcom_stdio_set_blocking(bool blocking);

/**
 * Register the handler invoked on the com thread when the buffer holds
 * unread data. Pass NULL to unregister. The handler should call
 * wcom_stdio_read() until it returns 0; it is invoked again once new data
 * arrives after such an empty read. Must be called from the com thread (or
 * before any data flows).
 */
void wcom_stdio_set_data_handler(wcom_stdio_data_handler_t handler, void *ctx);

/**
 * Extract up to size bytes of buffered data, without ever blocking. Returns
 * the number of bytes copied into buf (0 if the buffer is empty). If gap is
 * not NULL, *gap is set to true when data was lost (overwritten) between the
 * previously read data and the data returned by this call. Must be called
 * from the com thread.
 */
size_t wcom_stdio_read(void *buf, size_t size, bool *gap);

/**
 * Install the handler that receives log output produced on the com thread.
 * In fact, this log output cannot go through the normal stdio path, because
 * it must never block. 
 * Pass NULL to restore the default handler.
 * Returns the previous handler.
 */
vprintf_like_t wcom_set_com_thread_log_vprintf(vprintf_like_t func);

#endif
