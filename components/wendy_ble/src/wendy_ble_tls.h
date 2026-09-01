#ifndef WENDY_BLE_TLS_H
#define WENDY_BLE_TLS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "esp_err.h"

/// One TLS server session over the open L2CAP channel, set up and torn down
/// per connection. Nothing is retained while idle: mbedTLS is configured with
/// dynamic buffers and frees config data after the handshake, so the contexts
/// could not be reused anyway, and keeping nothing resident is what leaves
/// room for the other transports' sessions.

/// Run the handshake to completion on the calling task. Returns ESP_OK only
/// once the encrypted stream is usable.
esp_err_t wble_tls_session_start(void);

/// Release everything. Safe whether or not the handshake succeeded.
void wble_tls_session_end(void);

/// Same contract as the L2CAP layer: byte count, 0 at end of stream, or
/// WBLE_ERR_WANT_READ / WBLE_ERR_WANT_WRITE / WBLE_ERR_UNKNOWN.
ssize_t wble_tls_read(void *buf, size_t len);
ssize_t wble_tls_write(const void *buf, size_t len);

/// True when mbedTLS holds already-decrypted bytes that no transport event
/// will announce. Without this a reader can park on a quiet wakeup fd while a
/// whole record sits decrypted in the TLS buffer.
bool wble_tls_pending(void);

#endif
