#pragma once

#include "wendy_com_link.h"
#include <stdint.h>

/* The context is an esp_tls_t owned by the server. Enrollment or reset revokes
 * anonymous access on the next read or write, including buffered TLS records. */
extern const struct wcom_stream_ops wendy_server_anonymous_tls_ops;

/* Makes the socket nonblocking before WendyCom can run any link callbacks.
 * Returns -1 on failure; the caller retains ownership of the TLS session. */
int wendy_server_add_anonymous_tls_link(esp_tls_t *tls,
                                      wcom_interruption_handler_t handler);

/* Positive, so it never collides with 0 or a negative mbedTLS/esp-tls error. */
#define WENDY_SERVER_TLS_HANDSHAKE_TIMEOUT 1

/* Makes fd nonblocking and runs the server handshake of tls on it. Waits in
 * select() between steps, so a silent client cannot hold the caller for longer
 * than timeout_us. Returns 0, the esp-tls error, -1 on a socket failure, or
 * WENDY_SERVER_TLS_HANDSHAKE_TIMEOUT. The caller keeps ownership of both. */
int wendy_server_anonymous_handshake(esp_tls_t *tls, int fd, int64_t timeout_us);
