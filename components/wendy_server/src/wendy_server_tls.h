#pragma once

#include "wendy_com_link.h"

/* The context is an esp_tls_t owned by the server. Enrollment or reset revokes
 * anonymous access on the next read or write, including buffered TLS records. */
extern const struct wcom_stream_ops wendy_server_anonymous_tls_ops;

/* Makes the socket nonblocking before WendyCom can run any link callbacks.
 * Returns -1 on failure; the caller retains ownership of the TLS session. */
int wendy_server_add_anonymous_tls_link(esp_tls_t *tls,
                                      wcom_interruption_handler_t handler);
