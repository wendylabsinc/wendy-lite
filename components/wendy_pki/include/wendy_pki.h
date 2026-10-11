#pragma once
#include "esp_err.h"
#include "wendy_conf.pb.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
typedef struct wendy_pki_connection wendy_pki_connection;
void wendy_pki_builtin_trust(bool *ready, bool *tsa_ready);
/* A challenge discloses no key material. Only the USB command calls this. */
esp_err_t wendy_pki_challenge(bool status_only, char nonce_hex[65], bool *enrolled);
/* Legacy wire API: this mbedTLS profile returns ESP_ERR_NOT_SUPPORTED. */
esp_err_t wendy_pki_sync_time(const char *server, const uint8_t *reply, size_t size,
                            bool *synchronized, int64_t *seconds);
/* Called by the cloud task after Wi-Fi is up; all network operations are bounded. */
esp_err_t wendy_pki_connect(wendy_pki_connection **connection);
void wendy_pki_close(wendy_pki_connection *connection);
/* Waits up to 10 seconds for peer close_notify and replies before detaching.
 * Success frees connection and transfers the open fd to the caller.
 * Failure returns -1; the caller still owns connection and must close it. */
int wendy_pki_detach(wendy_pki_connection *connection);
int wendy_pki_fd(void *connection);
ssize_t wendy_pki_read(void *connection, void *data, size_t size);
ssize_t wendy_pki_write(void *connection, const void *data, size_t size);

/* Takes ownership of fd on every outcome. No issuance or network time fetch. */
esp_err_t wendy_pki_accept(int fd, wendy_pki_connection **connection);

#include "wendy_lite_grant.h"
/* Installs keys exclusively from authenticated outer TLS, then detaches TCP. */
int wendy_pki_relay_upgrade(wendy_pki_connection *, struct wendy_lite_trust *);
esp_err_t wendy_pki_accept_relay(int fd, const struct wendy_lite_trust *, wendy_pki_connection **);
