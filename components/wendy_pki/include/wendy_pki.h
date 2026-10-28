#pragma once
#include "esp_err.h"
#include "wendy_conf.pb.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "wendy_peer_role.h"
typedef struct wendy_pki_connection wendy_pki_connection;
void wendy_pki_builtin_trust(bool *ready, bool *tsa_ready);
/* A challenge discloses no key material. Only the USB command calls this. */
esp_err_t wendy_pki_challenge(bool status_only, char nonce_hex[65], bool *enrolled);
/* Physical setup only; caller must enforce the USB transport boundary.
 * Clears enrollment configuration before identity keys, preserving signed time.
 * The caller reboots after acknowledging success. */
esp_err_t wendy_pki_reset(const char *expected_device_id, const char *nonce_hex);
/* Revokes use of existing network sessions until reboot after recovery starts. */
bool wendy_pki_reset_in_progress(void);
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

/* Nonblocking encrypted-byte transport. read/write return a byte count, 0 for
 * EOF, -2 for WANT_READ, -3 for WANT_WRITE, or -1 for failure. wait returns 0
 * to retry or -1 on timeout/disconnect; deadline_us uses esp_timer_get_time().
 * Callbacks and context are copied, but the caller owns the transport and must
 * keep its context alive until wendy_pki_close(). */
struct wendy_pki_stream {
    void *context;
    ssize_t (*read)(void *context, void *data, size_t size);
    ssize_t (*write)(void *context, const void *data, size_t size);
    int (*wait)(void *context, bool writing, int64_t deadline_us);
};
/* Authenticates a same-tenant operator using the enrolled identity. No legacy
 * or anonymous fallback. Closing the connection never closes the transport. */
esp_err_t wendy_pki_accept_stream(const struct wendy_pki_stream *stream,
                                wendy_pki_connection **connection);
bool wendy_pki_pending(wendy_pki_connection *connection);

/* Takes ownership of fd on every outcome. No issuance or network time fetch. */
esp_err_t wendy_pki_accept(int fd, wendy_pki_connection **connection);
/* LAN additionally accepts same-tenant devices for SensorLink. The consumer
 * must restrict device peers using the role captured by the TLS handshake. */
esp_err_t wendy_pki_accept_lan(int fd, wendy_pki_connection **connection);
enum wendy_peer_role wendy_pki_get_peer_role(const wendy_pki_connection *connection);

#include "wendy_lite_grant.h"
enum wendy_pki_relay_result {
    WENDY_PKI_RELAY_FAILED = -1,
    WENDY_PKI_RELAY_RENEW = -2,
};
/* Installs keys exclusively from authenticated outer TLS, then detaches TCP.
 * Returns the handed-off fd, FAILED, or RENEW for normal planned refresh.
 * The caller must close connection on every outcome. A nonnegative return
 * transfers the detached fd to the caller independently of connection. */
int wendy_pki_relay_upgrade(wendy_pki_connection *, struct wendy_lite_trust *);
esp_err_t wendy_pki_accept_relay(int fd, const struct wendy_lite_trust *, wendy_pki_connection **);

/* Optional active-mesh TLS workspace experiment; false releases cached RAM. */
void wendy_pki_input_workspace_active(bool active);
size_t wendy_pki_input_workspace_cached_bytes(void);
/* Borrow only existing zeroed storage for short PKI work; never allocates.
 * The caller owns it until release, including if the mesh stops meanwhile. */
uint8_t *wendy_pki_input_workspace_borrow(size_t *capacity);
void wendy_pki_input_workspace_release(uint8_t *);
