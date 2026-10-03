#pragma once
#include "esp_err.h"
#include "wendy_conf.pb.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
typedef struct wendy_pki_connection wendy_pki_connection;
/* A challenge discloses no key material. Only the USB command calls this. */
esp_err_t wendy_pki_challenge(bool status_only, char nonce_hex[65], bool *enrolled);
/* Called by the cloud task after Wi-Fi is up; all network operations are bounded. */
esp_err_t wendy_pki_connect(wendy_pki_connection **connection);
void wendy_pki_close(wendy_pki_connection *connection);
int wendy_pki_fd(void *connection);
ssize_t wendy_pki_read(void *connection, void *data, size_t size);
ssize_t wendy_pki_write(void *connection, const void *data, size_t size);
