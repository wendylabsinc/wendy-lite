#pragma once
#include <stddef.h>
#include <sys/types.h>
#include "esp_err.h"

#define ESP_TLS_ERR_SSL_WANT_READ -0x6900
#define ESP_TLS_ERR_SSL_WANT_WRITE -0x6880

typedef struct esp_tls { int fd; } esp_tls_t;
ssize_t esp_tls_conn_read(esp_tls_t *tls, void *data, size_t size);
ssize_t esp_tls_conn_write(esp_tls_t *tls, const void *data, size_t size);
esp_err_t esp_tls_get_conn_sockfd(esp_tls_t *tls, int *fd);
