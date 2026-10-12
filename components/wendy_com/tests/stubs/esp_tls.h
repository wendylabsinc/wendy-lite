#pragma once
#include <sys/types.h>
#include <stddef.h>
typedef struct esp_tls { int fd; } esp_tls_t;
static inline ssize_t esp_tls_conn_read(esp_tls_t *tls, void *data, size_t size) { return -1; }
static inline ssize_t esp_tls_conn_write(esp_tls_t *tls, const void *data, size_t size) { return -1; }
static inline int esp_tls_get_conn_sockfd(esp_tls_t *tls, int *fd) { *fd = tls->fd; return 0; }
