#include "wendy_server_tls.h"
#include "wendy_conf.h"
#include "wendy_pki.h"
#include "esp_tls.h"
#include <fcntl.h>

static ssize_t stream_result(ssize_t result)
{
    if (result == ESP_TLS_ERR_SSL_WANT_READ) return WCOM_STREAM_ERR_WANT_READ;
    if (result == ESP_TLS_ERR_SSL_WANT_WRITE) return WCOM_STREAM_ERR_WANT_WRITE;
    return result < 0 ? WCOM_STREAM_ERR_UNKNOWN : result;
}

static bool anonymous_access_allowed(void)
{
    return !wendy_conf_has_enrollment() && !wendy_pki_reset_in_progress();
}

static ssize_t anonymous_read(void *context, void *data, size_t size)
{
    if (!anonymous_access_allowed()) return WCOM_STREAM_ERR_UNKNOWN;
    return stream_result(esp_tls_conn_read(context, data, size));
}

static ssize_t anonymous_write(void *context, const void *data, size_t size)
{
    if (!anonymous_access_allowed()) return WCOM_STREAM_ERR_UNKNOWN;
    return stream_result(esp_tls_conn_write(context, data, size));
}

static int anonymous_fd(void *context)
{
    int fd = -1;
    if (esp_tls_get_conn_sockfd(context, &fd) != ESP_OK) return -1;
    return fd;
}

const struct wcom_stream_ops wendy_server_anonymous_tls_ops = {
    .read = anonymous_read,
    .write = anonymous_write,
    .wakeup_fd = anonymous_fd,
};

int wendy_server_add_anonymous_tls_link(esp_tls_t *tls,
                                      wcom_interruption_handler_t handler)
{
    int fd = anonymous_fd(tls);
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return wcom_add_socket_link_with_permission(&wendy_server_anonymous_tls_ops,
        tls, handler, WCOM_LINK_PERMISSION_FULL);
}
