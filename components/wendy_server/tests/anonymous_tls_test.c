#include "wendy_server_tls.h"
#include "wendy_conf.h"
#include "wendy_pki.h"
#include "esp_tls.h"
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static bool enrolled, resetting;
static unsigned reads, writes;
static ssize_t tls_result = 4;
static esp_err_t fd_result = ESP_OK;
static esp_tls_t connection = {.fd = 42};
static unsigned registrations;
static int registration_result = 7;

bool wendy_conf_has_enrollment(void) { return enrolled; }
bool wendy_pki_reset_in_progress(void) { return resetting; }

ssize_t esp_tls_conn_read(esp_tls_t *tls, void *data, size_t size)
{
    assert(tls == &connection && size == 4);
    ++reads;
    if (tls_result > 0) memcpy(data, "data", (size_t)tls_result);
    return tls_result;
}

ssize_t esp_tls_conn_write(esp_tls_t *tls, const void *data, size_t size)
{
    assert(tls == &connection && size == 4 && !memcmp(data, "data", 4));
    ++writes;
    return tls_result;
}

esp_err_t esp_tls_get_conn_sockfd(esp_tls_t *tls, int *fd)
{
    assert(tls == &connection);
    if (fd_result == ESP_OK) *fd = tls->fd;
    return fd_result;
}

int wcom_add_socket_link_with_permission(const struct wcom_stream_ops *ops, void *context,
                                         wcom_interruption_handler_t handler,
                                         enum wcom_link_permission permission)
{
    assert(ops == &wendy_server_anonymous_tls_ops && context == &connection);
    assert(handler == NULL && permission == WCOM_LINK_PERMISSION_FULL);
    /* Registration can immediately call observers that post reads or writes. */
    assert(fcntl(connection.fd, F_GETFL, 0) & O_NONBLOCK);
    ++registrations;
    return registration_result;
}

static void test_socket_setup(void)
{
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    connection.fd = sockets[0];
    int original_flags = fcntl(connection.fd, F_GETFL, 0);
    assert(original_flags >= 0 && !(original_flags & O_NONBLOCK));
    fd_result = ESP_OK;
    assert(wendy_server_add_anonymous_tls_link(&connection, NULL) == 7);
    assert(registrations == 1);
    assert(fcntl(connection.fd, F_GETFL, 0) == (original_flags | O_NONBLOCK));

    registration_result = -1;
    assert(wendy_server_add_anonymous_tls_link(&connection, NULL) == -1);
    assert(registrations == 2);
    fd_result = ESP_FAIL;
    assert(wendy_server_add_anonymous_tls_link(&connection, NULL) == -1);
    assert(registrations == 2);
    fd_result = ESP_OK;
    assert(close(sockets[0]) == 0);
    assert(wendy_server_add_anonymous_tls_link(&connection, NULL) == -1);
    assert(registrations == 2);
    assert(close(sockets[1]) == 0);
}

static void assert_io(ssize_t expected)
{
    char data[4] = {0};
    assert(wendy_server_anonymous_tls_ops.read(&connection, data, sizeof data) == expected);
    if (expected > 0) assert(!memcmp(data, "data", (size_t)expected));
    assert(wendy_server_anonymous_tls_ops.write(&connection, "data", 4) == expected);
}

int main(void)
{
    assert(wendy_server_anonymous_tls_ops.wakeup_fd(&connection) == 42);
    fd_result = ESP_FAIL;
    assert(wendy_server_anonymous_tls_ops.wakeup_fd(&connection) == -1);

    assert_io(4);
    assert(reads == 1 && writes == 1);

    /* An existing anonymous connection loses both directions immediately when
     * enrollment is stored, even when TLS has already buffered application data. */
    enrolled = true;
    assert_io(WCOM_STREAM_ERR_UNKNOWN);
    assert(reads == 1 && writes == 1);

    /* Reset keeps access revoked after it removes enrollment configuration. */
    enrolled = false;
    resetting = true;
    assert_io(WCOM_STREAM_ERR_UNKNOWN);
    assert(reads == 1 && writes == 1);

    resetting = false;
    const ssize_t inputs[] = {2, 0, ESP_TLS_ERR_SSL_WANT_READ, ESP_TLS_ERR_SSL_WANT_WRITE, -99};
    const ssize_t outputs[] = {2, 0, WCOM_STREAM_ERR_WANT_READ, WCOM_STREAM_ERR_WANT_WRITE,
                               WCOM_STREAM_ERR_UNKNOWN};
    for (size_t i = 0; i < sizeof inputs / sizeof inputs[0]; ++i) {
        tls_result = inputs[i];
        assert_io(outputs[i]);
    }
    test_socket_setup();
    return 0;
}
