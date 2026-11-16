#include "app_relay.h"
#include <errno.h>
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <sys/socket.h>
#endif
int wn_app_relay_step(wendy_pki_connection *connection, int backend, struct buffer buffers[2],
                      bool *local_half, bool *tls_half, bool output_pending)
{
    struct buffer *remote = &buffers[0], *local = &buffers[1];
    bool progress = false;
    if (remote->offset == remote->size && !remote->eof) {
        ssize_t n = wendy_pki_read(connection, remote->data, sizeof remote->data);
        if (n > 0) {
            remote->offset = 0;
            remote->size = n;
            progress = true;
        } else if (!n)
            remote->eof = true;
        else if (n != -2 && n != -3)
            return -1;
    }
    if (remote->offset < remote->size) {
        ssize_t n = send(backend, remote->data + remote->offset, remote->size - remote->offset,
                         MSG_DONTWAIT);
        if (n > 0) {
            remote->offset += n;
            progress = true;
        } else if (!n || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
            return -1;
    }
    if (remote->eof && remote->offset == remote->size && !*local_half) {
        if (shutdown(backend, SHUT_WR)) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                return progress;
            return -1;
        }
        *local_half = true;
        progress = true;
    }
    if (local->offset == local->size && !local->eof) {
        ssize_t n = recv(backend, local->data, sizeof local->data, MSG_DONTWAIT);
        if (n > 0) {
            local->offset = 0;
            local->size = n;
            progress = true;
        } else if (!n)
            local->eof = true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            return -1;
    }
    if (local->offset < local->size) {
        ssize_t n =
            wendy_pki_write(connection, local->data + local->offset, local->size - local->offset);
        if (n > 0) {
            local->offset += n;
            progress = true;
        } else if (n != -2 && n != -3)
            return -1;
    }
    if (local->eof && local->offset == local->size && !*tls_half) {
        int result = wendy_pki_shutdown_write(connection);
        if (!result) {
            *tls_half = true;
            /* close_notify may just have entered the BIO. Let the actor pump
             * it before trusting the output_pending snapshot from this turn. */
            return 1;
        }
        if (result != -2 && result != -3)
            return -1;
    }
    if (*tls_half && *local_half && !output_pending)
        return -1;
    return progress;
}
