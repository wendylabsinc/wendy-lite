#include "wendy_net_direct_socket.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
/* lwIP can report exhausted packet/queue storage as a transient syscall
 * failure. No bytes were accepted on -1: retain the stream/datagram for retry. */
static bool again(void)
{
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOMEM ||
           errno == ENOBUFS;
}
int wn_direct_socket_init(struct wn_direct_socket *s, int fd)
{
    if (!s || fd < 0)
        return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
#ifdef SO_NOSIGPIPE
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof yes))
        return -1;
#endif
    *s = (struct wn_direct_socket){.fd = fd};
    return 0;
}
int wn_direct_socket_read(struct wn_direct_socket *s, struct wn_direct_sender *tx, uint64_t window)
{
    if (!s || !tx || !tx->buffer.pool || s->fd < 0)
        return -1;
    if (s->read_eof || tx->finished)
        return 0;
    struct wn_direct_buffer *b = &tx->buffer;
    /* Sender capacity is local storage, not an advertised receive grant. */
    if (wn_direct_trim(b))
        return -1;
    uint64_t pending = b->end - b->start;
    if (pending >= window)
        return 0;
    uint64_t available = b->limit - b->end + (uint64_t)b->pool->available * WN_DIRECT_CHUNK;
    size_t n = WN_DIRECT_CHUNK;
    if (n > window - pending)
        n = (size_t)(window - pending);
    if (n > available)
        n = (size_t)available;
    if (!n)
        return 0;
    if (b->end > UINT64_MAX - n)
        return -1;
    uint8_t scratch[WN_DIRECT_CHUNK];
    /* Do not allocate a new chunk merely to discover an idle local socket.
     * PEEK leaves all bytes owned by the socket if retention allocation fails. */
    ssize_t ready = recv(s->fd, scratch, 1, MSG_DONTWAIT | MSG_PEEK);
    if (ready < 0)
        return again() ? 0 : -1;
    if (!ready) {
        s->read_eof = true;
        wn_direct_send_finish(tx);
        return 1;
    }
    int reserved = wn_direct_reserve(b, b->end + n);
    /* A free logical slot does not guarantee backing memory in a dynamic pool.
     * Leave bytes in the socket until retention storage is available. */
    if (reserved)
        return reserved == WN_DIRECT_CAPACITY ? 0 : -1;
    ssize_t got = recv(s->fd, scratch, n, MSG_DONTWAIT);
    int error = errno;
    if (got > 0 && wn_direct_send_accept(tx, scratch, (size_t)got, window))
        return -1;
    if (wn_direct_trim(b))
        return -1;
    if (got < 0) {
        errno = error;
        return again() ? 0 : -1;
    }
    if (!got) {
        s->read_eof = true;
        wn_direct_send_finish(tx);
        return 1;
    }
    return 1;
}
int wn_direct_socket_write(struct wn_direct_socket *s, struct wn_direct_receiver *rx)
{
    if (!s || !rx || !rx->buffer.pool || s->fd < 0)
        return -1;
    if (s->write_shutdown)
        return 0;
    uint8_t scratch[WN_DIRECT_CHUNK];
    size_t n = 0;
    if (wn_direct_copy(&rx->buffer, rx->buffer.start, scratch, sizeof scratch, &n))
        return -1;
    if (n) {
        ssize_t sent = send(s->fd, scratch, n, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent < 0)
            return again() ? 0 : -1;
        if (!sent || (size_t)sent > n)
            return -1;
        return wn_direct_release(&rx->buffer, rx->buffer.start + (uint64_t)sent) ? -1 : 1;
    }
    if (wn_direct_receive_eof(rx)) {
        if (shutdown(s->fd, SHUT_WR))
            return again() ? 0 : -1;
        s->write_shutdown = true;
        return 1;
    }
    return 0;
}

int wn_direct_socket_datagram_read(struct wn_direct_socket *s, uint8_t *buffer, size_t capacity,
                                   size_t *size)
{
    if (!s || s->fd < 0 || !buffer || !capacity || !size)
        return -1;
    *size = 0;
    struct iovec part = {.iov_base = buffer, .iov_len = capacity};
    struct msghdr message = {.msg_iov = &part, .msg_iovlen = 1};
    /* MSG_TRUNC is an output flag on both lwIP and POSIX. Passing it as an
     * input flag would fail on lwIP. recvmsg consumes one complete UDP packet. */
    ssize_t n = recvmsg(s->fd, &message, MSG_DONTWAIT);
    if (n < 0)
        return again() ? 0 : -1;
    if ((message.msg_flags & MSG_TRUNC) || (size_t)n > capacity)
        return 2;
    *size = (size_t)n;
    return 1;
}
int wn_direct_socket_datagram_write(struct wn_direct_socket *s, const uint8_t *buffer, size_t size)
{
    if (!s || s->fd < 0 || (!buffer && size))
        return -1;
    const uint8_t empty = 0;
    ssize_t n = send(s->fd, buffer ? buffer : &empty, size, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n < 0)
        return again() ? 0 : -1;
    return (size_t)n == size ? 1 : -1;
}
