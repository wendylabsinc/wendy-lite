#include "wendy_net_direct_packet.h"
#include "wendy_net_direct_flows.h"
#include <string.h>
int wn_direct_packet_init(struct wn_direct_packet *p, uint8_t *storage, size_t size)
{
    if (!p || !storage || size < 3 || size / 3 > UINT16_MAX)
        return -1;
    *p = (struct wn_direct_packet){.storage = storage, .capacity = size / 3};
    return 0;
}
int wn_direct_packet_init_dynamic(struct wn_direct_packet *p, size_t maximum,
                                  void *(*allocate)(size_t), void (*release)(void *))
{
    if (!p || !maximum || maximum > UINT16_MAX || !allocate || !release)
        return -1;
    *p = (struct wn_direct_packet){.capacity = maximum, .allocate = allocate, .release = release};
    return 0;
}
int wn_direct_packet_bind(struct wn_direct_packet *p, uint64_t generation, uint32_t alias)
{
    if (!p || !p->used || p->promoted || !generation || generation <= p->tx.generation ||
        generation <= p->rx.generation || !alias)
        return -1;
    return wn_direct_datagram_sender_bind(&p->tx, generation, alias) ||
                   wn_direct_datagram_bind(&p->rx, generation, alias)
               ? -1
               : 0;
}
int wn_direct_packet_open(struct wn_direct_packet *p, uint32_t flow, size_t maximum,
                          uint64_t generation, uint32_t alias)
{
    if (!p || p->used || !maximum || maximum > p->capacity)
        return -1;
    *p = (struct wn_direct_packet){.storage = p->storage,
                                   .capacity = p->capacity,
                                   .allocate = p->allocate,
                                   .release = p->release};
    if (!p->storage && p->allocate)
        p->storage = p->allocate(3 * p->capacity);
    if (!p->storage)
        return WN_DIRECT_CAPACITY;
    if (wn_direct_datagram_sender_init(&p->tx, flow, p->storage, maximum) ||
        wn_direct_datagram_init(&p->rx, flow, p->storage + p->capacity, maximum)) {
        wn_direct_packet_close(p);
        return -1;
    }
    p->used = true;
    p->ready = false;
    if (wn_direct_packet_bind(p, generation, alias)) {
        wn_direct_packet_close(p);
        return -1;
    }
    return 0;
}
void wn_direct_packet_suspend(struct wn_direct_packet *p)
{
    if (!p || !p->used || p->promoted)
        return;
    wn_direct_datagram_sender_suspend(&p->tx);
    wn_direct_datagram_suspend(&p->rx);
    /* A complete already-received message may still reach the local socket;
     * only incomplete/unsent messages are discarded across carrier loss. */
}
void wn_direct_packet_close(struct wn_direct_packet *p)
{
    if (p) {
        wn_direct_packet_suspend(p);
        p->used = false;
        p->ready = false;
        if (p->storage && p->release) {
            memset(p->storage, 0, 3 * p->capacity);
            p->release(p->storage);
            p->storage = NULL;
        }
    }
}
int wn_direct_packet_receive(struct wn_direct_packet *p, uint64_t generation,
                             const struct wn_direct_frame *f)
{
    if (!p || !p->used || p->promoted)
        return -1;
    const uint8_t *data;
    size_t size;
    int result = wn_direct_datagram_receive(&p->rx, generation, f, &data, &size);
    if (result == 1 && !p->ready) {
        if (size)
            memcpy(p->storage + 2 * p->capacity, data, size);
        p->ready_size = size;
        p->ready = true;
    }
    return result < 0 ? -1 : 0;
}
int wn_direct_packet_poll_io(struct wn_direct_packet *p, const struct wn_direct_packet_io *io)
{
    if (!p || !p->used || !io || !io->read || !io->write)
        return -1;
    int progress = 0;
    if (p->ready) {
        int r = io->write(io->context, p->storage + 2 * p->capacity, p->ready_size);
        if (r < 0 || r > 1)
            return -1;
        if (r) {
            p->ready = false;
            progress = 1;
        }
    }
    if (!p->tx.active) {
        size_t size;
        int r = io->read(io->context, p->tx.storage, p->tx.capacity, &size);
        if (r < 0)
            return -1;
        if (r) {
            if (r > 2 || (r == 1 && size > p->tx.capacity))
                return -1;
            progress = 1;
            if (r == 1 && p->promoted) {
                p->tx.total = size;
                p->tx.active = true;
                p->sent = 0;
                p->header_out[0] = (uint8_t)(size >> 8);
                p->header_out[1] = (uint8_t)size;
            } else if (r == 1 && p->tx.alias &&
                       wn_direct_datagram_queue(&p->tx, p->tx.storage, size))
                return -1;
        }
    }
    return progress;
}

int wn_direct_packet_promote(struct wn_direct_packet *p)
{
    if (!p || !p->used || p->promoted || p->tx.alias || p->rx.alias || p->tx.active || p->rx.active)
        return -1;
    p->promoted = true;
    p->header_used = 0;
    p->sent = p->received = p->wanted = 0;
    p->read_wait = p->write_wait = 0;
    return 0;
}
static uint8_t want(int n)
{
    return n == -2 ? 1 : n == -3 ? 2 : 0;
}
int wn_direct_packet_upper_poll(struct wn_direct_packet *p, const struct wn_direct_upper *upper)
{
    if (!p || !p->used || !p->promoted || !upper || !upper->read || !upper->write)
        return -1;
    int progress = 0;
    if (p->tx.active) {
        const uint8_t *data;
        size_t size;
        if (p->sent < 2) {
            data = p->header_out + p->sent;
            size = 2 - p->sent;
        } else {
            data = p->tx.storage + p->sent - 2;
            size = p->tx.total + 2 - p->sent;
        }
        int n = upper->write(upper->context, data, size);
        p->write_wait = want(n);
        if (n > 0) {
            if ((size_t)n > size)
                return -1;
            p->sent += (size_t)n;
            progress = 1;
            if (p->sent == p->tx.total + 2)
                p->tx.active = false;
        } else if (!p->write_wait)
            return -1;
    }
    if (p->header_used < 2) {
        size_t size = 2 - p->header_used;
        int n = upper->read(upper->context, p->header_in + p->header_used, size);
        p->read_wait = want(n);
        if (n > 0) {
            if ((size_t)n > size)
                return -1;
            p->header_used += (uint8_t)n;
            progress = 1;
            if (p->header_used == 2) {
                p->wanted = ((size_t)p->header_in[0] << 8) | p->header_in[1];
                p->received = 0;
                if (p->wanted > p->rx.capacity)
                    return -1;
            }
        } else if (!p->read_wait)
            return -1;
    }
    if (p->header_used == 2) {
        if (p->received < p->wanted) {
            size_t size = p->wanted - p->received;
            int n = upper->read(upper->context, p->rx.storage + p->received, size);
            p->read_wait = want(n);
            if (n > 0) {
                if ((size_t)n > size)
                    return -1;
                p->received += (size_t)n;
                progress = 1;
            } else if (!p->read_wait)
                return -1;
        }
        if (p->received == p->wanted) {
            if (!p->ready) {
                if (p->wanted)
                    memcpy(p->storage + 2 * p->capacity, p->rx.storage, p->wanted);
                p->ready_size = p->wanted;
                p->ready = true;
            }
            p->header_used = 0;
            progress = 1;
        }
    }
    return progress;
}

static int socket_read(void *arg, uint8_t *p, size_t capacity, size_t *size)
{
    return wn_direct_socket_datagram_read(arg, p, capacity, size);
}
static int socket_write(void *arg, const uint8_t *p, size_t size)
{
    return wn_direct_socket_datagram_write(arg, p, size);
}
int wn_direct_packet_poll(struct wn_direct_packet *p, struct wn_direct_socket *socket)
{
    if (!socket || socket->fd < 0)
        return -1;
    const struct wn_direct_packet_io io = {
        .context = socket, .read = socket_read, .write = socket_write};
    return wn_direct_packet_poll_io(p, &io);
}
