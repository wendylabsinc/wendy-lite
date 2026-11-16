#include "wendy_net_direct_guest_packet.h"
#include "wendy_net_alloc.h"
#if CONFIG_WENDY_NET
#include "wendy_net.h"
#include <stdlib.h>
#include <string.h>
struct guest_packet {
    int owner, association;
    uint16_t port, maximum;
    bool outgoing;
    uint8_t *pending;
    size_t pending_size;
};
static bool live(struct guest_packet *g)
{
    if (!g->outgoing && wendy_net_guest_datagram_owner(g->port) != g->owner)
        return false;
    return g->association <= 0 || wendy_net_mesh_socket_live(g->association);
}
static int receive_guest(void *arg, uint8_t *buffer, size_t capacity, size_t *size)
{
    struct guest_packet *g = arg;
    if (!live(g))
        return -1;
    *size = 0;
    if (g->association <= 0)
        return 0;
    uint8_t *packet = NULL;
    size_t n = 0;
    int r = wendy_net_guest_datagram_take(g->association, &packet, &n);
    if (r <= 0)
        return r;
    bool oversized = n > capacity;
    if (!oversized && n)
        memcpy(buffer, packet, n);
    /* Guest TX is ordinary heap ownership; RX below is mesh-ledger ownership. */
    free(packet);
    wendy_net_guest_datagram_sent(g->association);
    if (oversized)
        return 2;
    *size = n;
    return 1;
}
static int deliver_guest(void *arg, const uint8_t *data, size_t size)
{
    struct guest_packet *g = arg;
    if (!live(g) || size > g->maximum)
        return -1;
    if (!g->pending) {
        g->pending = wendy_net_malloc(size ? size : 1);
        if (!g->pending)
            return 0;
        if (size)
            memcpy(g->pending, data, size);
        g->pending_size = size;
    }
    if (g->pending_size != size)
        return -1;
    int r = g->outgoing
                ? wendy_net_mesh_datagram_receive_owned(g->association, &g->pending, size,
                                                        wendy_net_free)
                : wendy_net_guest_datagram_deliver_retained(g->owner, &g->association, &g->pending,
                                                            size, g->maximum, wendy_net_free);
    return r;
}
static void close_guest(void *arg)
{
    struct guest_packet *g = arg;
    if (g->association > 0)
        wendy_net_guest_datagram_closed(g->association);
    wendy_net_free(g->pending);
    wendy_net_free(g);
}
static uint16_t create(int owner, uint16_t port, uint16_t maximum, bool outgoing,
                       struct wn_direct_packet_io *io)
{
    if (!io)
        return WN_DIRECT_DENIED;
    *io = (struct wn_direct_packet_io){0};
    if (owner <= 0 || !maximum || maximum > wendy_net_guest_datagram_capacity())
        return WN_DIRECT_DENIED;
    struct guest_packet *g = wendy_net_calloc(1, sizeof *g);
    if (!g)
        return WN_DIRECT_NO_CAPACITY;
    *g = (struct guest_packet){.owner = owner,
                               .association = outgoing ? owner : 0,
                               .port = port,
                               .maximum = maximum,
                               .outgoing = outgoing};
    if (outgoing && wendy_net_mesh_datagram_connected(owner, maximum)) {
        wendy_net_free(g);
        return WN_DIRECT_DENIED;
    }
    *io = (struct wn_direct_packet_io){
        .context = g, .read = receive_guest, .write = deliver_guest, .close = close_guest};
    return 0;
}
uint16_t wn_direct_guest_packet_incoming(uint16_t port, uint16_t maximum,
                                         struct wn_direct_packet_io *io)
{
    return create(wendy_net_guest_datagram_owner(port), port, maximum, false, io);
}
uint16_t wn_direct_guest_packet_outgoing(int handle, uint16_t maximum,
                                         struct wn_direct_packet_io *io)
{
    return create(handle, 0, maximum, true, io);
}

#endif
