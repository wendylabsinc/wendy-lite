#include "wendy_net_direct_guest_packet.h"
#include "wendy_net.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
static int owner = 5, association = 7, closed, delivered, completed;
static bool alive = true, blocked = true, tx, connect_fail;
int wendy_net_guest_datagram_owner(uint16_t port)
{
    return port == 9000 ? owner : -1;
}
unsigned wendy_net_guest_datagram_capacity(void)
{
    return 1024;
}
bool wendy_net_mesh_socket_live(int handle)
{
    assert(handle == association);
    return alive;
}
int wendy_net_mesh_datagram_connected(int handle, unsigned max)
{
    assert(handle == association && max == 1024);
    return connect_fail ? -1 : 0;
}
int wendy_net_guest_datagram_take(int handle, uint8_t **packet, size_t *size)
{
    assert(handle == association);
    *packet = NULL;
    *size = 0;
    if (!tx)
        return 0;
    tx = false;
    *packet = malloc(4);
    assert(*packet);
    memcpy(*packet, "ping", 4);
    *size = 4;
    return 1;
}
void wendy_net_guest_datagram_sent(int handle)
{
    assert(handle == association);
    completed++;
}
void wendy_net_guest_datagram_closed(int handle)
{
    assert(handle == association);
    closed++;
}
int wendy_net_guest_datagram_deliver_retained(int expected, int *handle, uint8_t **packet,
                                              size_t size, unsigned max,
                                              wendy_net_packet_release_fn release)
{
    assert(expected == owner && max == 1024 && size == 0 && *packet);
    if (blocked)
        return 0;
    assert(!*handle || *handle == association);
    *handle = association;
    release(*packet);
    *packet = NULL;
    delivered++;
    return 1;
}
int wendy_net_mesh_datagram_receive_owned(int handle, uint8_t **packet, size_t size,
                                          wendy_net_packet_release_fn release)
{
    assert(handle == association && size == 0 && *packet);
    release(*packet);
    *packet = NULL;
    delivered++;
    return 1;
}
int main(void)
{
    assert(wendy_net_runtime_memory_open());
    struct wn_direct_packet_io io;
    assert(wn_direct_guest_packet_incoming(1, 1024, &io) == WN_DIRECT_DENIED);
    assert(!wn_direct_guest_packet_incoming(9000, 1024, &io));
    uint8_t bytes[4];
    size_t size;
    assert(io.read(io.context, bytes, sizeof bytes, &size) == 0);
    assert(io.write(io.context, NULL, 0) == 0); /* retains one charged empty packet */
    wendy_net_memory_snapshot_t before, after;
    wendy_net_runtime_memory_snapshot(&before);
    assert(io.write(io.context, NULL, 0) == 0);
    wendy_net_runtime_memory_snapshot(&after);
    assert(before.current_bytes == after.current_bytes &&
           before.allocation_count == after.allocation_count);
    blocked = false;
    assert(io.write(io.context, NULL, 0) == 1 && delivered == 1);
    tx = true;
    assert(io.read(io.context, bytes, sizeof bytes, &size) == 1 && size == 4 &&
           !memcmp(bytes, "ping", 4) && completed == 1);
    owner++;
    assert(io.write(io.context, NULL, 0) == -1 &&
           io.read(io.context, bytes, sizeof bytes, &size) == -1);
    io.close(io.context);
    assert(closed == 1 && wendy_net_runtime_memory_drained());
    connect_fail = true;
    assert(wn_direct_guest_packet_outgoing(association, 1024, &io) == WN_DIRECT_DENIED &&
           wendy_net_runtime_memory_drained());
    connect_fail = false;
    assert(!wn_direct_guest_packet_outgoing(association, 1024, &io));
    assert(io.write(io.context, NULL, 0) == 1);
    alive = false;
    assert(io.read(io.context, bytes, sizeof bytes, &size) == -1);
    io.close(io.context);
    assert(closed == 2 && wendy_net_runtime_memory_drained());
    wendy_net_runtime_memory_close();
    return 0;
}
