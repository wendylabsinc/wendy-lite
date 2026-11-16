#include "../src/direct_native.h"
#include "../src/agent_bridge.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <string.h>
struct wnab_bridge {
    struct wnap_ring in, out;
    uint8_t ib[33], ob[33];
    bool closed, retired, eof;
    uint32_t receipt, done;
};
static struct wnab_bridge bridge;
static struct wn_direct_peer peer;
static struct wn_direct_flow flow;
static enum wcom_link_permission permission;
static int opens, releases;
static bool live = true;
static uint64_t send_capacity = UINT64_MAX;
uint64_t wn_direct_flows_send_capacity(const struct wn_direct_flows *m,
                                       const struct wn_direct_flow *f)
{
    assert(m == &peer.flows && f == &flow);
    uint64_t pending = f->sender.buffer.end - f->sender.buffer.start;
    uint64_t room = m->window > pending ? m->window - pending : 0;
    return room < send_capacity ? room : send_capacity;
}
struct wnab_bridge *wnab_open(enum wcom_link_permission p, unsigned capacity)
{
    assert(capacity == 32);
    permission = p;
    opens++;
    memset(&bridge, 0, sizeof bridge);
    wnap_init(&bridge.in, bridge.ib, 32);
    wnap_init(&bridge.out, bridge.ob, 32);
    return &bridge;
}
struct wnap_ring *wnab_incoming(struct wnab_bridge *b)
{
    return &b->in;
}
struct wnap_ring *wnab_outgoing(struct wnab_bridge *b)
{
    return &b->out;
}
void wnab_notify(struct wnab_bridge *b)
{
    assert(b == &bridge);
}
void wnab_input_eof(struct wnab_bridge *b)
{
    b->eof = true;
}
bool wnab_closed(struct wnab_bridge *b)
{
    return b->closed;
}
uint32_t wnab_output_receipt(struct wnab_bridge *b)
{
    return b->receipt;
}
void wnab_output_drained(struct wnab_bridge *b, uint32_t receipt)
{
    if (b->receipt == receipt)
        b->done = receipt;
}
void wnab_close(struct wnab_bridge *b)
{
    b->closed = true;
}
bool wnab_retired(struct wnab_bridge *b)
{
    return b->retired;
}
void wnab_release(struct wnab_bridge *b)
{
    assert(b->retired);
    releases++;
}
struct wn_direct_peer *wn_direct_registry_lookup(struct wn_direct_registry *r, uint64_t serial)
{
    (void)r;
    return live && serial == peer.serial ? &peer : NULL;
}
struct wn_direct_flow *wn_direct_flows_find(struct wn_direct_flows *f, uint32_t id)
{
    assert(f == &peer.flows);
    return id == 1 ? &flow : NULL;
}
int wn_direct_session_complete_memory(struct wn_direct_session *s, uint32_t id)
{
    assert(s == &peer.session && id == 1);
    return 0;
}
int wn_direct_flows_reset(struct wn_direct_flows *f, uint32_t id, uint16_t reason)
{
    (void)f;
    (void)id;
    (void)reason;
    flow.reset = true;
    return 0;
}
int main(void)
{
    assert(wendy_net_runtime_memory_open());
    struct wn_direct_natives owner = {0};
    struct wn_direct_registry registry = {0};
    struct wn_direct_slot chunks[4];
    struct wn_direct_pool pool;
    assert(!wn_direct_pool_init_dynamic(&pool, chunks, 4, wendy_net_malloc, wendy_net_free));
    wn_direct_buffer_init(&flow.sender.buffer, &pool);
    wn_direct_buffer_init(&flow.receiver.buffer, &pool);
    assert(!wn_direct_reserve(&flow.receiver.buffer, 256));
    peer.serial = 42;
    peer.flows.window = 4;
    flow.has_lane = true;
    assert(!wn_direct_native_open(&owner, &peer, 1, false, 32));
    assert(permission == WCOM_LINK_PERMISSION_SENSOR_ONLY);
    assert(wn_direct_native_open(&owner, &peer, 1, true, 32) == WN_DIRECT_DENIED && opens == 1);
    assert(wnap_write(&bridge.out, "abcdef", 6) == 6);
    bridge.receipt = 7;
    send_capacity = 0;
    assert(!wn_direct_natives_poll(&owner, &registry));
    assert(!flow.sender.buffer.end && wnap_available(&bridge.out) == 6);
    send_capacity = UINT64_MAX;
    assert(wn_direct_natives_poll(&owner, &registry));
    assert(flow.sender.buffer.end == 4 && wnap_available(&bridge.out) == 2 && !bridge.done);
    peer.session.attached = true;
    peer.session.active = false;
    assert(!wn_direct_natives_poll(&owner, &registry) && wnap_available(&bridge.out) == 2);
    /* Detached app can fill bounded retention; full window leaves producer data intact. */
    peer.session.attached = false;
    assert(!wn_direct_natives_poll(&owner, &registry));
    assert(!wn_direct_release(&flow.sender.buffer, 4));
    assert(wn_direct_natives_poll(&owner, &registry));
    assert(!wnap_available(&bridge.out) && !bridge.done);
    assert(!wn_direct_release(&flow.sender.buffer, 6));
    wn_direct_natives_poll(&owner, &registry);
    assert(bridge.done == 7);
    assert(!wn_direct_receive(&flow.receiver, "reply", 5));
    assert(!wn_direct_receive_finish(&flow.receiver, 5));
    assert(wn_direct_natives_poll(&owner, &registry) && bridge.eof);
    char reply[5];
    assert(wnap_read(&bridge.in, reply, 5) == 5 && !memcmp(reply, "reply", 5));
    bridge.closed = true;
    assert(wn_direct_natives_poll(&owner, &registry) && flow.sender.finished && owner.first);
    live = false;
    wn_direct_natives_poll(&owner, &registry);
    assert(owner.first && !releases);
    bridge.retired = true;
    assert(wn_direct_natives_poll(&owner, &registry) && !owner.first && releases == 1);
    live = true;
    assert(!wn_direct_native_open(&owner, &peer, 1, true, 32) &&
           permission == WCOM_LINK_PERMISSION_FULL);
    assert(!wn_direct_natives_stop(&owner));
    bridge.retired = true;
    assert(wn_direct_natives_stop(&owner) && releases == 2);
    wn_direct_close(&flow.sender.buffer);
    wn_direct_close(&flow.receiver.buffer);
    assert(wendy_net_runtime_memory_drained());
    wendy_net_runtime_memory_close();
    return 0;
}
