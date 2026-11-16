#include "direct_native.h"
#include "agent_bridge.h"
#include "wendy_net_alloc.h"
struct wn_direct_native {
    struct wn_direct_native *next;
    struct wnab_bridge *bridge;
    uint64_t serial;
    uint32_t id;
    bool closing, input_eof;
};
static bool retire(struct wn_direct_native *n)
{
    wnab_close(n->bridge);
    if (!wnab_retired(n->bridge))
        return false;
    wnab_output_drained(n->bridge, wnab_output_receipt(n->bridge));
    wnab_release(n->bridge);
    wendy_net_free(n);
    return true;
}
uint16_t wn_direct_native_open(struct wn_direct_natives *owner, struct wn_direct_peer *p,
                               uint32_t id, bool operator_peer, unsigned capacity)
{
    if (!owner || !p || p->session.closed || wn_direct_session_frozen(&p->session))
        return WN_DIRECT_DENIED;
    for (struct wn_direct_native *old = owner->first; old; old = old->next)
        if (old->serial == p->serial && old->id == id)
            return WN_DIRECT_DENIED;
    struct wn_direct_native *n = wendy_net_calloc(1, sizeof *n);
    if (!n)
        return WN_DIRECT_NO_CAPACITY;
    n->bridge = wnab_open(
        operator_peer ? WCOM_LINK_PERMISSION_FULL : WCOM_LINK_PERMISSION_SENSOR_ONLY, capacity);
    if (!n->bridge) {
        wendy_net_free(n);
        return WN_DIRECT_NO_CAPACITY;
    }
    n->serial = p->serial;
    n->id = id;
    n->next = owner->first;
    owner->first = n;
    if (wn_direct_session_complete_memory(&p->session, id)) {
        n->closing = true;
        return WN_DIRECT_DENIED;
    }
    return 0;
}
static int transfer(struct wn_direct_native *n, struct wn_direct_peer *p, struct wn_direct_flow *f)
{
    struct wnab_bridge *b = n->bridge;
    int progress = 0;
    uint32_t receipt = wnab_output_receipt(b);
    const uint8_t *out;
    size_t size = wnap_read_span(wnab_outgoing(b), &out);
    uint64_t room = wn_direct_flows_send_capacity(&p->flows, f);
    if (size > room)
        size = (size_t)room;
    if (size > WN_DIRECT_CHUNK)
        size = WN_DIRECT_CHUNK;
    if (size) {
        int r = wn_direct_send_accept(&f->sender, out, size, p->flows.window);
        if (r && r != WN_DIRECT_CAPACITY)
            return -1;
        if (!r) {
            wnap_consume(wnab_outgoing(b), size);
            wnab_notify(b);
            progress = 1;
        }
    }
    /* Configuration receipts wait for remote logical ownership, not enqueue. */
    if (!wnap_available(wnab_outgoing(b)) && f->sender.buffer.start == f->sender.buffer.end)
        wnab_output_drained(b, receipt);
    bool closed = wnab_closed(b);
    if (closed && !wnap_available(wnab_outgoing(b)) && !f->sender.finished) {
        wn_direct_send_finish(&f->sender);
        progress = 1;
    }
    if (closed) {
        /* Application closed its input. Drain/discard as a closed socket reader
         * would, retaining outgoing bytes until FIN and receipt reconciliation. */
        if (f->receiver.buffer.end > f->receiver.buffer.start) {
            if (wn_direct_release(&f->receiver.buffer, f->receiver.buffer.end))
                return -1;
            progress = 1;
        }
    } else {
        uint8_t *in;
        size_t capacity = wnap_write_span(wnab_incoming(b), &in), copied = 0;
        if (capacity) {
            if (wn_direct_copy(&f->receiver.buffer, f->receiver.buffer.start, in, capacity,
                               &copied))
                return -1;
            if (copied) {
                if (wn_direct_release(&f->receiver.buffer, f->receiver.buffer.start + copied))
                    return -1;
                wnap_produce(wnab_incoming(b), copied);
                wnab_notify(b);
                progress = 1;
            }
        }
    }
    if (!n->input_eof && wn_direct_receive_eof(&f->receiver)) {
        n->input_eof = true;
        wnab_input_eof(b);
        progress = 1;
    }
    return progress;
}
int wn_direct_natives_poll(struct wn_direct_natives *owner, struct wn_direct_registry *registry)
{
    int progress = 0;
    struct wn_direct_native **at = &owner->first;
    while (*at) {
        struct wn_direct_native *n = *at;
        struct wn_direct_peer *p = wn_direct_registry_lookup(registry, n->serial);
        struct wn_direct_flow *f = p ? wn_direct_flows_find(&p->flows, n->id) : NULL;
        if (!f || f->reset || !f->has_lane)
            n->closing = true;
        if (!n->closing && !wn_direct_session_frozen(&p->session)) {
            int r = transfer(n, p, f);
            if (r < 0) {
                (void)wn_direct_flows_reset(&p->flows, n->id, WN_DIRECT_IO);
                n->closing = true;
            }
            if (r)
                progress = 1;
        }
        if (n->closing) {
            struct wn_direct_native *next = n->next;
            if (retire(n)) {
                *at = next;
                progress = 1;
                continue;
            }
        }
        at = &n->next;
    }
    return progress;
}
bool wn_direct_natives_stop(struct wn_direct_natives *owner)
{
    struct wn_direct_native **at = &owner->first;
    while (*at) {
        struct wn_direct_native *n = *at, *next = n->next;
        n->closing = true;
        if (retire(n))
            *at = next;
        else
            at = &n->next;
    }
    return !owner->first;
}
