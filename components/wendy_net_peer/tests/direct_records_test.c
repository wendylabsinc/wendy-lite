#include "direct_session_fixture.h"
#include "wendy_net_direct_records.h"
#include "wendy_net_direct_binding.h"
#include <stdlib.h>
static bool fail_resize;
static unsigned live_buffers;
static void *resize_record(void *p, size_t size)
{
    if (!size) {
        if (p) {
            assert(live_buffers);
            live_buffers--;
            free(p);
        }
        return NULL;
    }
    if (fail_resize) {
        fail_resize = false;
        return NULL;
    }
    void *next = realloc(p, size);
    if (next && !p)
        live_buffers++;
    return next;
}
struct transport {
    struct fixture app;
    struct wn_direct_records records;
    struct transport *other;
    uint8_t input[8192];
    size_t size, offset;
    const void *retry;
    size_t retry_size;
    bool block, eof;
};
static int read_record(void *arg, uint8_t *out, size_t size)
{
    struct transport *t = arg;
    if (t->offset == t->size)
        return t->eof ? 0 : -2;
    if (size > 3)
        size = 3;
    if (size > t->size - t->offset)
        size = t->size - t->offset;
    memcpy(out, t->input + t->offset, size);
    t->offset += size;
    return (int)size;
}
static int write_record(void *arg, const uint8_t *bytes, size_t size)
{
    struct transport *t = arg;
    if (t->retry)
        assert(t->retry == bytes && t->retry_size == size);
    if (t->block) {
        t->block = false;
        t->retry = bytes;
        t->retry_size = size;
        return -3;
    }
    t->block = true;
    t->retry = NULL;
    struct transport *o = t->other;
    if (o->offset) {
        memmove(o->input, o->input + o->offset, o->size - o->offset);
        o->size -= o->offset;
        o->offset = 0;
    }
    if (size > 7)
        size = 7;
    assert(o->size + size <= sizeof o->input);
    memcpy(o->input + o->size, bytes, size);
    o->size += size;
    return (int)size;
}
static int open_record(void *arg, uint32_t id)
{
    struct transport *t = arg;
    t->app.backend_opens++;
    complete(&t->app, id);
    return 0;
}
static int step(struct transport *t)
{
    struct wn_direct_upper io = {.context = t, .read = read_record, .write = write_record};
    assert(wn_direct_session_tick(&t->app.session, ++now) >= 0);
    return wn_direct_records_poll(&t->records, &t->app.session, t->app.session.token, &io, now,
                                  open_record, t);
}
static void pump(struct transport *a, struct transport *b)
{
    for (unsigned i = 0; i < 10000; i++) {
        int x = step(a), y = step(b);
        assert(x >= 0 && y >= 0);
        if (!x && !y && !a->records.queued && !b->records.queued && a->app.session.active &&
            b->app.session.active)
            return;
    }
    assert(!"records did not settle");
}
static int flow_export(void *arg, const char *label, const uint8_t context[32], uint8_t out[32])
{
    assert(!strcmp(label, WN_DIRECT_PROMOTED_EXPORT_LABEL));
    return export(arg, context, out);
}
static int raw_shutdown(void *arg)
{
    (void)arg;
    return 0;
}
static void raw_close(void *arg)
{
    (void)arg;
}
static void bind_raw(struct transport *a, struct transport *b, uint32_t id)
{
    struct wn_direct_promoted_binding ab, bb;
    assert(
        !wn_direct_session_start_binding(&a->app.session, id, &ab, 1, flow_export, &a->app, now));
    assert(
        !wn_direct_session_start_binding(&b->app.session, id, &bb, 0, flow_export, &b->app, now));
    struct wn_direct_upper ai = {.context = a,
                                 .read = read_record,
                                 .write = write_record,
                                 .shutdown_write = raw_shutdown,
                                 .close = raw_close};
    struct wn_direct_upper bi = ai;
    bi.context = b;
    bool marker = false;
    for (unsigned i = 0; i < 10000 && (!ab.done || !bb.done); i++) {
        assert(wn_direct_promoted_poll(&ab, &ai) >= 0);
        assert(wn_direct_promoted_poll(&bb, &bi) >= 0);
        if (bb.done && !marker) {
            assert(a->size < sizeof a->input);
            a->input[a->size++] = 42;
            marker = true;
        }
    }
    assert(ab.done && bb.done && marker);
    /* Final READY may share the TLS input with application data. */
    assert(a->size - a->offset == 1 && a->input[a->offset] == 42);
    a->offset = a->size;
    assert(!wn_direct_session_commit_flow(&a->app.session, id, &ab, &ai, now));
    assert(!wn_direct_session_commit_flow(&b->app.session, id, &bb, &bi, now));
    assert(wn_direct_flows_find(&a->app.flows, id)->promoted &&
           wn_direct_flows_find(&b->app.flows, id)->promoted);
    assert(b->app.backend_opens == 1);
}
int main(void)
{
    assert(psa_crypto_init() == PSA_SUCCESS);
    struct transport a = {0}, b = {0};
    a.other = &b;
    b.other = &a;
    init(&a.app, 0);
    init(&b.app, 1);
    a.records.resize = resize_record;
    b.records.resize = resize_record;
    attach(&a.app);
    attach(&b.app);
    pump(&a, &b);
    uint32_t id;
    assert(!wn_direct_flows_begin(&a.app.flows, (struct wn_direct_request){WN_DIRECT_TCP, 28080, 0},
                                  now, &id));
    /* Failure before copy must leave the session record unaccepted for retry. */
    fail_resize = true;
    assert(step(&a) < 0);
    assert(a.app.session.wire_size && !a.records.queued && !a.records.tx);
    pump(&a, &b);
    assert(!a.records.tx && !a.records.tx_capacity && a.records.rx_capacity == 2);
    assert(b.app.backend_opens == 1);
    wn_direct_session_lost(&a.app.session, 1, now);
    wn_direct_session_lost(&b.app.session, 1, now);
    struct transport *peers[] = {&a, &b};
    for (unsigned i = 0; i < 2; i++) {
        struct transport *t = peers[i];
        t->app.epoch++;
        assert(!wn_direct_session_promote(&t->app.session, 2, 1,
                                          t->app.session.binding.identity_digest,
                                          t->app.session.cfg.selected, t->app.session.cfg.deadline,
                                          export, &t->app, i == 0, now));
    }
    pump(&a, &b);
    assert(a.app.flows.upper_control && b.app.flows.upper_control && b.app.backend_opens == 1);
    bind_raw(&a, &b, id);
    resize_record(a.records.tx, 0);
    resize_record(a.records.rx, 0);
    resize_record(b.records.tx, 0);
    resize_record(b.records.rx, 0);
    assert(!live_buffers);
    dispose(&a.app);
    dispose(&b.app);
    return 0;
}
