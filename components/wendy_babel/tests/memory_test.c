/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_babel.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct heap
{
    size_t live, peak, calls, fail_at;
};
struct allocation
{
    max_align_t alignment;
    size_t bytes;
};
static void *allocate(void *context, size_t bytes)
{
    struct heap *h = context;
    if (++h->calls == h->fail_at)
        return NULL;
    struct allocation *a = malloc(sizeof *a + bytes);
    assert(a);
    a->bytes = bytes;
    h->live += bytes;
    if (h->live > h->peak)
        h->peak = h->live;
    return a + 1;
}
static void deallocate(void *context, void *memory)
{
    struct heap *h = context;
    struct allocation *a = (struct allocation *)memory - 1;
    assert(h->live >= a->bytes);
    h->live -= a->bytes;
    free(a);
}
static struct wb_prefix host(unsigned n)
{
    struct wb_prefix p = {.bytes = {0xfd, 0x45, 0xb8, 0x91, 0x56, 0x7f}, .bits = 128, .family = 6};
    p.bytes[15] = n;
    return p;
}
static int drain(struct wb_engine *e, int result)
{
    if (result < 0)
        return result;
    if (result == WB_PENDING)
    {
        uint8_t blocked[WB_PACKET_MAX];
        uint64_t id;
        assert(wb_next_packet(e, &id, blocked, sizeof blocked) == WB_BUSY);
        assert(wb_commit(e, e->pending, true) == WB_OK);
    }
    uint8_t history[WB_HISTORY_MAX], packet[WB_PACKET_MAX];
    uint64_t id;
    assert(wb_save(e, history, sizeof history) >= 40);
    while ((result = wb_next_packet(e, &id, packet, sizeof packet)) > 0)
    {
    }
    assert(result == 0 && !e->messages);
    if (!e->links_capacity)
        assert(!e->before && !e->scratch);
    return result;
}
static int neighbour(struct wb_engine *e, uint64_t link, unsigned peer)
{
    uint8_t packet[160] = {42, 2};
    size_t n = 4;
    struct wb_message hello = {.type = WB_HELLO, .seqno = 1, .interval = 400};
    struct wb_message ihu = {.type = WB_IHU, .metric = 128, .interval = 800};
    struct wb_message route = {.type = WB_UPDATE,
                               .prefix = host(peer),
                               .router = peer,
                               .seqno = 1,
                               .metric = 0,
                               .interval = 1600};
    n += wb_encode(&hello, packet + n, sizeof packet - n);
    n += wb_encode(&ihu, packet + n, sizeof packet - n);
    n += wb_encode(&route, packet + n, sizeof packet - n);
    packet[2] = (n - 4) >> 8;
    packet[3] = n - 4;
    return wb_receive(e, 0, link, packet, n);
}
static struct wb_link link(unsigned id)
{
    struct wb_link l = {.id = id,
                        .local = {0xfe, 0x80},
                        .peer = {0xfe, 0x80},
                        .cost = 128,
                        .max_packet = WB_PACKET_MAX};
    l.local[15] = 3;
    l.peer[15] = id;
    return l;
}
static void report(struct wb_engine *e, struct heap *h, const char *name, bool measure)
{
    struct wb_memory m = wb_memory(e);
    assert(m.current == sizeof *e + h->live && m.peak == sizeof *e + h->peak);
    if (measure)
        printf("%s current=%zu peak=%zu routes=%zu\n", name, m.current, m.peak, e->route_count);
}
/* Fail every allocation along the successful path, including transient route
 * snapshots, growth copies, history and queues. Never export before commit;
 * unrecoverable forwarding/suppression allocation failures stop the engine. */
static size_t scenario(size_t fail_at, bool measure)
{
    struct wb_engine e = {0};
    struct heap h = {.fail_at = fail_at};
    struct wb_config c = {
        .router = 3, .allocate = allocate, .deallocate = deallocate, .memory_context = &h};
    assert(wb_init(&e, &c) == WB_OK && !h.live && !h.calls);
    assert(sizeof e <= 512);
    for (unsigned i = 0; i < 1000; i++)
        assert(drain(&e, wb_tick(&e, 0)) == 0);
    assert(!h.calls && wb_next_deadline(&e) == UINT64_MAX);
    report(&e, &h, "inactive", measure);
    struct wb_prefix own = host(3);
    int r = drain(&e, wb_originate(&e, 0, &own, 0));
    if (r < 0)
        goto done;
    report(&e, &h, "own_address_only", measure);
    for (unsigned i = 1; i <= 2; i++)
    {
        struct wb_link l = link(i);
        r = drain(&e, wb_add_link(&e, 0, &l));
        if (r < 0)
            goto done;
        r = drain(&e, neighbour(&e, i, i));
        if (r < 0)
            goto done;
        assert(e.route_count >= 1);
        if (!fail_at)
        {
            /* Settle snapshot growth after a newly learned route. Repeating
             * an unchanged event must not need heap just to reselect routes. */
            assert(drain(&e, wb_tick(&e, 0)) == 0);
            size_t prior_calls = h.calls;
            for (unsigned tick = 0; tick < 1000; tick++)
                assert(drain(&e, wb_tick(&e, 0)) == 0);
            assert(h.calls == prior_calls);
            if (measure)
                printf("steady_%u_peer allocation_calls_per_1000_ticks=%zu\n",
                       i, h.calls - prior_calls);
        }
        report(&e, &h, i == 1 ? "one_peer" : "two_peers_transit_tables", measure);
        if (!fail_at)
            assert(wb_memory(&e).current < (i == 1 ? 2048 : 3072));
    }
    r = drain(&e, wb_remove_link(&e, 1, 1));
    if (r < 0)
        goto done;
    r = drain(&e, wb_remove_link(&e, 1, 2));
    if (r < 0)
        goto done;
    r = drain(&e, wb_withdraw(&e, 1, &own));
    if (r < 0)
        goto done;
    report(&e, &h, "disconnected_with_required_history", measure);
    /* History must survive disconnection until its protocol lifetime expires. */
    if (!fail_at)
        assert(h.live && e.sources);
    r = drain(&e, wb_tick(&e, 400000));
    if (r < 0)
        goto done;
    r = drain(&e, wb_tick(&e, 800000));
    if (r < 0)
        goto done;
    assert(!h.live && !e.route_count);
    report(&e, &h, "expired_back_to_inactive", measure);
done:
    if (r < 0)
    {
        assert(fail_at && (r == WB_STOPPED || r == WB_LIMIT));
        if (r == WB_STOPPED)
        {
            uint8_t packet[WB_PACKET_MAX];
            uint64_t id;
            assert(wb_next_packet(&e, &id, packet, sizeof packet) == WB_STOPPED);
            assert(wb_tick(&e, 800001) == WB_STOPPED);
        }
    }
    report(&e, &h, "final", false);
    size_t calls = h.calls;
    wb_deinit(&e);
    assert(!h.live);
    return calls;
}
int main(int argc, char **argv)
{
    size_t calls = scenario(0, true);
    if (argc == 2 && !strcmp(argv[1], "--normal"))
        return 0;
    for (size_t i = 1; i <= calls + 1; i++)
        scenario(i, false);
    printf("allocation failure sweep passed: %zu positions; no retained heap after deinit\n",
           calls);
}
