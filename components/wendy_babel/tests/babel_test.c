/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_babel.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct wb_engine engines[3], spare;
static bool deny;
static bool allow(void *ctx, uint64_t router, const struct wb_prefix *prefix, uint16_t seq)
{
    (void)ctx;
    (void)router;
    (void)prefix;
    (void)seq;
    return !deny;
}
static struct wb_prefix host(unsigned n)
{
    struct wb_prefix p = {.bytes = {0xfd, 0x45, 0xb8, 0x91, 0x56, 0x7f}, .bits = 128, .family = 6};
    p.bytes[15] = (uint8_t)n;
    return p;
}
static struct wb_link make_link(unsigned a, unsigned b, uint16_t c)
{
    struct wb_link l = {.id = b + 1,
                        .local = {0xfe, 0x80},
                        .peer = {0xfe, 0x80},
                        .cost = c,
                        .max_packet = WB_PACKET_MAX};
    l.local[15] = (uint8_t)(a + 1);
    l.peer[15] = (uint8_t)(b + 1);
    return l;
}
struct packet
{
    unsigned from, to;
    size_t size;
    uint8_t data[WB_PACKET_MAX];
};
static struct packet packets[512];
static unsigned written, read_at;
static uint64_t now, generation, link_ids[3][3];
static void complete(unsigned index, int result)
{
    struct wb_engine *e = &engines[index];
    if (result < 0)
        fprintf(stderr, "node=%u time=%llu result=%d stopped=%d pending=%llu queued=%zu/%zu\n",
                index, (unsigned long long)now, result, e->stopped, (unsigned long long)e->pending,
                e->message_cursor, e->message_count);
    assert(result >= 0);
    if (result == WB_PENDING)
    {
        assert(wb_tick(e, now) == WB_BUSY);
        assert(wb_commit(e, e->pending, true) == WB_OK);
    }
    uint8_t history[WB_HISTORY_MAX];
    int history_size = wb_save(e, history, sizeof history);
    assert(history_size > 0);
    for (;;)
    {
        uint8_t packet[WB_PACKET_MAX];
        uint64_t link = 0;
        int n = wb_next_packet(e, &link, packet, sizeof packet);
        assert(n >= 0);
        if (!n)
            break;
        assert(written - read_at < 512);
        struct packet *p = &packets[written++ % 512];
        p->from = index;
        p->to = (unsigned)((link - 1) % 3);
        p->size = (size_t)n;
        memcpy(p->data, packet, (size_t)n);
    }
}
static void deliver(void)
{
    unsigned count = 0;
    while (read_at < written)
    {
        struct packet p = packets[read_at++ % 512];
        assert(p.to < 3);
        assert(++count < 10000);
        complete(p.to, wb_receive(&engines[p.to], now, link_ids[p.to][p.from], p.data, p.size));
    }
    written = read_at = 0;
}
static void advance(uint64_t end)
{
    while (now < end)
    {
        now += 20;
        for (unsigned i = 0; i < 3; i++)
            complete(i, wb_tick(&engines[i], now));
        deliver();
    }
}
static void init(void)
{
    now = 0;
    generation = 0;
    memset(link_ids, 0, sizeof link_ids);
    written = read_at = 0;
    deny = false;
    for (unsigned i = 0; i < 3; i++)
    {
        struct wb_config c = {.router = i + 1, .hello_ms = 1000, .update_ms = 4000, .allow = allow};
        assert(wb_init(&engines[i], &c) == 0);
        struct wb_prefix p = host(i + 1);
        complete(i, wb_originate(&engines[i], now, &p, 0));
    }
}
static void connect(unsigned a, unsigned b, uint16_t c)
{
    struct wb_link ab = make_link(a, b, c), ba = make_link(b, a, c);
    generation += 3;
    ab.id += generation;
    ba.id += generation;
    link_ids[a][b] = ab.id;
    link_ids[b][a] = ba.id;
    complete(a, wb_add_link(&engines[a], now, &ab));
    complete(b, wb_add_link(&engines[b], now, &ba));
    deliver();
}
static const struct wb_route *route(unsigned node, unsigned destination)
{
    struct wb_prefix p = host(destination + 1);
    return wb_lookup(&engines[node], &p);
}
static void test_transit(void)
{
    init();
    connect(0, 1, 128);
    connect(1, 2, 128);
    advance(12000);
    const struct wb_route *r = route(0, 2);
    assert(r && !r->unreachable && r->link == link_ids[0][1] && r->metric == 256);
    r = route(2, 0);
    assert(r && !r->unreachable && r->link == link_ids[2][1] && r->metric == 256);
    connect(0, 2, 2048);
    advance(22000);
    r = route(0, 2);
    assert(r && r->link == link_ids[0][1] && r->metric == 256);
    complete(1, wb_remove_link(&engines[1], now, link_ids[1][2]));
    complete(2, wb_remove_link(&engines[2], now, link_ids[2][1]));
    deliver();
    advance(42000);
    r = route(0, 2);
    assert(r && !r->unreachable && r->link == link_ids[0][2] && r->metric == 2048);
    /* Removing every path leaves an explicit /128 suppression entry. */
    complete(0, wb_remove_link(&engines[0], now, link_ids[0][2]));
    complete(2, wb_remove_link(&engines[2], now, link_ids[2][0]));
    deliver();
    advance(44000);
    r = route(0, 2);
    assert(!r || r->unreachable);
}
static void test_policy(void)
{
    init();
    connect(0, 1, 128);
    connect(1, 2, 128);
    advance(12000);
    assert(route(0, 2) && !route(0, 2)->unreachable);
    deny = true;
    complete(0, wb_tick(&engines[0], now));
    deliver();
    assert(route(0, 2) && route(0, 2)->unreachable);
    deny = false;
    advance(24000);
    assert(route(0, 2) && !route(0, 2)->unreachable);
}
static void test_endpoint_policy(void)
{
    init();
    struct wb_config c = engines[1].config;
    c.local_only = true;
    assert(wb_init(&engines[1], &c) == WB_OK);
    struct wb_prefix own = host(2);
    complete(1, wb_originate(&engines[1], now, &own, 0));
    connect(0, 1, 128);
    connect(1, 2, 128);
    advance(12000);
    assert(route(0, 1) && !route(0, 1)->unreachable);
    assert(route(2, 1) && !route(2, 1)->unreachable);
    assert(!route(0, 2) && !route(2, 0));
    assert(engines[1].route_count == 1 && !engines[1].candidates);
}
static void test_history(void)
{
    init();
    connect(0, 1, 128);
    connect(1, 2, 128);
    advance(12000);
    uint8_t history[WB_HISTORY_MAX];
    int size = wb_save(&engines[1], history, sizeof history);
    assert(size > 0);
    struct wb_config c = engines[1].config;
    assert(wb_restore(&spare, &c, history, (size_t)size) == 0);
    assert(spare.route_count == 0 && spare.seqno == engines[1].seqno &&
           spare.last_link == engines[1].last_link);
    struct wb_link l = make_link(1, 0, 128);
    assert(wb_add_link(&spare, 0, &l) == WB_INVALID); /* stale link incarnation */
    int s = wb_tick(&spare, 0);
    assert(s == WB_PENDING);
    assert(wb_commit(&spare, spare.pending, true) == 0);
    struct wb_prefix p = host(3);
    const struct wb_route *r = wb_lookup(&spare, &p);
    assert(r && r->unreachable);
    history[4] ^= 1;
    assert(wb_restore(&spare, &c, history, (size_t)size) == WB_INVALID);
}
static void test_capacity_and_commit(void)
{
    struct wb_config c = {.router = 42};
    assert(wb_init(&spare, &c) == 0);
    for (unsigned i = 0; i < WB_ROUTES; i++)
    {
        struct wb_prefix p = host(i + 1);
        assert(wb_originate(&spare, 0, &p, 0) == WB_PENDING);
        assert(wb_next_packet(&spare, &now, NULL, 0) == WB_BUSY);
        assert(wb_commit(&spare, spare.pending, true) == 0);
    }
    struct wb_prefix extra = host(200);
    assert(wb_originate(&spare, 0, &extra, 0) == WB_LIMIT);
    assert(spare.route_count == WB_ROUTES && !spare.stopped);
    assert(wb_withdraw(&spare, 0, &extra) == 0);
    struct wb_prefix p = host(1);
    assert(wb_withdraw(&spare, 0, &p) == WB_PENDING);
    assert(wb_commit(&spare, spare.pending, false) == WB_STOPPED);
    assert(wb_tick(&spare, 1) == WB_STOPPED);
}
static unsigned visits;
static struct wb_message decoded;
static void visit(void *ctx, const struct wb_message *m)
{
    (void)ctx;
    visits++;
    decoded = *m;
}
static void test_wire(void)
{
    uint8_t source[16] = {0xfe, 0x80}, packet[128] = {42, 2};
    source[15] = 2;
    struct wb_message m = {.type = WB_UPDATE,
                           .prefix = host(3),
                           .router = UINT64_MAX - 2,
                           .metric = 128,
                           .seqno = 65535,
                           .interval = 400};
    size_t n = wb_encode(&m, packet + 4, sizeof packet - 4);
    assert(n > 0);
    packet[2] = 0;
    packet[3] = (uint8_t)n;
    visits = 0;
    assert(wb_decode(packet, n + 4, source, visit, NULL) == 0);
    assert(visits == 1 && decoded.router == m.router && decoded.seqno == 65535 &&
           wb_prefix_equal(&decoded.prefix, &m.prefix));
    packet[n + 4] = WB_HELLO;
    packet[n + 5] = 99;
    packet[3] = (uint8_t)(n + 2);
    visits = 0;
    assert(wb_decode(packet, n + 6, source, visit, NULL) == WB_INVALID && visits == 0);
    /* Mandatory unknown sub-TLV suppresses the update after its context. */
    n = wb_encode(&m, packet + 4, sizeof packet - 4);
    packet[17] += 2;
    packet[n + 4] = 128;
    packet[n + 5] = 0;
    packet[3] = (uint8_t)(n + 2);
    visits = 0;
    assert(wb_decode(packet, n + 6, source, visit, NULL) == 0 && visits == 0);
    for (size_t size = 0; size < n + 6; size++)
    {
        visits = 0;
        (void)wb_decode(packet, size, source, visit, NULL);
    }
}
int main(void)
{
    test_wire();
    test_transit();
    test_policy();
    test_endpoint_policy();
    test_history();
    test_capacity_and_commit();
    for (unsigned i = 0; i < 3; i++)
        wb_deinit(&engines[i]);
    wb_deinit(&spare);
    printf("native C Babel engine=%zu bytes; source=%zu candidate=%zu route=%zu; history bound=%u; "
           "transit, fallback, policy, restart and bounds passed\n",
           sizeof(struct wb_engine), sizeof(struct wb_source), sizeof(struct wb_candidate),
           sizeof(struct wb_route), WB_HISTORY_MAX);
}
