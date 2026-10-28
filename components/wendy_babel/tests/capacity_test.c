/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_babel.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct wb_prefix host(unsigned n)
{
    struct wb_prefix p = {.bytes = {0xfd, 1}, .bits = 128, .family = 6};
    p.bytes[14] = n >> 8;
    p.bytes[15] = n;
    return p;
}
static void complete(struct wb_engine *e, int status)
{
    assert(status == WB_OK || status == WB_PENDING);
    /* A portable checkpoint is optional storage owned by the caller. */
    uint8_t history[WB_HISTORY_MAX];
    assert(wb_save(e, NULL, 0) == wb_save(e, history, sizeof history));
    if (status == WB_PENDING)
        assert(wb_commit(e, e->pending, true) == WB_OK);
    uint8_t packet[WB_PACKET_MAX];
    uint64_t link;
    while ((status = wb_next_packet(e, &link, packet, sizeof packet)) > 0)
        assert(wb_decode(packet, status, (uint8_t[16]){0xfe, 0x80}, NULL, NULL) == WB_OK);
    assert(status == 0 && !e->messages);
}
static void receive(struct wb_engine *e, uint64_t link, struct wb_message *m)
{
    uint8_t packet[128] = {42, 2};
    size_t n = wb_encode(m, packet + 4, sizeof packet - 4);
    assert(n && n < 256);
    packet[3] = n;
    complete(e, wb_receive(e, 0, link, packet, n + 4));
}
int main(void)
{
    struct wb_engine e = {0};
    struct wb_config c = {.router = 1000};
    assert(wb_init(&e, &c) == WB_OK && !e.config.local_only);
    assert(WB_CANDIDATES >= WB_ROUTES * WB_LINKS);
    for (unsigned path = 1; path <= WB_LINKS; path++)
    {
        struct wb_link l = {.id = path, .local = {0xfe, 0x80}, .peer = {0xfe, 0x80},
                            .cost = 128 * path, .max_packet = 512};
        l.local[15] = 100;
        l.peer[15] = path;
        complete(&e, wb_add_link(&e, 0, &l));
        struct wb_message m = {.type = WB_HELLO, .seqno = 1, .interval = 400};
        receive(&e, path, &m);
        m = (struct wb_message){.type = WB_IHU, .metric = 128, .interval = 800};
        receive(&e, path, &m);
        for (unsigned prefix = 1; prefix <= WB_ROUTES; prefix++)
        {
            m = (struct wb_message){.type = WB_UPDATE, .prefix = host(prefix), .router = prefix,
                                    .seqno = 1, .metric = 0, .interval = 1600};
            receive(&e, path, &m);
        }
    }
    size_t candidates = 0;
    for (size_t i = 0; i < e.candidates_capacity; i++)
        candidates += e.candidates[i].used;
    assert(candidates == WB_ROUTES * WB_LINKS && e.route_count == WB_ROUTES);
    assert(!e.counters.rejected && !e.counters.queue_drops);
    struct wb_prefix extra = host(WB_ROUTES + 1);
    assert(wb_originate(&e, 0, &extra, 0) == WB_LIMIT);
    struct wb_prefix own = host(1);
    /* Originating an already admitted prefix must also work at the prefix cap. */
    complete(&e, wb_originate(&e, 0, &own, 0));
    assert(wb_lookup(&e, &own)->local);
    complete(&e, wb_withdraw(&e, 0, &own));
    for (unsigned path = 1; path <= WB_LINKS; path++)
    {
        complete(&e, wb_remove_link(&e, 0, path));
        const struct wb_route *r = wb_lookup(&e, &own);
        assert(r && (path == WB_LINKS ? r->unreachable : r->link == path + 1));
    }
    complete(&e, wb_tick(&e, 400000));
    complete(&e, wb_tick(&e, 800000));
    assert(e.route_count == 0 && wb_memory(&e).current == sizeof e);
    wb_deinit(&e);
    puts("full prefix table with alternate carriers, fallback, checkpoint and expiry passed");
}
