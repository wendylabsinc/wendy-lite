/* SPDX-License-Identifier: Apache-2.0
 * Binary pipe adapter for differential tests against the Go routing engine.
 */
#include "wendy_babel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static struct wb_engine engine;
static uint8_t input[WB_PACKET_MAX + 64];
static void read_exact(void *p, size_t n)
{
    if (fread(p, 1, n, stdin) != n)
        exit(2);
}
static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++)
        v = v << 8 | p[i];
    return v;
}
static unsigned get16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }
static void put64(uint64_t v)
{
    for (unsigned i = 0; i < 8; i++)
        putchar((int)((v >> (56 - 8 * i)) & 255));
}
static void put16(unsigned v)
{
    putchar((int)(v >> 8) & 255);
    putchar((int)v & 255);
}
static void prefix(struct wb_prefix *p, const uint8_t *data)
{
    memcpy(p->bytes, data, 16);
    p->bits = data[16];
    p->family = data[17];
}
static bool deny;
static bool allow(void *ctx, uint64_t router, const struct wb_prefix *p, uint16_t seq)
{
    (void)ctx;
    (void)router;
    (void)p;
    (void)seq;
    return !deny;
}
int main(void)
{
    for (;;)
    {
        int command = getchar();
        if (command == EOF)
        {
            wb_deinit(&engine);
            return 0;
        }
        read_exact(input, 8);
        uint64_t now = get64(input);
        int result = WB_INVALID;
        switch (command)
        {
        case 'i':
        {
            struct wb_config c = {
                .router = now, .hello_ms = 1000, .update_ms = 4000, .allow = allow};
            result = wb_init(&engine, &c);
            break;
        }
        case 't':
            result = wb_tick(&engine, now);
            break;
        case 'a':
        {
            read_exact(input, 42);
            struct wb_link l = {.id = get64(input),
                                .cost = (uint16_t)get16(input + 40),
                                .max_packet = WB_PACKET_MAX};
            memcpy(l.local, input + 8, 16);
            memcpy(l.peer, input + 24, 16);
            result = wb_add_link(&engine, now, &l);
            break;
        }
        case 'r':
        {
            read_exact(input, 10);
            uint64_t id = get64(input);
            unsigned size = get16(input + 8);
            if (size > WB_PACKET_MAX)
                return 3;
            read_exact(input, size);
            result = wb_receive(&engine, now, id, input, size);
            break;
        }
        case 'o':
        case 'w':
        {
            read_exact(input, 18);
            struct wb_prefix p;
            prefix(&p, input);
            result =
                command == 'o' ? wb_originate(&engine, now, &p, 0) : wb_withdraw(&engine, now, &p);
            break;
        }
        case 'd':
            read_exact(input, 8);
            result = wb_remove_link(&engine, now, get64(input));
            break;
        case 'c':
            read_exact(input, 10);
            result = wb_set_cost(&engine, now, get64(input), (uint16_t)get16(input + 8));
            break;
        case 'p':
            deny = !deny;
            result = wb_tick(&engine, now);
            break;
        default:
            return 4;
        }
        if (result == WB_PENDING)
            result = wb_commit(&engine, engine.pending, true);
        put16((unsigned)(uint16_t)result);
        put16(engine.seqno);
        put16((unsigned)engine.route_count);
        for (size_t i = 0; i < engine.route_count; i++)
        {
            const struct wb_route *r = &engine.routes[i];
            fwrite(r->prefix.bytes, 1, 16, stdout);
            putchar(r->prefix.bits);
            putchar(r->prefix.family);
            put64(r->router);
            put16(r->seqno);
            put16(r->metric);
            put64(r->link);
            putchar((r->local ? 1 : 0) | (r->unreachable ? 2 : 0));
            putchar(r->next_family);
            fwrite(r->next_hop, 1, 16, stdout);
        }
        for (;;)
        {
            uint8_t packet[WB_PACKET_MAX];
            uint64_t id = 0;
            int size = wb_next_packet(&engine, &id, packet, sizeof packet);
            if (size < 0)
                return 5;
            if (!size)
                break;
            put16((unsigned)size);
            put64(id);
            fwrite(packet, 1, (size_t)size, stdout);
        }
        put16(0);
        fflush(stdout);
    }
}
