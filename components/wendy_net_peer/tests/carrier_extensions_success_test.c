/* An unknown bounded frame must not desynchronize the next known frame. */
#include "wendy_net_carrier.h"
#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct input {
    uint8_t bytes[14000];
    size_t size, offset;
    unsigned reads, delivered;
};
static ssize_t read_bytes(void *context, void *out, size_t size)
{
    struct input *in = context;
    if (++in->reads % 7 == 0 || in->offset == in->size)
        return -2;
    if (size > 31)
        size = 31;
    if (size > in->size - in->offset)
        size = in->size - in->offset;
    memcpy(out, in->bytes + in->offset, size);
    in->offset += size;
    return (ssize_t)size;
}
static ssize_t no_write(void *context, const void *bytes, size_t size)
{
    (void)context;
    (void)bytes;
    (void)size;
    return -3;
}
static int receive(void *context, const void *bytes, size_t size, bool control)
{
    struct input *in = context;
    assert(!control && size == 1 && ((const uint8_t *)bytes)[0] == 42);
    ++in->delivered;
    return 0;
}
static void add(struct input *in, uint8_t kind, size_t size, uint8_t value)
{
    assert(in->size + 5 + size <= sizeof in->bytes);
    uint8_t *at = in->bytes + in->size;
    at[0] = kind;
    wn_put32(at + 1, (uint32_t)size);
    memset(at + 5, value, size);
    in->size += 5 + size;
}
static void init(struct wnc_carrier *c, struct input *in, uint8_t *scratch, bool operator)
{
    struct wnc_io io = {.context = in, .read = read_bytes, .write = no_write};
    assert(!wnc_init(c, &io, scratch, WN_DATAGRAM_MAX, 8192, 8192));
    if (operator)
        assert(!wnc_operator_router(c));
}
int main(void)
{
    for (unsigned operator = 0; operator < 2; operator++) {
        struct input in = {0};
        uint8_t scratch[WN_DATAGRAM_MAX];
        struct wnc_carrier carrier;
        init(&carrier, &in, scratch, operator);
        add(&in, operator ? 4 : 2, 1, 42);
        add(&in, 255, 0, 0);
        add(&in, 0, 8196, 0xa5); /* Larger than scratch; no whole-body allocation. */
        add(&in, operator ? 4 : 2, 1, 42);
        unsigned calls = 0;
        while (in.offset != in.size || carrier.header_have) {
            assert(wnc_pump(&carrier, calls++, receive, &in) >= 0);
            assert(!carrier.body || carrier.body == scratch);
            assert(calls < 2000);
        }
        assert(in.delivered == 2 && !carrier.body && !carrier.rx_discard);
        wnc_deinit(&carrier);
        in = (struct input){0};
        init(&carrier, &in, scratch, operator);
        add(&in, 255, 8197, 0);
        assert(wnc_pump(&carrier, 0, receive, &in) == WNC_INVALID);
        assert(!carrier.body);
        wnc_deinit(&carrier);
        in = (struct input){0};
        init(&carrier, &in, scratch, operator);
        add(&in, 255, 100, 0);
        in.size = 8; /* Three body bytes then no more progress. */
        assert(wnc_pump(&carrier, 0, receive, &in) == 1);
        assert(wnc_pump(&carrier, 1, receive, &in) == 1);
        assert(wnc_pump(&carrier, 5000001, receive, &in) == WNC_TIMEOUT);
        wnc_deinit(&carrier);
    }
    puts("future carrier kinds skipped; continuation, bounds and timeout retained");
    return 0;
}
