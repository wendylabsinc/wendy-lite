#include "wendy_net_carrier.h"
#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct port
{
    struct port *peer;
    uint8_t ring[31];
    size_t head, size;
    const void *retry;
    size_t retry_size;
    unsigned reads, writes, blocks;
    bool eof;
};
struct endpoint
{
    struct wnc_carrier carrier;
    struct port port;
    uint8_t buffer[2052];
    unsigned owner, sent, received;
};
static ssize_t read_bytes(void *ctx, void *data, size_t size)
{
    struct port *p = ctx;
    p->reads++;
    if (p->eof)
        return 0;
    if (!p->size)
        return -2;
    if (p->reads % 11 == 0)
    {
        p->blocks++;
        return -3;
    }
    if (size > 17)
        size = 17;
    if (size > p->size)
        size = p->size;
    for (size_t i = 0; i < size; i++)
        ((uint8_t *)data)[i] = p->ring[(p->head + i) % sizeof p->ring];
    p->head = (p->head + size) % sizeof p->ring;
    p->size -= size;
    return (ssize_t)size;
}
static ssize_t write_bytes(void *ctx, const void *data, size_t size)
{
    struct port *p = ctx, *q = p->peer;
    p->writes++;
    if (p->retry)
    {
        assert(data == p->retry && size == p->retry_size);
    }
    if (q->size == sizeof q->ring || p->writes % 7 == 0 || p->writes % 13 == 0)
    {
        p->retry = data;
        p->retry_size = size;
        p->blocks++;
        return p->writes % 13 == 0 ? -2 : -3;
    }
    p->retry = NULL;
    if (size > 23)
        size = 23;
    if (size > sizeof q->ring - q->size)
        size = sizeof q->ring - q->size;
    for (size_t i = 0; i < size; i++)
        q->ring[(q->head + q->size + i) % sizeof q->ring] =
            ((const uint8_t *)data)[i];
    q->size += size;
    return (ssize_t)size;
}
static void init(struct endpoint *e, unsigned owner)
{
    memset(e, 0, sizeof *e);
    e->owner = owner;
    struct wnc_io io = {
        .context = &e->port, .read = read_bytes, .write = write_bytes};
    assert(
        !wnc_init(&e->carrier, &io, e->buffer, sizeof e->buffer, 8192, 65536));
}
static void fill(uint8_t *bytes, size_t size, unsigned seq, unsigned owner)
{
    wn_put32(bytes, seq);
    for (size_t i = 4; i < size; i++)
        bytes[i] = (uint8_t)((seq * 7 + i + owner) % 251);
}
static int receive(void *ctx, const void *data, size_t size, bool control)
{
    struct endpoint *e = ctx;
    assert(size == 1024 && control == (bool)(e->received % 2));
    uint8_t expected[1024];
    fill(expected, sizeof expected, e->received, 1 - e->owner);
    assert(!memcmp(expected, data, size));
    e->received++;
    return 0;
}
static int unexpected(void *ctx, const void *data, size_t size, bool control)
{
    (void)ctx;
    (void)data;
    (void)size;
    (void)control;
    assert(!"invalid frame delivered");
    return 0;
}
static int large_receive(void *ctx, const void *data, size_t size, bool control)
{
    unsigned *count = ctx;
    const uint8_t *bytes = data;
    assert(control && size == 60000 && wn_get32(bytes) == 42);
    for (size_t i = 4; i < size; i++)
        assert(bytes[i] == (uint8_t)((42 * 7 + i) % 251));
    (*count)++;
    return 0;
}
struct packet_pressure
{
    struct wn_assembler assembler;
    uint8_t expected[WN_MTU];
    unsigned controls, packets;
};
static int pressure_receive(void *ctx, const void *data, size_t size,
                            bool control)
{
    struct packet_pressure *p = ctx;
    if (control)
    {
        assert(size == 600 && !p->controls++);
        for (size_t i = 0; i < size; i++)
            assert(!((const uint8_t *)data)[i]);
    }
    else
    {
        int assembled = wn_assemble(&p->assembler, data, size, 0);
        assert(assembled >= 0);
        if (assembled)
        {
            assert(assembled == WN_MTU && !p->packets++);
            assert(!memcmp(p->assembler.packet, p->expected, WN_MTU));
        }
    }
    return 0;
}
int main(void)
{
    struct endpoint a, b;
    init(&a, 0);
    init(&b, 1);
    a.port.peer = &b.port;
    b.port.peer = &a.port;
    unsigned rounds = 0;
    while (a.received < 128 || b.received < 128)
    {
        struct endpoint *ends[] = {&a, &b};
        for (unsigned i = 0; i < 2; i++)
        {
            struct endpoint *e = ends[i];
            if (e->sent < 128 && e->carrier.queued < 2048)
            {
                uint8_t data[1024];
                fill(data, sizeof data, e->sent, e->owner);
                assert(
                    !wnc_enqueue(&e->carrier, data, sizeof data, e->sent % 2));
                e->sent++;
            }
            assert(wnc_pump(&e->carrier, (int64_t)rounds * 10, receive, e) >=
                   0);
            assert(e->carrier.queued <= 8192);
        }
        assert(++rounds < 200000);
    }
    assert(!a.carrier.queued && !b.carrier.queued && a.port.blocks &&
           b.port.blocks);
    printf("duplex 128KiB each direction,31byte windows: rounds=%u idle=%zu\n",
           rounds, sizeof a.carrier);
    wnc_deinit(&a.carrier);
    wnc_deinit(&b.carrier);
    /* The first fragment fits, the second exceeds the queue budget. Keep
     * the prior control frame, roll back every new fragment, then retry the
     * complete packet after pressure clears without reopening the stream. */
    init(&a, 0);
    init(&b, 1);
    a.port.peer = &b.port;
    b.port.peer = &a.port;
    a.carrier.limit = 2048;
    struct packet_pressure pressure = {0};
    fill(pressure.expected, WN_MTU, 7, 0);
    pressure.expected[0] = 0x60;
    wn_put16(pressure.expected + 4, WN_MTU - 40);
    uint8_t control[600] = {0};
    assert(!wnc_enqueue(&a.carrier, control, sizeof control, true));
    size_t before = a.carrier.queued;
    assert(wnc_enqueue_packet(&a.carrier, pressure.expected, WN_MTU, 1) ==
           WNC_LIMIT);
    assert(a.carrier.queued == before && a.carrier.head == a.carrier.tail);
    for (rounds = 0; !pressure.controls; rounds++)
    {
        assert(wnc_pump(&a.carrier, rounds * 10, unexpected, NULL) >= 0);
        assert(wnc_pump(&b.carrier, rounds * 10, pressure_receive, &pressure) >=
               0);
        assert(rounds < 200000);
    }
    assert(!a.carrier.queued && !b.carrier.header_have && !pressure.packets);
    assert(!wnc_enqueue_packet(&a.carrier, pressure.expected, WN_MTU, 2));
    for (; !pressure.packets; rounds++)
    {
        assert(wnc_pump(&a.carrier, rounds * 10, unexpected, NULL) >= 0);
        assert(wnc_pump(&b.carrier, rounds * 10, pressure_receive, &pressure) >=
               0);
        assert(rounds < 200000);
    }
    assert(!a.carrier.queued);
    wnc_deinit(&a.carrier);
    wnc_deinit(&b.carrier);

    init(&a, 0);
    init(&b, 1);
    a.port.peer = &b.port;
    b.port.peer = &a.port;
    /* Reject the control length before attempting a large allocation. */
    a.port.ring[0] = 1;
    wn_put32(a.port.ring + 1, 65541);
    a.port.size = 5;
    assert(wnc_pump(&a.carrier, 0, unexpected, NULL) == WNC_INVALID &&
           !a.carrier.body);
    wnc_deinit(&a.carrier);
    init(&a, 0);
    a.port.peer = &b.port;
    a.port.ring[0] = 1;
    wn_put32(a.port.ring + 1, 5);
    wn_put32(a.port.ring + 5, 2);
    a.port.ring[9] = 'x';
    a.port.size = 10;
    assert(wnc_pump(&a.carrier, 0, unexpected, NULL) == 1);
    assert(wnc_pump(&a.carrier, 1, unexpected, NULL) == WNC_INVALID);
    wnc_deinit(&a.carrier);
    init(&a, 0);
    a.port.peer = &b.port;
    a.port.ring[0] = 1;
    a.port.size = 1;
    assert(wnc_pump(&a.carrier, 0, unexpected, NULL) == 1);
    assert(wnc_pump(&a.carrier, 5000000, unexpected, NULL) == WNC_TIMEOUT);
    wnc_deinit(&a.carrier);
    init(&a, 0);
    a.port.peer = &b.port;
    uint8_t block[1024] = {0};
    unsigned queued = 0;
    while (!wnc_enqueue(&a.carrier, block, sizeof block, false))
        queued++;
    assert(queued && a.carrier.queued <= 8192);
    b.port.size = sizeof b.port.ring;
    assert(!wnc_pump(&a.carrier, 0, unexpected, NULL));
    assert(wnc_pump(&a.carrier, 5000000, unexpected, NULL) == WNC_TIMEOUT);
    wnc_deinit(&a.carrier);
    wnc_deinit(&b.carrier);

    init(&a, 0);
    init(&b, 1);
    a.port.peer = &b.port;
    b.port.peer = &a.port;
    a.carrier.limit = 65536;
    static uint8_t large[60000];
    fill(large, sizeof large, 42, 0);
    assert(!wnc_enqueue(&a.carrier, large, sizeof large, true));
    unsigned delivered = 0;
    for (rounds = 0; !delivered; rounds++)
    {
        assert(wnc_pump(&a.carrier, (int64_t)rounds * 10, unexpected, NULL) >=
               0);
        assert(wnc_pump(&b.carrier, (int64_t)rounds * 10, large_receive,
                        &delivered) >= 0);
        assert(rounds < 200000);
    }
    assert(!b.carrier.body && !a.carrier.queued);
    b.port.eof = true;
    assert(wnc_pump(&b.carrier, rounds * 10, unexpected, NULL) == WNC_CLOSED);
    wnc_deinit(&a.carrier);
    wnc_deinit(&b.carrier);
    puts(
        "sparse framing, partial retry, bounds, expiry and large receive pass");
    return 0;
}
