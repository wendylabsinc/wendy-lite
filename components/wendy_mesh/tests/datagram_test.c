#include "wendy_mesh_datagram.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct packet {
    size_t n;
    uint8_t bytes[WM_DG_MAX];
};
struct wire {
    struct packet q[128];
    unsigned count, sent;
    bool loss;
};
static int enqueue(void* ctx, const uint8_t* p, size_t n)
{
    struct wire* w = ctx;
    assert(n <= WM_DG_MAX);
    ++w->sent;
    if (w->loss && w->sent % 5 == 0)
        return -1;
    unsigned copies = w->loss && w->sent % 3 == 0 ? 2 : 1;
    while (copies--) {
        assert(w->count < 128);
        w->q[w->count].n = n;
        memcpy(w->q[w->count++].bytes, p, n);
    }
    return 0;
}
static void deliver(struct wire* from, struct wm_datagram* to, struct wire* reply)
{
    /* Reverse arrival order, including duplicates and delayed ACKs. */
    while (from->count) {
        struct packet p = from->q[--from->count];
        wm_datagram_receive(to, p.bytes, p.n, enqueue, reply);
    }
}
int main(void)
{
    struct wm_datagram a, b;
    struct wire ab = { .loss = true }, ba = { .loss = true };
    wm_datagram_init(&a, 123);
    wm_datagram_init(&b, 456);
    uint8_t input[16384], output[16384], reverse[16384];
    for (unsigned i = 0; i < sizeof input; ++i)
        input[i] = (uint8_t)(i * 71 + i / 17);
    size_t aw = 0, bw = 0, ar = 0, br = 0;
    int64_t now;
    for (now = 0; now < INT64_C(120000000) && (ar < sizeof input || br < sizeof input); now += 1000) {
        assert(!wm_datagram_tick(&a, now, enqueue, &ab));
        assert(!wm_datagram_tick(&b, now, enqueue, &ba));
        deliver(&ab, &b, &ba);
        deliver(&ba, &a, &ab);
        int n = wm_datagram_write(&a, input + aw, sizeof input - aw, now);
        if (n > 0)
            aw += n;
        else
            assert(n == 0 || n == -3);
        n = wm_datagram_write(&b, input + bw, sizeof input - bw, now);
        if (n > 0)
            bw += n;
        else
            assert(n == 0 || n == -3);
        /* Initially withhold reads to exercise receive-buffer backpressure. */
        if (now > 1000000) {
            size_t nread = sizeof input - ar;
            if (nread > 97)
                nread = 97;
            n = wm_datagram_read(&a, reverse + ar, nread);
            if (n > 0)
                ar += n;
            else
                assert(n == 0 || n == -2);
            nread = sizeof input - br;
            if (nread > 31)
                nread = 31;
            n = wm_datagram_read(&b, output + br, nread);
            if (n > 0)
                br += n;
            else
                assert(n == 0 || n == -2);
        }
    }
    assert(ar == sizeof input && br == sizeof input);
    assert(!memcmp(input, output, sizeof input) && !memcmp(input, reverse, sizeof input));
    /* Old epochs cannot inject data or acknowledge a new session. */
    struct wm_datagram fresh;
    wm_datagram_init(&fresh, 999);
    for (unsigned n = 0; n < WM_DG_HEADER; ++n)
        wm_datagram_receive(&fresh, input, n, enqueue, &ab);
    deliver(&ab, &fresh, &ba);
    assert(fresh.size == 0 && !fresh.connected);
    /* A permanently lost ACK closes the stream, rather than losing bytes. */
    ab.count = ba.count = 0;
    a.tx_size = 0;
    assert(wm_datagram_write(&a, input, 20, now) == 20);
    assert(wm_datagram_tick(&a, now + 5000000, enqueue, &ab) == -1);
    assert(wm_datagram_read(&a, output, 1) == -1);
    /* Full buffer: don't acknowledge data that has not been retained. */
    wm_datagram_init(&a, 111);
    wm_datagram_init(&b, 222);
    a.remote = b.local;
    b.remote = a.local;
    a.connected = b.connected = true;
    ab = (struct wire) { 0 };
    ba = (struct wire) { 0 };
    b.size = WM_DG_BUFFER;
    assert(wm_datagram_write(&a, input, 225, 0) == 225);
    assert(!wm_datagram_tick(&a, 0, enqueue, &ab));
    struct packet data = ab.q[0];
    deliver(&ab, &b, &ba);
    assert(ba.count == 0 && b.size == WM_DG_BUFFER && b.rx_seq == 1);
    assert(wm_datagram_read(&b, output, 225) == 225);
    wm_datagram_receive(&b, data.bytes, data.n, enqueue, &ba);
    assert(ba.count == 1 && b.size == WM_DG_BUFFER && b.rx_seq == 2);
    wm_datagram_receive(&b, data.bytes, data.n, enqueue, &ba);
    assert(ba.count == 2 && b.size == WM_DG_BUFFER && b.rx_seq == 2);
    /* A stale ACK, wrong destination and malformed oversized data do nothing. */
    ba.q[0].bytes[13] ^= 1;
    wm_datagram_receive(&a, ba.q[0].bytes, ba.q[0].n, enqueue, &ab);
    assert(a.tx_size == 225);
    data.bytes[5] ^= 1;
    wm_datagram_receive(&b, data.bytes, data.n, enqueue, &ba);
    wm_datagram_receive(&b, data.bytes, WM_DG_MAX + 1, enqueue, &ba);
    assert(b.rx_seq == 2 && ba.count == 2);
    puts("PASS ESP-NOW loss, duplicates, reorder, backpressure, epochs and timeout");
}
