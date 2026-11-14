/* Two stream endpoints against each other through a simulated radio that
 * loses, duplicates, delays and reorders datagrams and sometimes refuses to
 * send. Simulated time only; deterministic. */
#include "espnow_stream.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WINDOW 8
static uint32_t seed = 0x1234567;
static uint32_t rng(void)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}
static unsigned allocations;
static void *test_alloc(size_t bytes)
{
    allocations++;
    return malloc(bytes);
}
static void test_free(void *p)
{
    assert(p && allocations);
    allocations--;
    free(p);
}

struct node {
    struct wnes *m;
    uint8_t mac[6];
    bool cut; /* Nothing this node sends arrives. */
};
static struct node nodes[2] = {{.mac = {2, 0, 0, 0, 0, 1}}, {.mac = {2, 0, 0, 0, 0, 2}}};
static struct {
    bool used;
    int64_t at;
    unsigned to;
    size_t size;
    uint8_t bytes[WNES_FRAME_MAX];
} flight[256];
static int64_t now;
static unsigned loss_pct, dup_pct, busy_pct, frames;
static int64_t delay_max;

static int radio_send(void *context, const uint8_t mac[6], const void *frame, size_t size)
{
    struct node *from = context;
    unsigned to = from == &nodes[0];
    assert(size >= WNES_HEADER && size <= WNES_FRAME_MAX);
    if (rng() % 100 < busy_pct)
        return 1;
    frames++;
    if (from->cut || memcmp(mac, nodes[to].mac, 6) || rng() % 100 < loss_pct)
        return 0;
    for (unsigned copies = 1 + (rng() % 100 < dup_pct); copies; copies--)
        for (unsigned i = 0; i < 256; i++)
            if (!flight[i].used) {
                flight[i].used = true;
                flight[i].at = now + (delay_max ? (int64_t)(rng() % (delay_max + 1)) : 0);
                flight[i].to = to;
                flight[i].size = size;
                memcpy(flight[i].bytes, frame, size);
                break;
            }
    return 0;
}
/* One simulated step: deliver what is due, then run both endpoints' timers. */
static void step(int64_t us)
{
    now += us;
    for (unsigned i = 0; i < 256; i++)
        if (flight[i].used && flight[i].at <= now) {
            flight[i].used = false;
            wnes_input(nodes[flight[i].to].m, nodes[!flight[i].to].mac, flight[i].bytes,
                       flight[i].size, now);
        }
    for (unsigned n = 0; n < 2; n++) {
        unsigned peak;
        (void)wnes_tick(nodes[n].m, now);
        assert(wnes_segments(nodes[n].m, &peak) <= peak);
    }
}
/* A wait that must end: a stuck stream fails the test instead of hanging it. */
static void wait_step(int64_t start)
{
    assert(now - start < 60000000);
    step(1000);
}
static void radio(unsigned loss, unsigned dup, unsigned busy, int64_t delay)
{
    loss_pct = loss;
    dup_pct = dup;
    busy_pct = busy;
    delay_max = delay;
    nodes[0].cut = nodes[1].cut = false;
    memset(flight, 0, sizeof flight);
}
static void open_nodes(uint16_t frame0, uint8_t window0, uint16_t frame1, uint8_t window1)
{
    for (unsigned n = 0; n < 2; n++) {
        struct wnes_config k;
        wnes_defaults(&k);
        k.frame_bytes = n ? frame1 : frame0;
        k.window = n ? window1 : window0;
        k.alloc = test_alloc;
        k.free = test_free;
        k.send = radio_send;
        k.random = rng;
        k.context = &nodes[n];
        nodes[n].m = wnes_open(&k, 4);
        assert(nodes[n].m);
    }
    wnes_accepting(nodes[1].m, 1 << WNES_MESH);
}
static void close_nodes(void)
{
    wnes_close(nodes[0].m);
    wnes_close(nodes[1].m);
    assert(!allocations);
}
static void establish(struct wnes_conn **a, struct wnes_conn **b)
{
    uint8_t mac[6], service = 9;
    *a = wnes_connect(nodes[0].m, nodes[1].mac, WNES_MESH, now);
    assert(*a);
    *b = NULL;
    for (int64_t start = now; !*b; step(500)) {
        assert(now - start < 5000000);
        *b = wnes_accept(nodes[1].m, mac, &service);
    }
    assert(!memcmp(mac, nodes[0].mac, 6) && service == WNES_MESH);
    assert(!wnes_accept(nodes[1].m, mac, &service));
}
static uint8_t pattern(unsigned stream, size_t offset)
{
    return (uint8_t)((offset * 2654435761u >> 11) ^ (offset >> 3) ^ stream);
}
struct flow {
    struct wnes_conn *from, *to;
    unsigned id;
    size_t total, written, read;
    int64_t stall_until;
};
/* Random-sized writes and reads; the reader sometimes stops for a while so
 * the window closes and has to reopen. Checks every byte and its order. */
static void pump(struct flow *f)
{
    uint8_t buffer[900];
    size_t n = 1 + rng() % 700;
    if (n > f->total - f->written)
        n = f->total - f->written;
    for (size_t i = 0; i < n; i++)
        buffer[i] = pattern(f->id, f->written + i);
    if (n) {
        ssize_t w = wnes_write(f->from, buffer, n);
        assert(w == -3 || (w > 0 && (size_t)w <= n));
        if (w > 0)
            f->written += (size_t)w;
    }
    if (now < f->stall_until)
        return;
    if (rng() % 2000 == 0)
        f->stall_until = now + 300000;
    ssize_t r = wnes_read(f->to, buffer, 1 + rng() % sizeof buffer);
    assert(r == -2 || r > 0);
    for (ssize_t i = 0; i < r; i++)
        assert(buffer[i] == pattern(f->id, f->read + (size_t)i));
    if (r > 0)
        f->read += (size_t)r;
}
static void transfer(size_t forward, size_t backward, unsigned bound)
{
    struct wnes_conn *a, *b;
    establish(&a, &b);
    struct flow ab = {a, b, 1, forward, 0, 0, 0}, ba = {b, a, 2, backward, 0, 0, 0};
    int64_t start = now;
    frames = 0;
    while (ab.read < forward || ba.read < backward) {
        pump(&ab);
        pump(&ba);
        step(500);
        /* Bounded windows: never more than send+receive per stream. */
        assert(wnes_segments(nodes[0].m, NULL) <= bound && wnes_segments(nodes[1].m, NULL) <= bound);
        assert(now - start < INT64_C(900000000));
    }
    printf("  %zu+%zu bytes in %lld ms simulated, %u frames\n", forward, backward,
           (long long)((now - start) / 1000), frames);
    uint8_t byte;
    while (!wnes_drained(a) || !wnes_drained(b))
        step(500);
    /* Clean close: the peer reads end-of-stream, both sides free themselves. */
    assert(wnes_write(a, "tail", 4) == 4);
    wnes_release(a, now);
    char tail[8];
    ssize_t r;
    for (start = now; (r = wnes_read(b, tail, sizeof tail)) == -2; step(500))
        assert(now - start < 5000000);
    assert(r == 4 && !memcmp(tail, "tail", 4));
    for (start = now; (r = wnes_read(b, &byte, 1)) == -2; step(500))
        assert(now - start < 5000000);
    assert(r == 0);
    wnes_release(b, now);
    for (start = now; wnes_uses(nodes[0].m, nodes[1].mac) || wnes_uses(nodes[1].m, nodes[0].mac);
         step(500))
        assert(now - start < 5000000);
    unsigned peak0, peak1;
    assert(!wnes_segments(nodes[0].m, &peak0) && !wnes_segments(nodes[1].m, &peak1));
    assert(peak0 <= bound && peak1 <= bound);
    assert(allocations == 4); /* Two managers and their frame buffers only. */
}

static void test_transfer(void)
{
    puts("clean radio");
    open_nodes(1024, WINDOW, 1024, WINDOW);
    radio(0, 0, 0, 0);
    transfer(1 << 20, 1 << 18, 2 * WINDOW);
    puts("lossy, duplicating, reordering, delaying, sometimes busy radio");
    radio(8, 3, 2, 15000);
    transfer(3 << 20, 1 << 20, 2 * WINDOW);
    close_nodes();
    puts("different frame sizes and windows at each end");
    open_nodes(1470, 16, 256, 3);
    radio(5, 2, 1, 8000);
    transfer(1 << 18, 1 << 18, 2 * 16);
    close_nodes();
}
/* The peer vanishes while data is unacknowledged: retransmission backs off
 * and then gives up. */
static void test_dead_peer_with_data(void)
{
    struct wnes_conn *a, *b;
    open_nodes(1024, WINDOW, 1024, WINDOW);
    radio(0, 0, 0, 1000);
    establish(&a, &b);
    nodes[0].cut = nodes[1].cut = true;
    assert(wnes_write(a, "x", 1) == 1);
    int64_t start = now;
    uint8_t byte;
    frames = 0;
    while (wnes_read(a, &byte, 1) == -2)
        wait_step(start);
    assert(wnes_read(a, &byte, 1) == -1 && wnes_write(a, "x", 1) == -1);
    assert(now - start > 3000000 && now - start < 10000000);
    assert(frames >= 5 && frames <= 8); /* Backoff, not a flood. */
    /* The silent side notices by its idle timeout. */
    while (wnes_read(b, &byte, 1) == -2)
        wait_step(start);
    assert(wnes_read(b, &byte, 1) == -1 && now - start > 29000000 && now - start < 31000000);
    wnes_release(a, now);
    wnes_release(b, now);
    step(1000);
    assert(allocations == 4);
    close_nodes();
}
static void test_dead_peer_idle(void)
{
    struct wnes_conn *a, *b;
    open_nodes(1024, WINDOW, 1024, WINDOW);
    radio(0, 0, 0, 1000);
    establish(&a, &b);
    for (int i = 0; i < 100; i++)
        step(1000);
    nodes[0].cut = nodes[1].cut = true;
    int64_t start = now;
    uint8_t byte;
    frames = 0;
    while (wnes_read(a, &byte, 1) == -2)
        wait_step(start);
    assert(now - start > 29000000 && now - start < 31000000);
    assert(!frames); /* An idle stream sends nothing at all, not even keepalives. */
    wnes_release(a, now);
    wnes_release(b, now);
    close_nodes();
}
static void test_connect(void)
{
    uint8_t byte, mac[6];
    open_nodes(1024, WINDOW, 1024, WINDOW);
    radio(0, 0, 0, 1000);
    /* Nobody there. */
    nodes[0].cut = true;
    struct wnes_conn *a = wnes_connect(nodes[0].m, nodes[1].mac, WNES_MESH, now);
    int64_t start = now;
    frames = 0;
    assert(a && wnes_write(a, "x", 1) == -3 && wnes_read(a, &byte, 1) == -2);
    while (wnes_write(a, "x", 1) == -3)
        wait_step(start);
    assert(wnes_write(a, "x", 1) == -1 && now - start >= 5000000 && now - start < 5100000);
    assert(frames >= 4 && frames <= 8);
    wnes_release(a, now);
    /* Refused: answered at once instead of timing out. */
    nodes[0].cut = false;
    wnes_accepting(nodes[1].m, 0);
    a = wnes_connect(nodes[0].m, nodes[1].mac, WNES_MESH, now);
    start = now;
    while (wnes_write(a, "x", 1) == -3)
        wait_step(start);
    assert(wnes_write(a, "x", 1) == -1 && now - start < 100000);
    wnes_release(a, now);
    assert(!wnes_accept(nodes[1].m, mac, &byte));
    /* Each kind of stream has its own admission: a node can relay signed
     * time while it has no room for another mesh link. */
    wnes_accepting(nodes[1].m, 1 << WNES_TIME);
    a = wnes_connect(nodes[0].m, nodes[1].mac, WNES_MESH, now);
    for (start = now; wnes_write(a, "x", 1) == -3;)
        wait_step(start);
    assert(wnes_write(a, "x", 1) == -1 && now - start < 100000);
    wnes_release(a, now);
    a = wnes_connect(nodes[0].m, nodes[1].mac, WNES_TIME, now);
    struct wnes_conn *b = NULL;
    for (start = now; !b; wait_step(start))
        b = wnes_accept(nodes[1].m, mac, &byte);
    assert(byte == WNES_TIME && wnes_write(a, "t", 1) == 1);
    wnes_release(a, now);
    wnes_release(b, now);
    for (int i = 0; i < 3000; i++)
        step(1000);
    /* A flood of connection requests cannot take more than the backlog. */
    wnes_accepting(nodes[1].m, 1 << WNES_MESH);
    for (unsigned i = 0; i < 200; i++) {
        uint8_t syn[WNES_HEADER] = {'W', 'N', 'E', 'N', WNES_VERSION, WNES_SYN, 0, WINDOW,
                                    0,   0,   0,   0,   1,            2,        3, (uint8_t)i};
        uint8_t from[6] = {2, 9, 9, 9, (uint8_t)(i >> 8), (uint8_t)i};
        wnes_input(nodes[1].m, from, syn, sizeof syn, now);
    }
    assert(allocations == 4 + 2 && !wnes_segments(nodes[1].m, NULL));
    for (int i = 0; i < 6000; i++)
        step(1000);
    assert(allocations == 4); /* Unconfirmed requests expire by themselves. */
    close_nodes();
}
/* The peer restarted and forgot the stream: its reset ends ours at once. */
static void test_restart(void)
{
    struct wnes_conn *a, *b;
    uint8_t byte;
    open_nodes(1024, WINDOW, 1024, WINDOW);
    radio(0, 0, 0, 1000);
    establish(&a, &b);
    wnes_close(nodes[1].m);
    struct wnes *old = nodes[0].m;
    open_nodes(1024, WINDOW, 1024, WINDOW);
    wnes_close(nodes[0].m);
    nodes[0].m = old;
    assert(wnes_write(a, "x", 1) == 1);
    int64_t start = now;
    while (wnes_read(a, &byte, 1) == -2)
        wait_step(start);
    assert(wnes_read(a, &byte, 1) == -1 && now - start < 100000);
    wnes_release(a, now);
    close_nodes();
}
/* Arbitrary and near-valid frames neither crash nor corrupt a live stream. */
static void test_garbage(void)
{
    struct wnes_conn *a, *b;
    open_nodes(1024, WINDOW, 1024, WINDOW);
    radio(0, 0, 0, 1000);
    establish(&a, &b);
    uint8_t frame[WNES_FRAME_MAX + 8];
    for (unsigned i = 0; i < 20000; i++) {
        size_t size = rng() % sizeof frame;
        for (size_t at = 0; at < size; at++)
            frame[at] = (uint8_t)rng();
        if (i % 2 && size >= WNES_HEADER) {
            memcpy(frame, WNES_MAGIC, 4);
            frame[4] = WNES_VERSION;
            frame[5] = (uint8_t)(rng() % 9);
        }
        /* From a stranger, and from the peer's own address with wrong ids. */
        uint8_t stranger[6] = {2, 7, 7, 7, 7, (uint8_t)rng()};
        wnes_input(nodes[1].m, i % 3 ? nodes[0].mac : stranger, frame, size, now);
        if (i % 64 == 0)
            step(1000);
    }
    for (int i = 0; i < 6000; i++)
        step(1000);
    struct flow ab = {a, b, 3, 50000, 0, 0, 0};
    for (int64_t start = now; ab.read < ab.total; step(500)) {
        assert(now - start < 60000000);
        pump(&ab);
    }
    wnes_release(a, now);
    wnes_release(b, now);
    close_nodes();
}
static void test_advert(void)
{
    uint8_t tenant[16], device[16], mesh[8], other[16] = {9}, out[WNES_ADVERT_SIZE], got[16], flags;
    for (unsigned i = 0; i < 16; i++) {
        tenant[i] = (uint8_t)(i + 1);
        device[i] = (uint8_t)(0xa0 + i);
    }
    memset(mesh, 0x5a, sizeof mesh);
    assert(wnes_advert_write(tenant, device, mesh, WNES_ACCEPTING, out) == WNES_ADVERT_SIZE);
    assert(!memcmp(out, WNES_MAGIC, 4) && out[5] == WNES_ADVERT);
    assert(wnes_advert_read(tenant, mesh, out, sizeof out, got, &flags));
    assert(!memcmp(got, device, 16) && flags == WNES_ACCEPTING);
    assert(!wnes_advert_read(other, mesh, out, sizeof out, got, &flags));
    assert(!wnes_advert_read(tenant, other, out, sizeof out, got, &flags));
    assert(!wnes_advert_read(tenant, mesh, out, sizeof out - 1, got, &flags));
    out[5] = WNES_SYN;
    assert(!wnes_advert_read(tenant, mesh, out, sizeof out, got, &flags));
    out[5] = WNES_ADVERT;
    out[4] = WNES_VERSION + 1;
    assert(!wnes_advert_read(tenant, mesh, out, sizeof out, got, &flags));
}
int main(void)
{
    struct wnes_config bad = {0};
    wnes_defaults(&bad);
    assert(!wnes_open(&bad, 4)); /* No callbacks. */
    test_advert();
    test_transfer();
    test_dead_peer_with_data();
    test_dead_peer_idle();
    test_connect();
    test_restart();
    test_garbage();
    puts("espnow stream: ok");
    return 0;
}
