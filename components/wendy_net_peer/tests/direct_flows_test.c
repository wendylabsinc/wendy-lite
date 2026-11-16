#include "wendy_net_direct_flows.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#define SLOTS 4
struct peer {
    struct wn_direct_flows owner;
    struct wn_direct_flow flows[2 * SLOTS];
    struct wn_direct_recovery_record expected[2 * SLOTS];
    uint32_t retired[2 * SLOTS];
    struct wn_direct_pool tx, rx;
    struct wn_direct_slot tx_chunks[32], rx_chunks[32];
    struct wn_direct_packet packets[1];
    uint8_t packet_storage[3 * 1024];
    unsigned opens;
    int endpoint;
    uint16_t refuse;
};
static int64_t now;
static void init_config(struct peer *p, uint8_t role, bool udp, uint16_t maximum)
{
    memset(p, 0, sizeof *p);
    p->endpoint = -1;
    assert(!wn_direct_pool_init_dynamic(&p->tx, p->tx_chunks, 32, malloc, free));
    assert(!wn_direct_pool_init_dynamic(&p->rx, p->rx_chunks, 32, malloc, free));
    assert(!wn_direct_flows_init(&p->owner, role, SLOTS, p->flows, p->expected,
                                 p->retired, &p->tx, &p->rx, 4096, 1024));
    if (udp) {
        assert(!wn_direct_packet_init(p->packets, p->packet_storage, sizeof p->packet_storage));
        assert(!wn_direct_flows_enable_datagrams(&p->owner, p->packets, 1));
    }
    assert(!wn_direct_flows_set_datagram_limit(&p->owner, maximum));
    assert(!wn_direct_flows_bind(&p->owner, 1));
}
static void init_mode(struct peer *p, uint8_t role, bool udp)
{
    init_config(p, role, udp, udp ? 1024 : 0);
}
static void init(struct peer *p, uint8_t role)
{
    init_mode(p, role, false);
}
static void dispose(struct peer *p)
{
    wn_direct_flows_close(&p->owner);
    if (p->endpoint >= 0)
        close(p->endpoint);
    assert(p->tx.available == 32 && p->rx.available == 32);
}
static bool transfer(struct peer *from, struct peer *to, uint8_t *drop)
{
    struct wn_direct_frame frame, again;
    int result = wn_direct_flows_prepare(&from->owner, now += 100000, &frame);
    assert(result >= 0);
    if (!result)
        return false;
    if (from->owner.upper_control)
        assert(frame.kind != WN_DIRECT_DATA && frame.kind != WN_DIRECT_STATE &&
               frame.kind != WN_DIRECT_FIN && frame.kind != WN_DIRECT_DATAGRAM);
    assert(wn_direct_flows_prepare(&from->owner, now, &again) == 1 && again.kind == frame.kind &&
           again.flow_id == frame.flow_id);
    uint8_t bytes[WN_DIRECT_MAX_FRAME];
    size_t count;
    assert(!wn_direct_frame_encode(&frame, bytes, sizeof bytes, &count));
    assert(!wn_direct_flows_accepted(&from->owner));
    if (drop && *drop == frame.kind) {
        *drop = 0;
        return true;
    }
    assert(!wn_direct_frame_decode(bytes, count, &frame));
    uint32_t fresh = 0;
    int err = wn_direct_flows_receive(&to->owner, &frame, now, &fresh);
    if (err)
        fprintf(stderr, "receive kind=%u flow=%u error=%d\n", frame.kind, frame.flow_id, err);
    assert(!err);
    if (fresh) {
        to->opens++;
        assert(!wn_direct_flows_complete(&to->owner, fresh, to->refuse));
        if (!to->refuse) {
            int fd[2];
            struct wn_direct_flow *flow = wn_direct_flows_find(&to->owner, fresh);
            assert(!socketpair(AF_UNIX, flow->packet ? SOCK_DGRAM : SOCK_STREAM, 0, fd));
            assert(!wn_direct_flows_socket(&to->owner, fresh, fd[0]));
            assert(to->endpoint < 0);
            to->endpoint = fd[1];
        }
    }
    return true;
}
static void pump(struct peer *a, struct peer *b, uint8_t *drop_a, uint8_t *drop_b)
{
    for (unsigned i = 0; i < 1000; i++) {
        int pa = wn_direct_flows_poll(&a->owner), pb = wn_direct_flows_poll(&b->owner);
        assert(pa >= 0 && pb >= 0);
        bool sa = transfer(a, b, drop_a), sb = transfer(b, a, drop_b);
        if (!pa && !pb && !sa && !sb)
            return;
    }
    assert(!"pump failed to quiesce");
}
static uint32_t begin(struct peer *p)
{
    uint32_t id;
    assert(!wn_direct_flows_begin(
        &p->owner, (struct wn_direct_request){.service = WN_DIRECT_TCP, .port = 28080}, now, &id));
    return id;
}
static int connect_app(struct peer *a, uint32_t id)
{
    int fd[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
    assert(!wn_direct_flows_socket(&a->owner, id, fd[0]));
    return fd[1];
}
static void recover(struct peer *a, struct peer *b)
{
    wn_direct_flows_suspend(&a->owner);
    wn_direct_flows_suspend(&b->owner);
    struct wn_direct_recovery_record ar[2 * SLOTS], br[2 * SLOTS], scratch[2 * SLOTS];
    struct wn_direct_recovery_view av, bv;
    struct wn_direct_recovery_step plan[4 * SLOTS];
    assert(!wn_direct_flows_snapshot(&a->owner, ar, 2 * SLOTS, &av));
    assert(!wn_direct_flows_snapshot(&b->owner, br, 2 * SLOTS, &bv));
    assert(!wn_direct_flows_recover(&a->owner, &bv, now, scratch, 2 * SLOTS, plan, 4 * SLOTS));
    assert(!wn_direct_flows_recover(&b->owner, &av, now, scratch, 2 * SLOTS, plan, 4 * SLOTS));
    assert(!wn_direct_flows_bind(&a->owner, 2));
    assert(!wn_direct_flows_bind(&b->owner, 2));
}
// An idle lane must not erase the attachment ID for a later flow's control frame.
static void loss(uint8_t kind)
{
    struct peer a, b;
    init(&a, 0);
    init(&b, 1);
    pump(&a, &b, NULL, NULL);
    uint32_t id = begin(&a);
    pump(&a, &b, NULL, NULL);
    int app = connect_app(&a, id);
    assert(b.opens == 1);
    assert(send(app, "before", 6, 0) == 6);
    uint8_t drop = kind;
    pump(&a, &b, kind == WN_DIRECT_DATA ? &drop : NULL, kind == WN_DIRECT_STATE ? &drop : NULL);
    assert(!drop);
    char got[100];
    if (kind == WN_DIRECT_STATE)
        assert(recv(b.endpoint, got, 6, MSG_DONTWAIT) == 6 && !memcmp(got, "before", 6));
    wn_direct_flows_suspend(&a.owner);
    wn_direct_flows_suspend(&b.owner);
    assert(send(app, "after", 5, 0) == 5);
    assert(wn_direct_flows_poll(&a.owner) > 0);
    recover(&a, &b);
    pump(&a, &b, NULL, NULL);
    const char *want = kind == WN_DIRECT_DATA ? "beforeafter" : "after";
    size_t n = strlen(want);
    assert(recv(b.endpoint, got, sizeof got, MSG_DONTWAIT) == (ssize_t)n && !memcmp(got, want, n));
    assert(b.opens == 1);
    assert(send(b.endpoint, "response", 8, 0) == 8);
    pump(&a, &b, NULL, NULL);
    assert(recv(app, got, sizeof got, MSG_DONTWAIT) == 8 && !memcmp(got, "response", 8));
    assert(!shutdown(app, SHUT_WR));
    pump(&a, &b, NULL, NULL);
    assert(recv(b.endpoint, got, sizeof got, MSG_DONTWAIT) == 0);
    assert(!shutdown(b.endpoint, SHUT_WR));
    pump(&a, &b, NULL, NULL);
    assert(recv(app, got, sizeof got, MSG_DONTWAIT) == 0);
    assert(wn_direct_flows_quiescent(&a.owner) && wn_direct_flows_quiescent(&b.owner));
    close(app);
    dispose(&a);
    dispose(&b);
}
static void early_fin(void)
{
    struct peer a, b;
    init(&a, 0);
    init(&b, 1);
    pump(&a, &b, NULL, NULL);
    uint32_t id = begin(&a);
    pump(&a, &b, NULL, NULL);
    struct wn_direct_flow *f = wn_direct_flows_find(&a.owner, id);
    assert(f);
    uint8_t payload[3150], got[3150];
    memset(payload, 0x6b, sizeof payload);
    assert(!wn_direct_send_accept(&f->sender, payload, sizeof payload, 4096));
    wn_direct_send_finish(&f->sender);
    pump(&a, &b, NULL, NULL);
    assert(recv(b.endpoint, got, sizeof got, MSG_DONTWAIT) == sizeof got &&
           !memcmp(got, payload, sizeof got));
    assert(recv(b.endpoint, got, 1, MSG_DONTWAIT) == 0);
    dispose(&a);
    dispose(&b);
}
struct upper_test {
    int fd, closed, reads;
    bool block;
    size_t retry_size;
};
static int upper_read(void *arg, uint8_t *p, size_t n)
{
    struct upper_test *u = arg;
    u->reads++;
    if (n > 5)
        n = 5;
    ssize_t got = recv(u->fd, p, n, MSG_DONTWAIT);
    return got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? -2 : (int)got;
}
static bool upper_pending(void *arg)
{
    struct upper_test *u = arg;
    uint8_t byte;
    ssize_t n = recv(u->fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    return n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK);
}
static int upper_write(void *arg, const uint8_t *p, size_t n)
{
    struct upper_test *u = arg;
    if (u->block) {
        u->block = false;
        u->retry_size = n;
        return -2;
    }
    if (u->retry_size) {
        assert(n == u->retry_size);
        u->retry_size = 0;
    }
    if (n > 3)
        n = 3;
    ssize_t got = send(u->fd, p, n, 0);
    return got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? -3 : (int)got;
}
static int upper_shutdown(void *arg)
{
    struct upper_test *u = arg;
    return shutdown(u->fd, SHUT_WR);
}
static void upper_close(void *arg)
{
    struct upper_test *u = arg;
    assert(!u->closed++);
    close(u->fd);
    u->fd = -1;
}
/* Reconciliation may acknowledge data still waiting for the local app. */
static void promoted(void)
{
    struct peer a, b;
    init(&a, 0);
    init(&b, 1);
    pump(&a, &b, NULL, NULL);
    uint32_t id = begin(&a);
    pump(&a, &b, NULL, NULL);
    int app = connect_app(&a, id);
    assert(send(app, "prefix", 6, 0) == 6);
    uint8_t drop = WN_DIRECT_DATA;
    pump(&a, &b, &drop, NULL);
    assert(!drop);
    recover(&a, &b);
    wn_direct_flows_suspend(&a.owner);
    wn_direct_flows_suspend(&b.owner);
    assert(!wn_direct_flows_bind_promoted(&a.owner, 3));
    assert(!wn_direct_flows_bind_promoted(&b.owner, 3));
    /* Release direct-only receive grants before allocating raw TLS, preserving
     * the unacknowledged prefix for the eventual upper-stream handoff. */
    assert(a.rx.available == 32 && a.tx.available == 31);
    assert(b.rx.available == 32 && b.tx.available == 32);
    uint32_t extra;
    assert(wn_direct_flows_begin(
        &a.owner, (struct wn_direct_request){.service = WN_DIRECT_WENDYCOM}, now, &extra));
    struct wn_direct_recovery_record records[8];
    struct wn_direct_recovery_view view;
    assert(wn_direct_flows_snapshot(&a.owner, records, 8, &view));
    struct wn_direct_frame frame = {.kind = WN_DIRECT_OPEN,
                                    .attachment_id = 3,
                                    .flow_id = id + 2,
                                    .service = WN_DIRECT_WENDYCOM};
    assert(wn_direct_flows_receive(&b.owner, &frame, now, &extra));
    frame = (struct wn_direct_frame){.kind = WN_DIRECT_DATA,
                                     .attachment_id = 3,
                                     .flow_id = id,
                                     .payload = (const uint8_t *)"x",
                                     .payload_size = 1};
    assert(wn_direct_flows_receive(&b.owner, &frame, now, &extra));
    int fd[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
    for (int i = 0; i < 2; i++)
        assert(!fcntl(fd[i], F_SETFL, fcntl(fd[i], F_GETFL, 0) | O_NONBLOCK));
    struct upper_test ua = {.fd = fd[0], .block = true}, ub = {.fd = fd[1]};
    struct wn_direct_upper upper = {.context = &ua,
                                    .read = upper_read,
                                    .write = upper_write,
                                    .shutdown_write = upper_shutdown,
                                    .close = upper_close,
                                    .pending = upper_pending};
    assert(!wn_direct_flows_promote(&a.owner, id, &upper));
    assert(a.rx.available == 32 && a.tx.available == 31);
    assert(wn_direct_flows_promote(&a.owner, id, &upper));
    upper.context = &ub;
    assert(!wn_direct_flows_promote(&b.owner, id, &upper));
    assert(b.rx.available == 32 && b.tx.available == 32);
    assert(wn_direct_flows_poll(&a.owner) >= 0);
    assert(ua.retry_size == 6);
    struct wn_direct_flow *f = wn_direct_flows_find(&a.owner, id);
    assert(f);
    assert(f->upper_write_wait == 1 && f->upper_read_wait == 1);
    assert(a.rx.available == 32 && f->receiver.buffer.limit == 0);
    assert(send(app, "tail", 4, 0) == 4);
    pump(&a, &b, NULL, NULL);
    char got[32];
    assert(recv(b.endpoint, got, sizeof got, MSG_DONTWAIT) == 10 && !memcmp(got, "prefixtail", 10));
    assert(f->upper_write_wait == 0);
    int reads = ua.reads;
    for (unsigned i = 0; i < 3; i++)
        assert(wn_direct_flows_poll(&a.owner) >= 0);
    assert(ua.reads == reads && a.rx.available == 32);
    assert(b.opens == 1);
    assert(send(b.endpoint, "reply", 5, 0) == 5);
    pump(&a, &b, NULL, NULL);
    assert(recv(app, got, sizeof got, MSG_DONTWAIT) == 5 && !memcmp(got, "reply", 5));
    assert(!shutdown(app, SHUT_WR));
    pump(&a, &b, NULL, NULL);
    assert(recv(b.endpoint, got, sizeof got, MSG_DONTWAIT) == 0);
    assert(!shutdown(b.endpoint, SHUT_WR));
    // Drain raw half-closes without delivering control confirmations yet.
    for (int i = 0; i < 10; i++) {
        assert(wn_direct_flows_poll(&a.owner) >= 0);
        assert(wn_direct_flows_poll(&b.owner) >= 0);
    }
    struct wn_direct_frame close_frame;
    assert(wn_direct_flows_prepare(&a.owner, now, &close_frame) == 1 &&
           close_frame.kind == WN_DIRECT_CLOSE_ACK);
    assert(!wn_direct_flows_accepted(&a.owner));
    assert(wn_direct_flows_poll(&a.owner) >= 0);
    struct wn_direct_frame again;
    assert(!wn_direct_flows_prepare(&a.owner, now, &again));
    uint32_t fresh;
    assert(!wn_direct_flows_receive(&b.owner, &close_frame, now, &fresh) && !fresh);
    pump(&a, &b, NULL, NULL);
    assert(recv(app, got, sizeof got, MSG_DONTWAIT) == 0);
    assert(wn_direct_flows_quiescent(&a.owner) && wn_direct_flows_quiescent(&b.owner));
    assert(ua.closed == 1 && ub.closed == 1);
    close(app);
    dispose(&a);
    dispose(&b);
}
/* A FIN learned on the direct lane (or by reconciliation) can precede
 * retained bytes replayed on the promoted stream. EOF is the final offset,
 * not merely knowledge of that offset. Exercise either initiating role. */
static void promoted_fin_before_replay(void)
{
    for (unsigned role = 0; role < 2; role++) {
        struct peer a, b;
        init(&a, (uint8_t)role);
        init(&b, (uint8_t)(1 - role));
        pump(&a, &b, NULL, NULL);
        uint32_t id = begin(&a);
        pump(&a, &b, NULL, NULL);
        int app = connect_app(&a, id);
        assert(send(app, "prefix", 6, 0) == 6);
        pump(&a, &b, NULL, NULL);
        char got[32];
        assert(recv(b.endpoint, got, sizeof got, MSG_DONTWAIT) == 6 && !memcmp(got, "prefix", 6));
        assert(send(app, "suffix", 6, 0) == 6);
        assert(!shutdown(app, SHUT_WR));
        uint8_t drop = WN_DIRECT_DATA;
        pump(&a, &b, &drop, NULL);
        assert(!drop);
        recover(&a, &b);
        struct wn_direct_flow *f = wn_direct_flows_find(&b.owner, id);
        assert(f);
        assert(f->receiver.finished && f->receiver.final == 12 && f->receiver.buffer.end == 6);
        wn_direct_flows_suspend(&a.owner);
        wn_direct_flows_suspend(&b.owner);
        assert(!wn_direct_flows_bind_promoted(&a.owner, 3));
        assert(!wn_direct_flows_bind_promoted(&b.owner, 3));
        int fd[2];
        assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
        for (int i = 0; i < 2; i++)
            assert(!fcntl(fd[i], F_SETFL, fcntl(fd[i], F_GETFL, 0) | O_NONBLOCK));
        struct upper_test ua = {.fd = fd[0]}, ub = {.fd = fd[1]};
        struct wn_direct_upper upper = {.context = &ua,
                                        .read = upper_read,
                                        .write = upper_write,
                                        .shutdown_write = upper_shutdown,
                                        .close = upper_close,
                                        .pending = upper_pending};
        assert(!wn_direct_flows_promote(&a.owner, id, &upper));
        upper.context = &ub;
        assert(!wn_direct_flows_promote(&b.owner, id, &upper));
        pump(&a, &b, NULL, NULL);
        assert(recv(b.endpoint, got, sizeof got, MSG_DONTWAIT) == 6 && !memcmp(got, "suffix", 6));
        assert(recv(b.endpoint, got, sizeof got, MSG_DONTWAIT) == 0);
        assert(send(b.endpoint, "reply", 5, 0) == 5);
        assert(!shutdown(b.endpoint, SHUT_WR));
        pump(&a, &b, NULL, NULL);
        assert(recv(app, got, sizeof got, MSG_DONTWAIT) == 5 && !memcmp(got, "reply", 5));
        assert(recv(app, got, sizeof got, MSG_DONTWAIT) == 0);
        assert(b.opens == 1 && wn_direct_flows_quiescent(&a.owner) &&
               wn_direct_flows_quiescent(&b.owner));
        close(app);
        dispose(&a);
        dispose(&b);
    }
    puts("promoted FIN replay delivered suffix and response on the original socket");
}
static void epoch_idle_lifecycle(void)
{
    struct peer a, b;
    init(&a, 0);
    init(&b, 1);
    struct peer *owners[] = {&a, &b};
    for (unsigned i = 0; i < 2; i++) {
        wn_direct_flows_suspend(&owners[i]->owner);
        assert(!wn_direct_flows_bind(&owners[i]->owner, 2));
    }
    pump(&a, &b, NULL, NULL);
    uint32_t first = begin(&a);
    pump(&a, &b, NULL, NULL);
    uint32_t second = begin(&b);
    pump(&a, &b, NULL, NULL);
    for (unsigned i = 0; i < 2; i++) {
        wn_direct_flows_suspend(&owners[i]->owner);
        assert(!wn_direct_flows_bind_promoted(&owners[i]->owner, 3));
    }
    assert(!wn_direct_flows_reset(&a.owner, first, WN_DIRECT_CANCELLED));
    pump(&a, &b, NULL, NULL);
    assert(!a.owner.idle_sent && !b.owner.idle_sent);
    assert(!wn_direct_flows_retirement_ready(&a.owner) &&
           !wn_direct_flows_retirement_ready(&b.owner));
    assert(!wn_direct_flows_reset(&b.owner, second, WN_DIRECT_CANCELLED));
    pump(&a, &b, NULL, NULL);
    assert(wn_direct_flows_retirement_ready(&a.owner) &&
           wn_direct_flows_retirement_ready(&b.owner));
    for (unsigned i = 0; i < 2; i++) {
        struct wn_direct_frame frame;
        assert(!wn_direct_flows_prepare(&owners[i]->owner, now, &frame));
    }
    dispose(&a);
    dispose(&b);
    puts("promoted epoch waited for both flows and bilateral idle");
}
/* Drive actual flow owners without draining the two stopped app readers. */
static bool credit_transfer(struct peer *from, struct peer *to)
{
    struct wn_direct_frame frame;
    int ready = wn_direct_flows_prepare(&from->owner, now += 100000, &frame);
    assert(ready >= 0);
    if (!ready)
        return false;
    uint8_t wire[WN_DIRECT_MAX_FRAME];
    size_t size;
    assert(!wn_direct_frame_encode(&frame, wire, sizeof wire, &size));
    assert(!wn_direct_flows_accepted(&from->owner));
    assert(!wn_direct_frame_decode(wire, size, &frame));
    uint32_t fresh = 0;
    assert(!wn_direct_flows_receive(&to->owner, &frame, now, &fresh));
    if (fresh) {
        to->opens++;
        assert(!wn_direct_flows_complete(&to->owner, fresh, 0));
    }
    return true;
}
static void credit_pump(struct peer *a, struct peer *b)
{
    for (unsigned i = 0; i < 1000; i++) {
        bool x = credit_transfer(a, b), y = credit_transfer(b, a);
        if (!x && !y)
            return;
    }
    assert(!"credit pump failed to quiesce");
}
static void stopped_readers_preserve_credit(void)
{
    struct peer a, b;
    init(&a, 0);
    init(&b, 1);
    credit_pump(&a, &b);
    uint32_t ids[3];
    for (unsigned i = 0; i < 3; i++) {
        ids[i] = begin(&a);
        credit_pump(&a, &b);
    }
    uint8_t payload[512];
    memset(payload, 0xa5, sizeof payload);
    for (unsigned i = 0; i < 8; i++)
        for (unsigned j = 0; j < 2; j++) {
            struct wn_direct_flow *f = wn_direct_flows_find(&a.owner, ids[j]);
            assert(!wn_direct_send_accept(&f->sender, payload, sizeof payload, a.owner.window));
            credit_pump(&a, &b);
        }
    uint8_t probe[1024], probe_got[1024];
    memset(probe, 0x37, sizeof probe);
    struct wn_direct_flow *probe_out = wn_direct_flows_find(&a.owner, ids[2]),
                          *probe_in = wn_direct_flows_find(&b.owner, ids[2]);
    assert(!wn_direct_send_accept(&probe_out->sender, probe, sizeof probe, a.owner.window));
    credit_pump(&a, &b);
    size_t count = 0;
    struct wn_direct_buffer *probe_rx = &probe_in->receiver.buffer;
    assert(!wn_direct_copy(probe_rx, probe_rx->start, probe_got, sizeof probe_got, &count));
    assert(count == sizeof probe_got && !memcmp(probe, probe_got, count));
    assert(!wn_direct_release(probe_rx, probe_rx->start + count));
    assert(b.rx.available * WN_DIRECT_CHUNK >= sizeof probe);
    uint32_t denied = 0;
    assert(wn_direct_flows_begin(
               &b.owner, (struct wn_direct_request){.service = WN_DIRECT_TCP, .port = 29000}, now,
               &denied) == WN_DIRECT_CAPACITY);
    credit_pump(&a, &b);
    recover(&a, &b);
    credit_pump(&a, &b);
    for (unsigned round = 0; round < 16; round++) {
        struct wn_direct_flow *out = wn_direct_flows_find(&a.owner, ids[2]),
                              *in = wn_direct_flows_find(&b.owner, ids[2]);
        assert(!wn_direct_send_accept(&out->sender, payload, sizeof payload, a.owner.window));
        credit_pump(&a, &b);
        uint8_t got[512];
        size_t n = 0;
        struct wn_direct_buffer *rx = &in->receiver.buffer;
        assert(!wn_direct_copy(rx, rx->start, got, sizeof got, &n));
        assert(n == sizeof got && !memcmp(got, payload, sizeof got));
        assert(!wn_direct_release(rx, rx->start + n));
        credit_pump(&a, &b);
    }
    for (unsigned j = 0; j < 2; j++)
        for (unsigned i = 0; i < 8; i++) {
            struct wn_direct_buffer *rx = &wn_direct_flows_find(&b.owner, ids[j])->receiver.buffer;
            uint8_t got[512];
            size_t n = 0;
            assert(!wn_direct_copy(rx, rx->start, got, sizeof got, &n));
            assert(n == sizeof got && !memcmp(got, payload, sizeof got));
            assert(!wn_direct_release(rx, rx->start + n));
            credit_pump(&a, &b);
        }
    assert(b.opens == 3);
    dispose(&a);
    dispose(&b);
}

static void busy_receive_window_grows(void)
{
    struct peer a, b;
    init(&a, 0);
    init(&b, 1);
    credit_pump(&a, &b);
    uint32_t id = begin(&a);
    credit_pump(&a, &b);
    struct wn_direct_flow *out = wn_direct_flows_find(&a.owner, id),
                          *in = wn_direct_flows_find(&b.owner, id);
    assert(in->receiver.buffer.limit == 1024);
    uint8_t data[512], got[512];
    memset(data, 0x42, sizeof data);
    for (unsigned round = 0; round < 16; round++) {
        assert(!wn_direct_send_accept(&out->sender, data, sizeof data, a.owner.window));
        credit_pump(&a, &b);
        struct wn_direct_buffer *rx = &in->receiver.buffer;
        size_t n = 0;
        assert(!wn_direct_copy(rx, rx->start, got, sizeof got, &n));
        assert(n == sizeof got && !memcmp(got, data, n));
        assert(!wn_direct_release(rx, rx->start + n));
        credit_pump(&a, &b);
    }
    uint64_t outstanding = in->receiver.buffer.limit - in->receiver.buffer.start;
    assert(outstanding > 1024 && outstanding <= 4096);
    dispose(&a);
    dispose(&b);
}

int main(void)
{
    stopped_readers_preserve_credit();
    busy_receive_window_grows();
    loss(WN_DIRECT_DATA);
    loss(WN_DIRECT_STATE);
    early_fin();
    promoted();
    promoted_fin_before_replay();
    epoch_idle_lifecycle();
    return 0;
}
