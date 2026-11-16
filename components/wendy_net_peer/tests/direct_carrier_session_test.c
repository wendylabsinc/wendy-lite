#include "direct_session_fixture.h"
#include "wendy_net_direct_carrier.h"
#include "wendy_net_peer_protocol.h"

struct pipe {
    struct pipe *other;
    uint8_t bytes[8192];
    size_t size, offset;
    bool blocked;
};
struct transport {
    struct fixture app;
    struct pipe io;
    struct wnc_carrier carrier;
    struct wn_direct_carrier direct;
    uint8_t small[WN_DATAGRAM_MAX];
    unsigned legacy;
};
static int64_t clock_now(void *arg)
{
    (void)arg;
    return now;
}
static ssize_t read_bytes(void *arg, void *out, size_t n)
{
    struct pipe *p = arg;
    if (p->offset == p->size)
        return -2;
    if (n > 7)
        n = 7;
    if (n > p->size - p->offset)
        n = p->size - p->offset;
    memcpy(out, p->bytes + p->offset, n);
    p->offset += n;
    return (ssize_t)n;
}
static ssize_t write_bytes(void *arg, const void *bytes, size_t n)
{
    struct pipe *p = arg;
    if (p->blocked)
        return -3;
    struct pipe *to = p->other;
    if (to->offset) {
        memmove(to->bytes, to->bytes + to->offset, to->size - to->offset);
        to->size -= to->offset;
        to->offset = 0;
    }
    if (n > 13)
        n = 13;
    if (n > sizeof to->bytes - to->size)
        n = sizeof to->bytes - to->size;
    if (!n)
        return -3;
    memcpy(to->bytes + to->size, bytes, n);
    to->size += n;
    return (ssize_t)n;
}
static uint16_t open_backend(void *arg, uint32_t id, struct wn_direct_request request)
{
    struct transport *t = arg;
    assert(request.service == WN_DIRECT_TCP && request.port == 28080);
    t->app.backend_opens++;
    complete(&t->app, id);
    return 0;
}
static int legacy(void *arg, const void *data, size_t size, bool control)
{
    struct transport *t = arg;
    assert(control && (size == 400 || size == 1) && *(const uint8_t *)data == 42);
    t->legacy++;
    return 0;
}
static void connect_carrier(struct transport *t, bool operator)
{
    struct wnc_io io = {&t->io, read_bytes, write_bytes};
    assert(!wnc_init(&t->carrier, &io, t->small, sizeof t->small, 8192, 8192));
    assert(!wnc_fair_scheduler(&t->carrier, 4));
    if (operator)
        assert(!wnc_operator_router(&t->carrier));
    attach(&t->app);
    assert(!wn_direct_carrier_bind(&t->direct, &t->app.session, &t->carrier, clock_now, NULL,
                                   open_backend, t));
    struct wn_direct_carrier duplicate = {0};
    struct wnc_carrier other;
    assert(!wnc_init(&other, &io, t->small, sizeof t->small, 8192, 8192));
    assert(wn_direct_carrier_bind(&duplicate, &t->app.session, &other, clock_now, NULL,
                                  open_backend, t) == WNC_INVALID);
    assert(!other.direct_receive && !duplicate.session);
    wnc_deinit(&other);
}
static void disconnect_carrier(struct transport *t)
{
    assert(wn_direct_carrier_unbind(&t->direct, now) == WNC_INVALID); // Worker still owns carrier.
    wnc_deinit(&t->carrier);
    assert(!wn_direct_carrier_unbind(&t->direct, now));
    t->io.size = t->io.offset = 0;
}
static void service(struct transport *a, struct transport *b)
{
    for (unsigned i = 0; i < 30000; i++) {
        now += 1000;
        int pa = wn_direct_session_tick(&a->app.session, now),
            pb = wn_direct_session_tick(&b->app.session, now);
        assert(pa >= 0 && pb >= 0);
        int fa = wn_direct_carrier_flush(&a->direct, 4),
            fb = wn_direct_carrier_flush(&b->direct, 4);
        assert(fa >= 0 && fb >= 0);
        int ca = wnc_pump(&a->carrier, now, legacy, a), cb = wnc_pump(&b->carrier, now, legacy, b);
        assert(ca >= 0 && cb >= 0);
        if (!pa && !pb && !fa && !fb && !ca && !cb && !a->carrier.queued && !b->carrier.queued &&
            a->app.session.active && b->app.session.active) {
            // Give cumulative ACK timers one further interval before declaring idle.
            now += 100000;
            fa = wn_direct_carrier_flush(&a->direct, 4);
            fb = wn_direct_carrier_flush(&b->direct, 4);
            assert(fa >= 0 && fb >= 0);
            if (!fa && !fb)
                return;
        }
    }
    assert(!"framed carrier did not idle");
}
static void test(bool operator)
{
    struct transport a = {0}, b = {0};
    init(&a.app, 0);
    init(&b.app, 1);
    a.io.other = &b.io;
    b.io.other = &a.io;
    connect_carrier(&a, operator);
    connect_carrier(&b, operator);
    uint8_t filler[400] = {42};
    unsigned filled = 0;
    int result;
    while (!(result = wnc_enqueue(&a.carrier, filler, sizeof filler, true)))
        filled++;
    assert(result == WNC_LIMIT && filled > 0);
    while (!(result = wnc_enqueue(&a.carrier, filler, 1, true)))
        filled++;
    assert(result == WNC_LIMIT);
    // Exhaust the metadata class, proving OFFER remains pending without consuming
    // its exchange state. Fragmented writes later make room without dropping it.
    a.io.blocked = true;
    assert(wn_direct_carrier_flush(&a.direct, 4) == 0);
    assert(a.app.session.wire_size == 137);
    uint8_t pending[137];
    memcpy(pending, a.app.session.wire, sizeof pending);
    assert(wn_direct_carrier_flush(&a.direct, 4) == 0 &&
           !memcmp(pending, a.app.session.wire, sizeof pending));
    for (unsigned i = 0; i < 5; i++) {
        now += 1000;
        assert(wnc_pump(&a.carrier, now, legacy, &a) >= 0);
    }
    assert(!a.app.session.active && !b.app.session.active);
    a.io.blocked = false;
    service(&a, &b);
    assert(b.legacy == filled);
    uint32_t id;
    assert(!wn_direct_flows_begin(&a.app.flows, (struct wn_direct_request){WN_DIRECT_TCP, 28080, 0},
                                  now, &id));
    service(&a, &b);
    int fd[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
    assert(!wn_direct_flows_socket(&a.app.flows, id, fd[0]));
    assert(b.app.backend_opens == 1);
    char sent[1500], got[1500];
    memset(sent, 0x51, sizeof sent);
    assert(send(fd[1], sent, sizeof sent, 0) == sizeof sent);
    service(&a, &b);
    assert(recv(b.app.endpoint, got, sizeof got, MSG_DONTWAIT) == sizeof got &&
           !memcmp(got, sent, sizeof got));
    assert(send(fd[1], "cut during frame", 16, 0) == 16);
    assert(wn_direct_session_tick(&a.app.session, now) > 0);
    assert(wn_direct_carrier_flush(&a.direct, 1) == 1);
    assert(wnc_pump(&a.carrier, now, legacy, &a) >= 0);
    assert(b.io.size > b.io.offset);
    int original = wn_direct_flows_find(&b.app.flows, id)->socket.fd;
    disconnect_carrier(&a);
    disconnect_carrier(&b);
    connect_carrier(&a, operator);
    connect_carrier(&b, operator);
    service(&a, &b);
    assert(recv(b.app.endpoint, got, sizeof got, MSG_DONTWAIT) == 16 &&
           !memcmp(got, "cut during frame", 16));
    assert(b.app.backend_opens == 1 &&
           wn_direct_flows_find(&b.app.flows, id)->socket.fd == original);
    // Promote without closing the physical mesh carrier. Old copied records may
    // drain afterward but cannot mutate the detached logical session.
    assert(!wn_direct_carrier_retire(&a.direct, now));
    assert(!wn_direct_carrier_retire(&b.direct, now));
    assert(!a.app.session.closed && !a.app.session.attached && !a.app.session.carrier_owner);
    assert(!b.app.session.closed && wn_direct_flows_find(&b.app.flows, id)->socket.fd == original);
    assert(a.carrier.io.write && b.carrier.io.write && !a.direct.session && !b.direct.session);
    assert(!wnc_enqueue(&a.carrier, filler, 1, true));
    unsigned old_legacy = b.legacy;
    for (unsigned i = 0; i < 100; i++) {
        now += 1000;
        assert(wnc_pump(&a.carrier, now, legacy, &a) >= 0);
        assert(wnc_pump(&b.carrier, now, legacy, &b) >= 0);
    }
    assert(b.legacy == old_legacy + 1);
    close(fd[1]);
    wnc_deinit(&a.carrier);
    wnc_deinit(&b.carrier);
    dispose(&a.app);
    dispose(&b.app);
}
struct reservation {
    bool busy, held;
    unsigned acquisitions, releases;
};
static bool reserve_reuse(void *arg)
{
    struct reservation *r = arg;
    assert(!r->held);
    if (r->busy)
        return false;
    r->held = true;
    r->acquisitions++;
    return true;
}
static void release_reuse(void *arg)
{
    struct reservation *r = arg;
    assert(r->held);
    r->held = false;
    r->releases++;
}
static void propose_pair(struct transport *a, struct transport *b, struct reservation *ra,
                         struct reservation *rb, unsigned count)
{
    for (unsigned i = 0; i < count; i++) {
        now += 1000;
        assert(wn_direct_carrier_propose(&a->direct, true, true, reserve_reuse, release_reuse, ra,
                                         now) >= 0);
        assert(wn_direct_carrier_propose(&b->direct, true, true, reserve_reuse, release_reuse, rb,
                                         now) >= 0);
        assert(wnc_pump(&a->carrier, now, legacy, a) >= 0);
        assert(wnc_pump(&b->carrier, now, legacy, b) >= 0);
    }
}
static void test_parked_rearm(bool participant_opens)
{
    struct transport a = {0}, b = {0};
    init(&a.app, 0);
    init(&b.app, 1);
    a.io.other = &b.io;
    b.io.other = &a.io;
    connect_carrier(&a, false);
    connect_carrier(&b, false);
    service(&a, &b);
    // A copied old close receipt remains in the physical writer during handoff.
    uint8_t old_record[9];
    size_t size;
    struct wn_direct_frame ack = {.kind = WN_DIRECT_CLOSE_ACK, .attachment_id = 1, .flow_id = 2};
    assert(!wn_direct_frame_encode(&ack, old_record, sizeof old_record, &size));
    assert(!wnc_enqueue_direct(&a.carrier, old_record, size));
    assert(!wn_direct_carrier_park(&a.direct, now));
    assert(!wn_direct_carrier_park(&b.direct, now));
    assert(!a.direct.session && !b.direct.session && a.direct.alias == 1 && b.direct.alias == 1);
    struct reservation ra = {0}, rb = {.busy = true};
    propose_pair(&a, &b, &ra, &rb, 100);
    assert(ra.acquisitions == 1 && ra.releases == 1 && !ra.held && !rb.held);
    // BUSY released the local gate; new work can satisfy the remote application's
    // dependency. Neither side holds a gate waiting for the old application.
    ra.busy = true;
    rb.busy = false;
    propose_pair(&a, &b, &ra, &rb, 300);
    assert(!ra.held && !rb.held);
    ra.busy = false;
    propose_pair(&a, &b, &ra, &rb, 100);
    assert(ra.held && rb.held && a.direct.proposal_accepted && b.direct.proposal_accepted);

    // Runtime retirement permission is supplied separately. The adapter only
    // handles reader/queue ownership; start one new owner before the other.
    dispose(&a.app);
    init(&a.app, 0);
    a.app.epoch = 1;
    a.app.session.binding.session_id[0] = 81;
    a.app.session.binding.capability[0] = 82;
    assert(!wn_direct_session_attach(&a.app.session, 1, 2, a.app.session.binding.identity_digest,
                                     a.app.session.cfg.selected, a.app.session.cfg.deadline, export,
                                     &a.app, now));
    assert(!wn_direct_carrier_bind(&a.direct, &a.app.session, &a.carrier, clock_now, NULL,
                                   open_backend, &a));
    assert(wn_direct_carrier_flush(&a.direct, 4) > 0);
    uint8_t metadata = 42;
    assert(!wnc_enqueue(&a.carrier, &metadata, 1, true));
    for (unsigned i = 0; i < 200; i++) {
        now += 1000;
        assert(wnc_pump(&a.carrier, now, legacy, &a) >= 0);
        assert(wnc_pump(&b.carrier, now, legacy, &b) >= 0);
    }
    assert(b.direct.parked_offer && b.legacy == 1 && !b.direct.session);
    dispose(&b.app);
    init(&b.app, 1);
    b.app.epoch = 1;
    assert(!wn_direct_session_attach(&b.app.session, 1, 2, b.app.session.binding.identity_digest,
                                     b.app.session.cfg.selected, b.app.session.cfg.deadline, export,
                                     &b.app, now));
    assert(!wn_direct_carrier_bind(&b.direct, &b.app.session, &b.carrier, clock_now, NULL,
                                   open_backend, &b));
    assert(!b.direct.parked_offer);
    service(&a, &b);
    assert(a.app.session.active && b.app.session.active && a.direct.alias == 2 &&
           b.direct.alias == 2);
    release_reuse(&ra);
    release_reuse(&rb);
    assert(!memcmp(a.app.session.binding.session_id, b.app.session.binding.session_id, 32));
    struct transport *origin = participant_opens ? &b : &a, *target = participant_opens ? &a : &b;
    uint32_t id;
    assert(!wn_direct_flows_begin(&origin->app.flows,
                                  (struct wn_direct_request){WN_DIRECT_TCP, 28080, 0}, now, &id));
    service(&a, &b);
    assert(target->app.backend_opens == 1);
    int fd[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
    assert(!wn_direct_flows_socket(&origin->app.flows, id, fd[0]));
    const char payload[] = "new application on the same TLS carrier";
    char got[sizeof payload];
    assert(send(fd[1], payload, sizeof payload, 0) == sizeof payload);
    service(&a, &b);
    assert(recv(target->app.endpoint, got, sizeof got, MSG_DONTWAIT) == sizeof got &&
           !memcmp(got, payload, sizeof got));
    close(fd[1]);
    disconnect_carrier(&a);
    disconnect_carrier(&b);
    dispose(&a.app);
    dispose(&b.app);
}
static void test_deferred_carrier(bool participant_opens)
{
    struct transport a = {0}, b = {0};
    init(&a.app, 0);
    init(&b.app, 1);
    a.io.other = &b.io;
    b.io.other = &a.io;
    struct transport *ends[2] = {&a, &b};
    for (unsigned i = 0; i < 2; i++) {
        struct transport *t = ends[i];
        struct wnc_io io = {&t->io, read_bytes, write_bytes};
        assert(!wnc_init(&t->carrier, &io, t->small, sizeof t->small, 8192, 8192));
        assert(!wnc_fair_scheduler(&t->carrier, 4));
        assert(!wn_direct_carrier_defer(&t->direct, &t->carrier, (uint8_t)i, clock_now, NULL,
                                        open_backend, t));
    }
    struct reservation ra = {0}, rb = {.busy = true};
    propose_pair(&a, &b, &ra, &rb, 100);
    assert(!ra.held && !rb.held && !a.app.session.attached && !b.app.session.attached);
    rb.busy = false;
    propose_pair(&a, &b, &ra, &rb, 400);
    assert(ra.held && rb.held);
    for (unsigned i = 0; i < 2; i++) {
        struct transport *t = ends[i];
        attach(&t->app);
        assert(!wn_direct_carrier_bind(&t->direct, &t->app.session, &t->carrier, clock_now, NULL,
                                       open_backend, t));
    }
    service(&a, &b);
    release_reuse(&ra);
    release_reuse(&rb);
    assert(a.direct.alias == 1 && b.direct.alias == 1);
    struct transport *origin = participant_opens ? &b : &a, *target = participant_opens ? &a : &b;
    uint32_t id;
    assert(!wn_direct_flows_begin(&origin->app.flows,
                                  (struct wn_direct_request){WN_DIRECT_TCP, 28080, 0}, now, &id));
    service(&a, &b);
    int fd[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
    assert(!wn_direct_flows_socket(&origin->app.flows, id, fd[0]));
    const char payload[] = "first app after deferred BLE admission";
    char got[sizeof payload];
    assert(send(fd[1], payload, sizeof payload, 0) == sizeof payload);
    service(&a, &b);
    assert(recv(target->app.endpoint, got, sizeof got, MSG_DONTWAIT) == sizeof got &&
           !memcmp(got, payload, sizeof got));
    assert(target->app.backend_opens == 1);
    close(fd[1]);
    disconnect_carrier(&a);
    disconnect_carrier(&b);
    dispose(&a.app);
    dispose(&b.app);
}
/* Closing a deferred logical owner must release a proposal without closing
 * the physical routing carrier or discarding its already-queued notification. */
static void test_terminal_proposal_keeps_routing(void)
{
    struct transport a = {0}, b = {0};
    init(&a.app, 0);
    init(&b.app, 1);
    a.io.other = &b.io;
    b.io.other = &a.io;
    struct transport *ends[2] = {&a, &b};
    for (unsigned i = 0; i < 2; i++) {
        struct transport *t = ends[i];
        struct wnc_io io = {&t->io, read_bytes, write_bytes};
        assert(!wnc_init(&t->carrier, &io, t->small, sizeof t->small, 8192, 8192));
        assert(!wn_direct_carrier_defer(&t->direct, &t->carrier, (uint8_t)i, clock_now, NULL,
                                        open_backend, t));
    }
    struct reservation ra = {0}, rb = {0};
    assert(
        !wn_direct_carrier_propose(&a.direct, true, true, reserve_reuse, release_reuse, &ra, now));
    assert(ra.held);
    assert(wn_direct_carrier_propose(&b.direct, true, false, reserve_reuse, release_reuse, &rb,
                                     now) == 2);
    assert(!wn_direct_carrier_retire(&b.direct, now));
    for (unsigned i = 0; i < 100; i++) {
        now += 1000;
        assert(wnc_pump(&a.carrier, now, legacy, &a) >= 0);
        assert(wnc_pump(&b.carrier, now, legacy, &b) >= 0);
    }
    assert(wn_direct_carrier_propose(&a.direct, true, true, reserve_reuse, release_reuse, &ra,
                                     now) == 2);
    assert(!ra.held && ra.acquisitions == 1 && ra.releases == 1);
    assert(!wn_direct_carrier_retire(&a.direct, now));
    uint8_t metadata = 42;
    unsigned before = b.legacy;
    assert(!wnc_enqueue(&a.carrier, &metadata, 1, true));
    for (unsigned i = 0; i < 100; i++) {
        now += 1000;
        assert(wnc_pump(&a.carrier, now, legacy, &a) >= 0);
        assert(wnc_pump(&b.carrier, now, legacy, &b) >= 0);
    }
    assert(b.legacy == before + 1);
    wnc_deinit(&a.carrier);
    wnc_deinit(&b.carrier);
    dispose(&a.app);
    dispose(&b.app);
}
static void test_paused_proposal_releases_admission(void)
{
    struct transport a = {0}, b = {0};
    init(&a.app, 0);
    a.io.other = &b.io;
    struct wnc_io io = {&a.io, read_bytes, write_bytes};
    assert(!wnc_init(&a.carrier, &io, a.small, sizeof a.small, 8192, 8192));
    assert(!wn_direct_carrier_defer(&a.direct, &a.carrier, 0, clock_now, NULL, open_backend, &a));
    struct reservation r = {0};
    assert(
        !wn_direct_carrier_propose(&a.direct, true, true, reserve_reuse, release_reuse, &r, now));
    assert(r.held);
    /* A connected but suspended peer does not complete the queued proposal.
     * Its reservation must expire without renewing on repeated actor polls. */
    int64_t deadline = a.direct.proposal_deadline;
    assert(!wn_direct_carrier_propose(&a.direct, true, true, reserve_reuse, release_reuse, &r,
                                      deadline - 1));
    assert(r.held && a.direct.proposal_deadline == deadline);
    assert(wn_direct_carrier_propose(&a.direct, true, true, reserve_reuse, release_reuse, &r,
                                     deadline) == WNC_TIMEOUT);
    assert(!r.held && r.acquisitions == 1 && r.releases == 1);
    assert(!wn_direct_carrier_retire(&a.direct, deadline));
    wnc_deinit(&a.carrier);
    dispose(&a.app);
}
int main(void)
{
    assert(psa_crypto_init() == PSA_SUCCESS);
    test(false);
    test(true);
    test_parked_rearm(false);
    test_parked_rearm(true);
    test_deferred_carrier(false);
    test_deferred_carrier(true);
    test_terminal_proposal_keeps_routing();
    test_paused_proposal_releases_admission();
    return 0;
}
