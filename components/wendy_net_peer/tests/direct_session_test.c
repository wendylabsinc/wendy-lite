#include "direct_session_fixture.h"
#include <errno.h>
#include <fcntl.h>
static bool transfer(struct fixture *from, struct fixture *to, uint8_t *drop)
{
    const uint8_t *p, *again;
    size_t n, second;
    int ready = wn_direct_session_next(&from->session, now += 100000, &p, &n);
    assert(ready >= 0);
    if (!ready)
        return false;
    assert(wn_direct_session_next(&from->session, now, &again, &second) == 1 && p == again &&
           n == second);
    uint8_t wire[WN_DIRECT_MAX_FRAME];
    memcpy(wire, p, n);
    assert(!wn_direct_session_accepted(&from->session));
    if (drop && *drop == wire[0]) {
        *drop = 0;
        return true;
    }
    uint32_t fresh;
    int err = wn_direct_session_receive(&to->session, to->epoch, wire, n, now, &fresh);
    if (err)
        fprintf(stderr, "session receive kind=%u err=%d closed=%d\n", wire[0], err,
                to->session.closed);
    assert(!err);
    if (fresh) {
        to->backend_opens++;
        if (to->delay)
            to->deferred = fresh;
        else
            complete(to, fresh);
    }
    return true;
}
static void pump(struct fixture *a, struct fixture *b, uint8_t *da, uint8_t *db)
{
    for (unsigned i = 0; i < 1000; i++) {
        int pa = wn_direct_session_tick(&a->session, now),
            pb = wn_direct_session_tick(&b->session, now);
        assert(pa >= 0 && pa != WN_DIRECT_CARRIER_LOST && pb >= 0 && pb != WN_DIRECT_CARRIER_LOST);
        bool sa = transfer(a, b, da), sb = transfer(b, a, db);
        if (!pa && !pb && !sa && !sb)
            return;
    }
    assert(!"session did not idle");
}
static void lost(struct fixture *f)
{
    wn_direct_session_lost(&f->session, f->epoch, now);
    assert(!f->session.attached && !f->session.closed);
}
static uint32_t begin(struct fixture *f)
{
    uint32_t id;
    assert(!wn_direct_flows_begin(&f->flows, (struct wn_direct_request){WN_DIRECT_TCP, 28080, 0},
                                  now, &id));
    return id;
}
static void recovery(uint8_t kind)
{
    struct fixture a, b;
    init(&a, 0);
    init(&b, 1);
    attach(&a);
    attach(&b);
    pump(&a, &b, NULL, NULL);
    assert(a.session.active && b.session.active);
    uint32_t id = begin(&a);
    pump(&a, &b, NULL, NULL);
    int fd[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
    assert(!wn_direct_flows_socket(&a.flows, id, fd[0]));
    assert(b.backend_opens == 1);
    assert(send(fd[1], "before", 6, 0) == 6);
    uint8_t drop = kind;
    pump(&a, &b, kind == WN_DIRECT_DATA ? &drop : NULL, kind == WN_DIRECT_STATE ? &drop : NULL);
    assert(!drop);
    char got[30];
    if (kind == WN_DIRECT_STATE)
        assert(recv(b.endpoint, got, 6, MSG_DONTWAIT) == 6);
    lost(&a);
    lost(&b);
    int backend = wn_direct_flows_find(&b.flows, id)->socket.fd;
    assert(send(fd[1], "after", 5, 0) == 5);
    assert(wn_direct_session_tick(&a.session, now) > 0);
    attach(&a);
    attach(&b);
    pump(&a, &b, NULL, NULL);
    const char *want = kind == WN_DIRECT_DATA ? "beforeafter" : "after";
    assert(recv(b.endpoint, got, sizeof got, MSG_DONTWAIT) == (ssize_t)strlen(want) &&
           !memcmp(got, want, strlen(want)));
    assert(b.backend_opens == 1 && wn_direct_flows_find(&b.flows, id)->socket.fd == backend);
    close(fd[1]);
    dispose(&a);
    dispose(&b);
}
static void bootstrap(uint8_t kind)
{
    struct fixture a, b;
    init(&a, 0);
    init(&b, 1);
    attach(&a);
    attach(&b);
    uint8_t drop = kind;
    if (kind == WN_DIRECT_OFFER)
        assert(transfer(&a, &b, &drop));
    else {
        assert(transfer(&a, &b, NULL));
        assert(transfer(&b, &a, NULL));
        assert(transfer(&b, &a, &drop));
    }
    assert(!drop);
    lost(&a);
    lost(&b);
    attach(&a);
    attach(&b);
    pump(&a, &b, NULL, NULL);
    assert(a.session.active && b.session.active && a.session.gate.generation == 2);
    dispose(&a);
    dispose(&b);
}
static void pending_backend(void)
{
    struct fixture a, b;
    init(&a, 0);
    init(&b, 1);
    b.delay = true;
    attach(&a);
    attach(&b);
    pump(&a, &b, NULL, NULL);
    uint32_t id = begin(&a);
    pump(&a, &b, NULL, NULL);
    assert(b.deferred == id && b.backend_opens == 1);
    lost(&a);
    lost(&b);
    attach(&a);
    attach(&b);
    int fd[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
    assert(wn_direct_session_complete(&b.session, id, 0, fd[0]) == WN_DIRECT_CAPACITY);
    pump(&a, &b, NULL, NULL);
    assert(!wn_direct_session_complete(&b.session, id, 0, fd[0]));
    b.endpoint = fd[1];
    pump(&a, &b, NULL, NULL);
    assert(b.backend_opens == 1);
    dispose(&a);
    dispose(&b);
}
static void outage(void)
{
    struct fixture a;
    init(&a, 0);
    attach(&a);
    lost(&a);
    int64_t deadline = a.session.outage_deadline;
    now += 1000000;
    attach(&a);
    lost(&a);
    assert(a.session.outage_deadline == deadline);
    assert(wn_direct_session_tick(&a.session, deadline) < 0 && a.session.closed);
    dispose(&a);
}
static void promote(struct fixture *f)
{
    f->epoch++;
    assert(!wn_direct_session_promote(&f->session, f->epoch, 1, f->session.binding.identity_digest,
                                      f->session.cfg.selected, f->session.cfg.deadline, export, f,
                                      f->session.binding.role == 0, now));
}
static int flow_export(void *arg, const char *label, const uint8_t context[32], uint8_t out[32])
{
    assert(!strcmp(label, WN_DIRECT_PROMOTED_EXPORT_LABEL));
    return export(arg, context, out);
}
static void binding_transfer(struct wn_direct_promoted_binding *a,
                             struct wn_direct_promoted_binding *b)
{
    const uint8_t *p;
    size_t n, used;
    int ready = wn_direct_promoted_output(a, &p, &n);
    assert(ready >= 0);
    if (!ready)
        return;
    if (n > 7)
        n = 7;
    assert(!wn_direct_promoted_input(b, p, n, &used) && used == n);
    assert(!wn_direct_promoted_sent(a, n));
}
struct upper_fd {
    int fd, closed;
};
static int upper_read(void *arg, uint8_t *p, size_t n)
{
    struct upper_fd *u = arg;
    ssize_t r = recv(u->fd, p, n, MSG_DONTWAIT);
    return r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? -2 : (int)r;
}
static int upper_write(void *arg, const uint8_t *p, size_t n)
{
    struct upper_fd *u = arg;
    if (n > 3)
        n = 3;
    ssize_t r = send(u->fd, p, n, 0);
    return r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? -3 : (int)r;
}
static int upper_shutdown(void *arg)
{
    return shutdown(((struct upper_fd *)arg)->fd, SHUT_WR);
}
static void upper_close(void *arg)
{
    struct upper_fd *u = arg;
    assert(!u->closed++);
    close(u->fd);
    u->fd = -1;
}
static void promotion(bool pending)
{
    struct fixture a, b;
    init(&a, 0);
    init(&b, 1);
    b.delay = pending;
    attach(&a);
    attach(&b);
    pump(&a, &b, NULL, NULL);
    uint32_t id = begin(&a);
    pump(&a, &b, NULL, NULL);
    int app[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, app));
    if (!pending) {
        assert(!wn_direct_flows_socket(&a.flows, id, app[0]));
        assert(send(app[1], "before", 6, 0) == 6);
        uint8_t drop = WN_DIRECT_DATA;
        pump(&a, &b, &drop, NULL);
        assert(!drop);
    }
    lost(&a);
    lost(&b);
    promote(&a);
    promote(&b);
    struct wn_direct_promoted_binding ba, bb;
    pump(&a, &b, NULL, NULL);
    assert(a.session.active && b.session.active && a.flows.upper_control && b.flows.upper_control);
    if (pending) {
        assert(wn_direct_session_start_binding(&a.session, id, &ba, 1, flow_export, &a, now) ==
               WN_DIRECT_CAPACITY);
        assert(b.deferred == id && b.backend_opens == 1);
        complete(&b, id);
        pump(&a, &b, NULL, NULL);
        assert(!wn_direct_flows_socket(&a.flows, id, app[0]));
    }
    assert(!wn_direct_session_start_binding(&a.session, id, &ba, 1, flow_export, &a, now));
    assert(!wn_direct_session_start_binding(&b.session, id, &bb, 0, flow_export, &b, now));
    for (int i = 0; i < 100 && !ba.done; i++) {
        binding_transfer(&ba, &bb);
        binding_transfer(&bb, &ba);
    }
    assert(ba.done && bb.done);
    int fd[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
    for (int i = 0; i < 2; i++)
        assert(!fcntl(fd[i], F_SETFL, fcntl(fd[i], F_GETFL, 0) | O_NONBLOCK));
    struct upper_fd ua = {.fd = fd[0]}, ub = {.fd = fd[1]};
    struct wn_direct_upper upper = {.context = &ua,
                                    .read = upper_read,
                                    .write = upper_write,
                                    .shutdown_write = upper_shutdown,
                                    .close = upper_close};
    assert(!wn_direct_session_commit_flow(&a.session, id, &ba, &upper, now));
    upper.context = &ub;
    assert(!wn_direct_session_commit_flow(&b.session, id, &bb, &upper, now));
    assert(send(app[1], "after", 5, 0) == 5);
    pump(&a, &b, NULL, NULL);
    char payload[32];
    const char *want = pending ? "after" : "beforeafter";
    assert(recv(b.endpoint, payload, sizeof payload, MSG_DONTWAIT) == (ssize_t)strlen(want) &&
           !memcmp(payload, want, strlen(want)) && b.backend_opens == 1);
    assert(send(b.endpoint, "reply", 5, 0) == 5);
    pump(&a, &b, NULL, NULL);
    assert(recv(app[1], payload, sizeof payload, MSG_DONTWAIT) == 5 &&
           !memcmp(payload, "reply", 5));
    wn_direct_session_lost(&a.session, 1, now - 1000000);
    assert(!a.session.closed); // fenced old carrier
    wn_direct_session_lost(&a.session, a.epoch, now);
    assert(a.session.closed && ua.closed == 1);
    // Upper connection death is terminal, not a fresh BLE attachment.
    assert(wn_direct_session_attach(&a.session, 3, 1, a.session.binding.identity_digest,
                                    a.session.cfg.selected, a.session.cfg.deadline, export, &a,
                                    now));
    close(app[1]);
    dispose(&a);
    dispose(&b);
    assert(ub.closed == 1);
}

int main(void)
{
    assert(psa_crypto_init() == PSA_SUCCESS);
    promotion(false);
    promotion(true);
    recovery(WN_DIRECT_DATA);
    recovery(WN_DIRECT_STATE);
    bootstrap(WN_DIRECT_OFFER);
    bootstrap(WN_DIRECT_READY_PROOF);
    pending_backend();
    outage();
    return 0;
}
