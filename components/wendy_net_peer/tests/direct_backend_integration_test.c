#include "wendy_net_direct_backend.h"
#include "wendy_net_direct_dial.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <psa/crypto.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

struct endpoint {
    struct wn_direct_registry registry;
    struct wn_direct_peer *peer;
    struct wn_direct_backends jobs;
    struct wn_direct_dials dials;
    unsigned random, epoch, opens;
    struct sockaddr_in address;
    bool pending;
};
static int64_t now;
static struct wn_direct_request requested = {WN_DIRECT_TCP, 28080, 0};
static int guest_fd = -1, completions;
static int guest_complete(int handle, int fd)
{
    assert(handle == 1 && guest_fd < 0);
    completions++;
    guest_fd = fd;
    return fd < 0 ? -1 : 0;
}
static int rng(void *arg, uint8_t *out, size_t size)
{
    struct endpoint *e = arg;
    memset(out, ++e->random, size);
    return 0;
}
static int exporter(void *arg, const uint8_t context[32], uint8_t out[32])
{
    struct endpoint *e = arg;
    (void)context;
    memset(out, 6 + e->epoch, 32);
    return 0;
}
static void init(struct endpoint *e, uint8_t role)
{
    assert(!wn_direct_registry_init(&e->registry, 1, true));
    struct wn_direct_session_config cfg = {.identity_digest = {7},
                                           .role = role,
                                           .selected = WN_DIRECT_CAP_VERSION | WN_DIRECT_CAP_TLS,
                                           .deadline = 1000000000000,
                                           .random = rng,
                                           .random_arg = e};
    struct wn_direct_peer_key key = {.principal = {3}, .instance = {4}};
    assert(!wn_direct_registry_acquire(&e->registry, &key, &cfg, 0, now, &e->peer));
}
static void attach(struct endpoint *e)
{
    e->epoch++;
    struct wn_direct_session *s = &e->peer->session;
    assert(!wn_direct_session_attach(s, e->epoch, 1, s->binding.identity_digest, WN_DIRECT_CAP_VERSION | WN_DIRECT_CAP_TLS,
                                     s->security_deadline, exporter, e, now));
}
static int begin(void *arg, struct wn_direct_request request)
{
    struct endpoint *e = arg;
    assert(request.service == requested.service && request.port == requested.port &&
           !request.datagram_size);
    e->opens++;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0 && !fcntl(fd, F_SETFL, O_NONBLOCK));
    assert(connect(fd, (struct sockaddr *)&e->address, sizeof e->address) == 0 ||
           errno == EINPROGRESS);
    return fd;
}
static int connected(int fd)
{
    fd_set wr;
    FD_ZERO(&wr);
    FD_SET(fd, &wr);
    struct timeval timeout = {0};
    int r = select(fd + 1, NULL, &wr, NULL, &timeout);
    assert(r >= 0);
    if (!r)
        return 0;
    int error = 0;
    socklen_t size = sizeof error;
    assert(!getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size));
    return error ? -1 : 1;
}
static int pending(int fd)
{
    (void)fd;
    return 0;
}
static void move(struct endpoint *a, struct endpoint *b)
{
    const uint8_t *wire;
    size_t size;
    int n = wn_direct_session_next(&a->peer->session, now, &wire, &size);
    assert(n >= 0);
    if (!n)
        return;
    uint8_t copy[WN_DIRECT_MAX_FRAME];
    memcpy(copy, wire, size);
    assert(!wn_direct_session_accepted(&a->peer->session));
    uint32_t id = 0;
    int received = wn_direct_session_receive(&b->peer->session, b->epoch, copy, size, now, &id);
    if (received)
        fprintf(
            stderr,
            "receive role=%u epoch=%u kind=%u size=%zu at=%lld result=%d active=%d exchanging=%d\n",
            b->peer->session.cfg.role, b->epoch, copy[0], size, (long long)now, received,
            b->peer->session.active, b->peer->session.exchanging);
    assert(!received);
    if (id)
        assert(!wn_direct_backend_start(&b->jobs, b->peer, id,
                                        wn_direct_flows_find(&b->peer->flows, id)->request, begin,
                                        b, now));
}
static void service(struct endpoint *a, struct endpoint *b, unsigned turns)
{
    for (unsigned i = 0; i < turns; i++) {
        now += 1000;
        assert(wn_direct_registry_tick(&a->registry, now) >= 0);
        assert(wn_direct_registry_tick(&b->registry, now) >= 0);
        wn_direct_dials_poll(&a->dials, &a->registry, guest_complete, now);
        wn_direct_dials_poll(&b->dials, &b->registry, guest_complete, now);
        move(a, b);
        move(b, a);
        wn_direct_backends_poll(&a->jobs, &a->registry, a->pending ? pending : connected, now);
        wn_direct_backends_poll(&b->jobs, &b->registry, b->pending ? pending : connected, now);
    }
}
static void dispose(struct endpoint *e)
{
    wn_direct_dials_close(&e->dials, guest_complete);
    wn_direct_backends_close(&e->jobs);
    wn_direct_registry_close(&e->registry);
    wn_direct_registry_release(&e->registry, e->peer);
    assert(wn_direct_registry_close(&e->registry));
}
int main(int argc, char **argv)
{
    if (argc == 2) {
        assert(!strcmp(argv[1], "native"));
        requested = (struct wn_direct_request){.service = WN_DIRECT_WENDYCOM};
    } else
        assert(argc == 1);
    assert(psa_crypto_init() == PSA_SUCCESS);
    assert(wendy_net_runtime_memory_open());
    struct endpoint a = {0}, b = {.pending = true};
    init(&a, 0);
    init(&b, 1);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    b.address =
        (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(listener, (struct sockaddr *)&b.address, sizeof b.address) &&
           !listen(listener, 2));
    socklen_t size = sizeof b.address;
    assert(!getsockname(listener, (struct sockaddr *)&b.address, &size));
    attach(&a);
    attach(&b);
    service(&a, &b, 100);
    assert(a.peer->session.active && b.peer->session.active);
    assert(!wn_direct_dial_start(&a.dials, a.peer->serial, 1, requested, now + 10000000));
    service(&a, &b, 100);
    assert(b.opens == 1 && b.jobs.first && completions == 0);
    uint32_t id = a.peer->flows.flows[0].id;
    assert(id);
    int backend = accept(listener, NULL, NULL);
    assert(backend >= 0);
    close(listener);
    wn_direct_session_lost(&a.peer->session, a.epoch, now);
    wn_direct_session_lost(&b.peer->session, b.epoch, now);
    attach(&a);
    attach(&b);
    b.pending = false;
    assert(!wn_direct_backends_poll(&b.jobs, &b.registry, connected, now) &&
           b.jobs.first); /* Ready, but reconciliation frozen. */
    service(&a, &b, 200);
    assert(!b.jobs.first && b.opens == 1 && a.peer->session.active && b.peer->session.active);
    assert(completions == 1 && guest_fd >= 0 && !a.dials.first);
    int local[2] = {-1, guest_fd};
    char payload[1500], got[1500];
    memset(payload, 0x42, sizeof payload);
    assert(send(local[1], payload, sizeof payload, 0) == sizeof payload);
    service(&a, &b, 200);
    assert(recv(backend, got, sizeof got, MSG_DONTWAIT) == sizeof got &&
           !memcmp(got, payload, sizeof got));
    int retained = wn_direct_flows_find(&b.peer->flows, id)->socket.fd;
    /* Retain application bytes across another loss without reopening TCP. */
    wn_direct_session_lost(&a.peer->session, a.epoch, now);
    wn_direct_session_lost(&b.peer->session, b.epoch, now);
    assert(send(backend, "thermometer", 11, 0) == 11);
    assert(wn_direct_registry_tick(&b.registry, ++now) >= 0);
    attach(&a);
    attach(&b);
    service(&a, &b, 200);
    assert(recv(local[1], got, sizeof got, MSG_DONTWAIT) == 11 && !memcmp(got, "thermometer", 11));
    assert(b.opens == 1 && wn_direct_flows_find(&b.peer->flows, id)->socket.fd == retained);
    assert(!shutdown(local[1], SHUT_WR));
    service(&a, &b, 200);
    assert(recv(backend, got, sizeof got, MSG_DONTWAIT) == 0);
    assert(!shutdown(backend, SHUT_WR));
    service(&a, &b, 200);
    assert(recv(local[1], got, sizeof got, MSG_DONTWAIT) == 0);
    close(local[1]);
    close(backend);
    guest_fd = -1;
    wn_direct_session_lost(&a.peer->session, a.epoch, now);
    wn_direct_session_lost(&b.peer->session, b.epoch, now);
    assert(!wn_direct_dial_start(&a.dials, a.peer->serial, 1, requested, now + 10000000));
    assert(!wn_direct_dials_poll(&a.dials, &a.registry, guest_complete, now) && a.dials.first &&
           completions == 1);
    wn_direct_dials_close(&a.dials, guest_complete);
    assert(completions == 2 && guest_fd == -1);
    attach(&a);
    attach(&b);
    assert(!wn_direct_dial_start(&a.dials, a.peer->serial, 1, requested, now + 1));
    assert(wn_direct_dials_poll(&a.dials, &a.registry, guest_complete, now + 1) && !a.dials.first &&
           completions == 3);
    service(&a, &b, 100);
    assert(!wn_direct_dial_start(&a.dials, a.peer->serial, 1, requested, now + 1));
    assert(!wn_direct_dials_poll(&a.dials, &a.registry, guest_complete, now) && a.dials.first);
    wn_direct_session_lost(&a.peer->session, a.epoch, now);
    wn_direct_session_lost(&b.peer->session, b.epoch, now);
    attach(&a);
    attach(&b);
    assert(wn_direct_dials_poll(&a.dials, &a.registry, guest_complete, now + 1) && a.dials.first &&
           completions == 4);
    /* Frozen cancellation keeps its flow tombstone; shutdown must not notify twice. */
    dispose(&a);
    dispose(&b);
    assert(completions == 4);
    assert(wendy_net_runtime_memory_drained());
    wendy_net_runtime_memory_close();
    return 0;
}
