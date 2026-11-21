#pragma once
#include "wendy_net_direct_session.h"
#include <psa/crypto.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SLOTS 4
struct fixture {
    struct wn_direct_session session;
    struct wn_direct_flows flows;
    struct wn_direct_flow entries[2 * SLOTS];
    struct wn_direct_recovery_record expected[2 * SLOTS], local[2 * SLOTS], remote[2 * SLOTS],
        scratch[2 * SLOTS];
    struct wn_direct_recovery_step plan[4 * SLOTS];
    uint32_t retired[2 * SLOTS];
    struct wn_direct_pool tx, rx;
    struct wn_direct_slot tx_chunks[32], rx_chunks[32];
    unsigned backend_opens;
    uint32_t deferred;
    uint8_t random, epoch;
    bool delay, invalid;
    int endpoint;
};
static int64_t now;
static int random_bytes(void *arg, uint8_t *out, size_t n)
{
    struct fixture *f = arg;
    memset(out, ++f->random, n);
    return 0;
}
static int export(void *arg, const uint8_t context[32], uint8_t out[32])
{
    (void)context;
    struct fixture *f = arg;
    memset(out, 6 + f->epoch, 32);
    return 0;
}
static int policy(void *arg, int64_t at, int64_t *deadline)
{
    (void)at;
    (void)deadline;
    return ((struct fixture *)arg)->invalid ? -1 : 0;
}
static void init_selected(struct fixture *f, uint8_t role, uint32_t selected)
{
    memset(f, 0, sizeof *f);
    f->endpoint = -1;
    assert(!wn_direct_pool_init_dynamic(&f->tx, f->tx_chunks, 32, malloc, free));
    assert(!wn_direct_pool_init_dynamic(&f->rx, f->rx_chunks, 32, malloc, free));
    assert(!wn_direct_flows_init(&f->flows, role, SLOTS, f->entries, f->expected,
                                 f->retired, &f->tx, &f->rx, 4096, 1024));
    struct wn_direct_session_config cfg = {.flows = &f->flows,
                                           .identity_digest = {7},
                                           .role = role,
                                           .selected = selected,
                                           .deadline = INT64_C(1000000000000),
                                           .random = random_bytes,
                                           .random_arg = f,
                                           .check = policy,
                                           .check_arg = f,
                                           .local = f->local,
                                           .remote = f->remote,
                                           .scratch = f->scratch,
                                           .plan = f->plan};
    assert(!wn_direct_session_init(&f->session, &cfg, now));
}
static void init(struct fixture *f, uint8_t role)
{
    init_selected(f, role, WN_DIRECT_CAP_VERSION | WN_DIRECT_CAP_TLS);
}
static void attach(struct fixture *f)
{
    f->epoch++;
    assert(!wn_direct_session_attach(&f->session, f->epoch, 1, f->session.binding.identity_digest,
                                     f->session.cfg.selected, f->session.cfg.deadline, export, f,
                                     now));
}
static void complete(struct fixture *f, uint32_t id)
{
    struct wn_direct_flow *flow = wn_direct_flows_find(&f->flows, id);
    assert(flow);
    int fd[2];
    assert(!socketpair(AF_UNIX, flow->packet ? SOCK_DGRAM : SOCK_STREAM, 0, fd));
    assert(!wn_direct_session_complete(&f->session, id, 0, fd[0]));
    assert(f->endpoint < 0);
    f->endpoint = fd[1];
}
static void dispose(struct fixture *f)
{
    wn_direct_session_close(&f->session);
    if (f->endpoint >= 0)
        close(f->endpoint);
    assert(f->tx.available == 32 && f->rx.available == 32);
}
