#pragma once
#include "wendy_net_direct_registry.h"
#include "wendy_net_direct_poll.h"
struct wn_direct_backend_job;
struct wn_direct_backends {
    struct wn_direct_backend_job *first;
};
/* Root actor owns jobs independently of disposable carrier workers. begin must
 * authorize the exact request and return a nonblocking socket, or -1. No TLS
 * pointers or peer pointers are retained. Zero means completion is now owned. */
uint16_t wn_direct_backend_start(struct wn_direct_backends *, struct wn_direct_peer *, uint32_t,
                                 struct wn_direct_request,
                                 int (*begin)(void *, struct wn_direct_request), void *,
                                 int64_t now);
/* connected:0 pending,1 connected,-1 failed. Completion waits across attachment
 * reconciliation; cancelled/retired epochs dispose the unclaimed socket. */
int wn_direct_backends_poll(struct wn_direct_backends *, struct wn_direct_registry *,
                            int (*connected)(int), int64_t now);
/* Pending connects wake on socket completion or their exact deadline. Ready
 * completions held by recovery do not request continuously writable sockets. */
int64_t wn_direct_backends_pollfds(struct wn_direct_backends *, fd_set *writing, int *maximum,
                                   int64_t deadline);
void wn_direct_backends_close(struct wn_direct_backends *);
