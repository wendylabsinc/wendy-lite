#include "wendy_net_direct_backend.h"
#include "wendy_net_alloc.h"
#include <limits.h>
#include <unistd.h>
struct wn_direct_backend_job {
    struct wn_direct_backend_job *next;
    uint64_t serial;
    uint32_t id;
    int fd;
    int64_t deadline;
    uint16_t result;
    bool ready;
};
uint16_t wn_direct_backend_start(struct wn_direct_backends *b, struct wn_direct_peer *peer,
                                 uint32_t id, struct wn_direct_request request,
                                 int (*begin)(void *, struct wn_direct_request), void *arg,
                                 int64_t now)
{
    if (!b || !peer || peer->session.closed || !id || !begin || now < 0 ||
        now > INT64_MAX - 5000000)
        return WN_DIRECT_DENIED;
    for (struct wn_direct_backend_job *p = b->first; p; p = p->next)
        if (p->serial == peer->serial && p->id == id)
            return WN_DIRECT_DENIED;
    struct wn_direct_backend_job *p = wendy_net_calloc(1, sizeof *p);
    if (!p)
        return WN_DIRECT_NO_CAPACITY;
    p->fd = begin(arg, request);
    if (p->fd < 0) {
        wendy_net_free(p);
        return WN_DIRECT_DENIED;
    }
    p->serial = peer->serial;
    p->id = id;
    p->deadline = now + 5000000;
    p->next = b->first;
    b->first = p;
    return 0;
}
int wn_direct_backends_poll(struct wn_direct_backends *b, struct wn_direct_registry *r,
                            int (*connected)(int), int64_t now)
{
    if (!b || !r || !connected)
        return 0;
    int progress = 0;
    struct wn_direct_backend_job **at = &b->first;
    while (*at) {
        struct wn_direct_backend_job *p = *at;
        struct wn_direct_peer *peer = wn_direct_registry_lookup(r, p->serial);
        struct wn_direct_flow *flow = peer ? wn_direct_flows_find(&peer->flows, p->id) : NULL;
        if (flow && !flow->reset) {
            if (!p->ready) {
                int status = now >= p->deadline ? -1 : connected(p->fd);
                if (!status) {
                    at = &p->next;
                    continue;
                }
                p->ready = true;
                if (status < 0) {
                    close(p->fd);
                    p->fd = -1;
                    p->result = WN_DIRECT_IO;
                }
            }
            int result = wn_direct_session_complete(&peer->session, p->id, p->result, p->fd);
            if (result == WN_DIRECT_CAPACITY) {
                at = &p->next;
                continue;
            }
            if (!result)
                p->fd = -1; /* Session accepted ownership. */
        }
        if (p->fd >= 0)
            close(p->fd);
        *at = p->next;
        wendy_net_free(p);
        progress = 1;
    }
    return progress;
}
void wn_direct_backends_close(struct wn_direct_backends *b)
{
    if (!b)
        return;
    while (b->first) {
        struct wn_direct_backend_job *p = b->first;
        b->first = p->next;
        if (p->fd >= 0)
            close(p->fd);
        wendy_net_free(p);
    }
}
int64_t wn_direct_backends_pollfds(struct wn_direct_backends *b, fd_set *writing, int *maximum,
                                   int64_t deadline)
{
    for (struct wn_direct_backend_job *p = b->first; p; p = p->next)
        if (!p->ready) {
            if (p->deadline < deadline)
                deadline = p->deadline;
            if (p->fd >= 0 && p->fd < FD_SETSIZE) {
                FD_SET(p->fd, writing);
                if (p->fd > *maximum)
                    *maximum = p->fd;
            }
        }
    return deadline;
}
