#include "wendy_net_direct_dial.h"
#include "wendy_net_alloc.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#ifndef ESP_PLATFORM
#include <arpa/inet.h>
#endif
struct wn_direct_dial_job {
    struct wn_direct_dial_job *next;
    uint64_t serial;
    uint32_t id;
    struct wn_direct_request request;
    int handle, listener, guest;
    int64_t deadline;
    bool notified, frozen;
};
static int nonblock(int fd)
{
    return fd >= 0 && fd < FD_SETSIZE && fcntl(fd, F_SETFL, O_NONBLOCK) >= 0 ? 0 : -1;
}
static void discard(struct wn_direct_dial_job *j)
{
    if (j->listener >= 0)
        close(j->listener);
    if (j->guest >= 0)
        close(j->guest);
    wendy_net_free(j);
}
static int pair_begin(struct wn_direct_dial_job *j)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof address;
    j->listener = socket(AF_INET, SOCK_STREAM, 0);
    if (nonblock(j->listener) || bind(j->listener, (struct sockaddr *)&address, size) ||
        getsockname(j->listener, (struct sockaddr *)&address, &size) || listen(j->listener, 1))
        return -1;
    j->guest = socket(AF_INET, SOCK_STREAM, 0);
    if (nonblock(j->guest))
        return -1;
    return connect(j->guest, (struct sockaddr *)&address, size) && errno != EINPROGRESS ? -1 : 0;
}
int wn_direct_dial_start(struct wn_direct_dials *d, uint64_t serial, int handle,
                         struct wn_direct_request request, int64_t deadline)
{
    if (!d || !serial || handle <= 0 || deadline <= 0)
        return -1;
    if (!((request.service == WN_DIRECT_TCP && request.port && !request.datagram_size) ||
          (request.service == WN_DIRECT_WENDYCOM && !request.port && !request.datagram_size) ||
          (request.service == WN_DIRECT_UDP && request.port && request.datagram_size &&
           d->complete_datagram)))
        return -1;
    for (struct wn_direct_dial_job *j = d->first; j; j = j->next)
        if (j->handle == handle)
            return -1;
    struct wn_direct_dial_job *j = wendy_net_calloc(1, sizeof *j);
    if (!j)
        return -1;
    *j = (struct wn_direct_dial_job){.next = d->first,
                                     .serial = serial,
                                     .handle = handle,
                                     .request = request,
                                     .deadline = deadline,
                                     .listener = -1,
                                     .guest = -1};
    d->first = j;
    return 0;
}
int wn_direct_dials_poll(struct wn_direct_dials *d, struct wn_direct_registry *r,
                         int (*complete)(int, int), int64_t now)
{
    int progress = 0;
    struct wn_direct_dial_job **at = &d->first;
    while (*at) {
        struct wn_direct_dial_job *j = *at;
        struct wn_direct_peer *p = wn_direct_registry_lookup(r, j->serial);
        j->frozen = p && wn_direct_session_frozen(&p->session);
        if (now >= j->deadline && !j->notified) {
            (void)complete(j->handle, -1);
            j->notified = true;
            progress = 1;
        }
        /* Report timeout promptly, but defer cancellation of an existing flow until
         * reconciliation unfreezes it. Such tombstones are bounded by flow slots. */
        if (j->frozen && (!j->notified || j->id)) {
            at = &j->next;
            continue;
        }
        bool fail = !p || now >= j->deadline;
        if (!fail && !j->id) {
            if (!p->session.active) {
                at = &j->next;
                continue;
            }
            if (j->request.service == WN_DIRECT_UDP &&
                p->flows.peer_datagram_known && !p->flows.peer_datagram_limit &&
                d->fallback_datagram) {
                if (d->fallback_datagram(j->handle, p, j->request, j->deadline)) {
                    at = &j->next;
                    continue;
                }
                /* No OPEN id exists; ownership, deadline and admission move together. */
                *at = j->next;
                discard(j);
                progress = 1;
                continue;
            }
            int result = wn_direct_flows_begin(&p->flows, j->request, now, &j->id);
            if (result == WN_DIRECT_CAPACITY) {
                at = &j->next;
                continue;
            }
            fail = result != 0;
        }
        struct wn_direct_flow *flow = !fail ? wn_direct_flows_find(&p->flows, j->id) : NULL;
        struct wn_direct_open_entry entry;
        if (!fail) {
            fail = !flow || flow->reset ||
                   wn_direct_flows_open(&p->flows, j->id, &entry);
            if (!fail && !entry.complete) {
                at = &j->next;
                continue;
            }
            if (!fail)
                fail = entry.result != 0;
        }
        if (!fail && j->request.service == WN_DIRECT_UDP) {
            /* The callback owns guest completion even if binding fails. Never invoke
             * stream completion a second time on that failure or during shutdown. */
            j->notified = true;
            if (d->complete_datagram(j->handle, &p->flows, j->id))
                (void)wn_direct_flows_reset(&p->flows, j->id, WN_DIRECT_CANCELLED);
            *at = j->next;
            discard(j);
            progress = 1;
            continue;
        }
        if (!fail && j->listener < 0)
            fail = pair_begin(j) != 0;
        if (!fail) {
            int fd = accept(j->listener, NULL, NULL);
            if (fd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                at = &j->next;
                continue;
            }
            if (fd < 0)
                fail = true;
            else if (wn_direct_flows_socket(&p->flows, j->id, fd)) {
                close(fd);
                fail = true;
            }
        }
        if (fail) {
            if (p && j->id)
                (void)wn_direct_flows_reset(&p->flows, j->id, WN_DIRECT_CANCELLED);
            if (!j->notified)
                (void)complete(j->handle, -1);
        } else {
            int fd = j->guest;
            j->guest = -1;
            if (complete(j->handle, fd))
                (void)wn_direct_flows_reset(&p->flows, j->id, WN_DIRECT_CANCELLED);
        }
        *at = j->next;
        discard(j);
        progress = 1;
    }
    return progress;
}
int64_t wn_direct_dials_pollfds(struct wn_direct_dials *d, fd_set *rd, fd_set *wr, int *maximum,
                                int64_t now, int64_t deadline)
{
    (void)wr;
    for (struct wn_direct_dial_job *j = d->first; j; j = j->next) {
        if (j->deadline > now && j->deadline < deadline)
            deadline = j->deadline;
        if (!j->frozen && j->listener >= 0) {
            FD_SET(j->listener, rd);
            if (j->listener > *maximum)
                *maximum = j->listener;
        }
    }
    return deadline;
}
void wn_direct_dials_close(struct wn_direct_dials *d, int (*complete)(int, int))
{
    while (d->first) {
        struct wn_direct_dial_job *j = d->first;
        d->first = j->next;
        if (!j->notified)
            (void)complete(j->handle, -1);
        discard(j);
    }
}
