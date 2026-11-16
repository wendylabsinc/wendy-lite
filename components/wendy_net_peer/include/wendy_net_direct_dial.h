#pragma once
#include "wendy_net_direct_poll.h"
struct wn_direct_dial_job;
struct wn_direct_dials {
    struct wn_direct_dial_job *first;
    /* Before OPEN only: transfer the existing guest admission to upper transport.
     * Zero transfers ownership; nonzero leaves the job pending until its deadline. */
    int (*fallback_datagram)(int handle, struct wn_direct_peer *, struct wn_direct_request,
                             int64_t deadline);
    /* Called only after successful UDP OPEN. Completes the guest exactly once,
     * including failure, and binds its native endpoint to the admitted flow.
     * Return nonzero to reset that flow. No stream fd is created. */
    int (*complete_datagram)(int handle, struct wn_direct_flows *, uint32_t id);
};
/* Actor-only. Jobs retain serials, never peer/carrier pointers. complete consumes
 * fd on both success and failure, including a guest cancelled during OPEN. */
int wn_direct_dial_start(struct wn_direct_dials *, uint64_t serial, int handle,
                         struct wn_direct_request, int64_t deadline);
int wn_direct_dials_poll(struct wn_direct_dials *, struct wn_direct_registry *,
                         int (*complete)(int handle, int fd), int64_t now);
int64_t wn_direct_dials_pollfds(struct wn_direct_dials *, fd_set *, fd_set *, int *, int64_t now,
                                int64_t deadline);
void wn_direct_dials_close(struct wn_direct_dials *, int (*complete)(int, int));
