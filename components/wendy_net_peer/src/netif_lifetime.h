#pragma once
#include <stdbool.h>
#include <stdint.h>

/* A carrier is a route to the mesh, not the lifetime of our IPv6 address.
 * Keep established TCP sockets during a short ordinary reconnection. No
 * packets are queued without a carrier; TCP retains its own bounded retry. */
#define WNNL_RECOVERY_US INT64_C(30000000)
struct wnnl { int64_t until; bool carrier, up; };

static inline bool wnnl_current(const struct wnnl *s, bool identity, int64_t now)
{
    return identity && s->up && (s->carrier || now < s->until);
}

static inline bool wnnl_update(struct wnnl *s, bool carrier, bool identity, int64_t now)
{
    if (carrier && identity) {
        s->up = true;
        s->until = 0;
    } else if (s->carrier && s->up && identity) {
        s->until = now + WNNL_RECOVERY_US;
    }
    s->carrier = carrier;
    if (!wnnl_current(s, identity, now)) {
        s->up = false;
        s->until = 0;
    }
    return s->up;
}
