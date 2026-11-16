#pragma once
#include "wendy_net_direct_registry.h"
struct wn_direct_native;
struct wn_direct_natives {
    struct wn_direct_native *first;
};
/* Actor derives role from retained authenticated policy, never OPEN bytes. */
uint16_t wn_direct_native_open(struct wn_direct_natives *, struct wn_direct_peer *, uint32_t id,
                               bool operator_peer, unsigned capacity);
int wn_direct_natives_poll(struct wn_direct_natives *, struct wn_direct_registry *);
bool wn_direct_natives_stop(struct wn_direct_natives *);
