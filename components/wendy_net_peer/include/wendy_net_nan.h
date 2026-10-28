#pragma once
#include "esp_err.h"
#include "wendy_net_peer_protocol.h"

esp_err_t wn_nan_start(void);
bool wn_nan_stop(void);
/* Thread-safe transfer of a live NDP candidate or accepted TCP socket.
 * fd=-1 means an outgoing candidate. Caller owns a transferred fd. */
bool wn_nan_take(struct wn_candidate *candidate,int *fd);
bool wn_nan_peer_live(const char *device);
