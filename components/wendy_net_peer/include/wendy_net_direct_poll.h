#pragma once
#include "wendy_net_direct_registry.h"
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <sys/select.h>
#endif
/* Add retained app sockets and shorten the actor timer for receipt/security
 * deadlines. Frozen recovery snapshots must not poll or consume app bytes. */
int64_t wn_direct_registry_pollfds(struct wn_direct_registry *, fd_set *, fd_set *, int *maximum,
                                   int64_t deadline);
