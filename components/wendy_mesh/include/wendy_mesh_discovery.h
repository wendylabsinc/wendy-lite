#pragma once
#include <stddef.h>
#include <stdint.h>

#define WM_DISCOVERY_MAX 8
struct wm_discovered_peer {
    char host[16];
    char device[37];
};
/* Validate only a discovery hint. TLS must still authenticate this exact
 * device under the enrolled tenant's roots before using the connection. */
int wm_discovery_candidate(const char *tenant, const char *self,
    const char *principal, const uint8_t address[4], struct wm_discovered_peer *out);
/* Fresh, bounded mDNS snapshot in randomized order; no persisted peer pin. */
size_t wm_discover_peers(const char *tenant, const char *self,
    struct wm_discovered_peer out[WM_DISCOVERY_MAX]);
