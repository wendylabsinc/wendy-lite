#include "wendy_mesh_discovery.h"
#include "mdns.h"
#include "esp_random.h"
#include <string.h>
#include <strings.h>

size_t wm_discover_peers(const char *tenant, const char *self,
    struct wm_discovered_peer out[WM_DISCOVERY_MAX])
{
    mdns_result_t *results = NULL;
    /* Discover current routers via their native QUIC advertisement. We still
     * connect to the separate TLS/TCP Lite listener, never the QUIC SRV port. */
    esp_err_t error = mdns_query_ptr("_wendy-net", "_udp", 2000, 16, &results);
    size_t count = 0;
    if (error != ESP_OK) goto done;
    for (mdns_result_t *r = results; r && count < WM_DISCOVERY_MAX; r = r->next) {
        if (!r->ttl || !r->port || !r->txt || !r->txt_value_len || r->txt_count > 16) continue;
        const char *principal = NULL, *protocol = NULL, *version = NULL;
        bool invalid = false;
        for (size_t i = 0; i < r->txt_count; ++i) {
            const char *key = r->txt[i].key, *value = r->txt[i].value;
            if (!key) { invalid = true; break; }
            for (size_t j = 0; j < i; ++j)
                if (!strcasecmp(key, r->txt[j].key)) { invalid = true; break; }
            if (invalid) break;
            const char **field = NULL;
            if (!strcasecmp(key, "principal")) field = &principal;
            else if (!strcasecmp(key, "protocol")) field = &protocol;
            else if (!strcasecmp(key, "version")) field = &version;
            if (!field) continue;
            if (!value || strlen(value) != r->txt_value_len[i]) { invalid = true; break; }
            *field = value;
        }
        if (invalid || !principal || strlen(principal) != 105 ||
            !protocol || strcmp(protocol, "quic-v1") || (version && strcmp(version, "1"))) continue;
        for (mdns_ip_addr_t *a = r->addr; a && count < WM_DISCOVERY_MAX; a = a->next) {
            if (a->addr.type != ESP_IPADDR_TYPE_V4) continue;
            struct wm_discovered_peer candidate;
            if (wm_discovery_candidate(tenant, self, principal,
                    (const uint8_t *)&a->addr.u_addr.ip4.addr, &candidate)) continue;
            bool seen = false;
            for (size_t i = 0; i < count; ++i)
                if (!strcmp(out[i].device, candidate.device) &&
                    !strcmp(out[i].host, candidate.host)) seen = true;
            if (!seen) out[count++] = candidate;
        }
    }
    for (size_t i = count; i > 1; --i) {
        size_t j = esp_random() % i;
        struct wm_discovered_peer tmp = out[i - 1];
        out[i - 1] = out[j];
        out[j] = tmp;
    }
done:
    mdns_query_results_free(results);
    return count;
}
