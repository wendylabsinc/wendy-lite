#include "wendy_mesh_discovery.h"
#include "mdns.h"
#include "esp_random.h"
#include <string.h>

size_t wm_discover_peers(const char *tenant, const char *self,
    struct wm_discovered_peer out[WM_DISCOVERY_MAX])
{
    mdns_result_t *results = NULL;
    /* Linux mesh routers already publish their principal on this service.
     * Its SRV port is the full mesh transport, not the Lite listener. */
    esp_err_t error = mdns_query_ptr("_wendy-mesh", "_tcp", 2000, 16, &results);
    size_t count = 0;
    if (error != ESP_OK) goto done;
    for (mdns_result_t *r = results; r && count < WM_DISCOVERY_MAX; r = r->next) {
        if (!r->ttl || r->port != 43023) continue;
        const char *principal = NULL;
        bool duplicate = false;
        for (size_t i = 0; i < r->txt_count; ++i) {
            if (!r->txt[i].key || strcmp(r->txt[i].key, "principal")) continue;
            if (principal) { duplicate = true; break; }
            if (!r->txt[i].value || !r->txt_value_len || r->txt_value_len[i] != 105 ||
                strlen(r->txt[i].value) != 105) { duplicate = true; break; }
            principal = r->txt[i].value;
        }
        if (!principal || duplicate) continue;
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
