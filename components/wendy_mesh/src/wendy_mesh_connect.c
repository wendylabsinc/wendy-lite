#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif
#include "wendy_mesh_connect.h"
#include "wendy_mesh_discovery.h"
#include "wendy_wifi.h"
#include "wendy_conf.h"

#if CONFIG_WENDY_MESH_TCP || CONFIG_WENDY_MESH_WIFI_BLE
static int connect_tcp(struct wm_mesh_connection* s, void (*phase)(enum wendy_mesh_phase))
{
    if (!wendy_wifi_is_connected()) {
        phase(WENDY_MESH_WAITING_WIFI);
        return -1;
    }
#if CONFIG_WENDY_MESH_AUTO_DISCOVER
    phase(WENDY_MESH_DISCOVERING);
    char tenant[37], self[65];
    wendy_conf_enrollment_identity(tenant, self);
    struct wm_discovered_peer candidates[WM_DISCOVERY_MAX];
    size_t count = wm_discover_peers(tenant, self, candidates);
#if CONFIG_WENDY_MESH_WIFI_BLE
    /* Discovery shuffles candidates. Bound each Wi-Fi round so unavailable
     * routers cannot postpone the next BLE acceptance window indefinitely. */
    if (count > 1) count = 1;
#endif
    for (size_t i = 0; i < count; ++i) {
        if (!wendy_wifi_is_connected() || !wendy_conf_is_current() ||
            wendy_pki_reset_in_progress()) return -1;
        phase(WENDY_MESH_CONNECTING);
        if (wendy_pki_mesh_connect(candidates[i].host, CONFIG_WENDY_MESH_ROUTER_PORT,
                candidates[i].device, &s->connection, &s->identity) == ESP_OK)
            break;
    }
    if (!s->connection) { phase(WENDY_MESH_DISCOVERING); return -1; }
#else
    if (wendy_pki_mesh_connect(CONFIG_WENDY_MESH_ROUTER_HOST, CONFIG_WENDY_MESH_ROUTER_PORT,
            CONFIG_WENDY_MESH_ROUTER_DEVICE, &s->connection, &s->identity) != ESP_OK) return -1;
#endif
    s->carrier.name = "Wi-Fi TCP";
    return 0;
}
#endif

int wm_mesh_connect(struct wm_mesh_connection* s, void (*phase)(enum wendy_mesh_phase))
{
    (void)phase;
    if (!wendy_conf_is_current() || wendy_pki_reset_in_progress()) return -1;
#if CONFIG_WENDY_MESH_WIFI_BLE
    if (connect_tcp(s, phase)) {
        if (!wendy_conf_is_current() || wendy_pki_reset_in_progress()) return -1;
        phase(WENDY_MESH_CONNECTING);
        if (wm_ble_open(&s->carrier)) return -1;
        if (wendy_pki_mesh_stream_same_tenant(&s->carrier.stream,
                &s->connection, &s->identity) != ESP_OK) return -1;
    }
#elif CONFIG_WENDY_MESH_TCP
    if (connect_tcp(s, phase)) return -1;
#else
#if CONFIG_WENDY_MESH_BLE
    if (wm_ble_open(&s->carrier)) return -1;
#else
    if (wm_espnow_open(&s->carrier)) return -1;
#endif
    if (wendy_pki_mesh_stream(&s->carrier.stream, s->carrier.server,
            CONFIG_WENDY_MESH_ROUTER_DEVICE, &s->connection, &s->identity) != ESP_OK) return -1;
#endif
    return 0;
}
