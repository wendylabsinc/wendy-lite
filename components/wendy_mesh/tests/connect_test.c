#include "wendy_mesh_connect.h"
#include "wendy_mesh_discovery.h"
#include "wendy_conf.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool wifi, current, resetting, tcp_ok, ble_open_ok, ble_tls_ok;
static bool reset_after_tcp;
static unsigned candidates, tcp_calls, ble_calls, tls_calls, closes;
static const char tenant[] = "12345678-9abc-4def-8123-000000000001";
static const char self[] = "12345678-9abc-4def-8123-000000000002";
static const char peer[] = "12345678-9abc-4def-8123-000000000003";
static int connection_storage;

bool wendy_wifi_is_connected(void) { return wifi; }
bool wendy_conf_is_current(void) { return current; }
bool wendy_pki_reset_in_progress(void) { return resetting; }
void wendy_conf_enrollment_identity(char out_tenant[37], char out_device[65])
{
    strcpy(out_tenant, tenant);
    strcpy(out_device, self);
}
size_t wm_discover_peers(const char* t, const char* d, struct wm_discovered_peer out[WM_DISCOVERY_MAX])
{
    assert(wifi && !strcmp(t, tenant) && !strcmp(d, self));
    for (unsigned i = 0; i < candidates; ++i) {
        strcpy(out[i].host, "192.0.2.1");
        strcpy(out[i].device, peer);
    }
    return candidates;
}
static void authenticated(wendy_pki_connection** c, struct wendy_pki_mesh_identity* identity)
{
    *c = (wendy_pki_connection*)&connection_storage;
    strcpy(identity->peer, peer);
}
esp_err_t wendy_pki_mesh_connect(const char* host, unsigned port, const char* pin,
    wendy_pki_connection** c, struct wendy_pki_mesh_identity* identity)
{
    assert(wifi && !ble_calls && !strcmp(host, "192.0.2.1") && port == 43024);
    assert(!strcmp(pin, peer));
    ++tcp_calls;
    if (reset_after_tcp) resetting = true;
    if (!tcp_ok) { *c = NULL; return ESP_FAIL; }
    authenticated(c, identity);
    return ESP_OK;
}
static void close_ble(void) { ++closes; }
int wm_ble_open(struct wm_carrier* carrier)
{
    assert(!tcp_ok && current && !resetting);
    ++ble_calls;
    if (!ble_open_ok) return -1;
    carrier->name = "BLE";
    carrier->close = close_ble;
    return 0;
}
esp_err_t wendy_pki_mesh_stream_same_tenant(const struct wendy_pki_stream* stream,
    wendy_pki_connection** c, struct wendy_pki_mesh_identity* identity)
{
    assert(stream && ble_calls && !tcp_ok);
    ++tls_calls;
    if (!ble_tls_ok) { *c = NULL; return ESP_FAIL; }
    authenticated(c, identity);
    return ESP_OK;
}
static void phase(enum wendy_mesh_phase next) { (void)next; }
static void reset(void)
{
    wifi = current = ble_open_ok = ble_tls_ok = true;
    resetting = tcp_ok = reset_after_tcp = false;
    candidates = 3;
    tcp_calls = ble_calls = tls_calls = closes = 0;
}
int main(void)
{
    for (unsigned scenario = 0; scenario < 8; ++scenario) {
        reset();
        struct wm_mesh_connection attempt = { 0 };
        if (scenario == 0) tcp_ok = true;
        if (scenario == 1) wifi = false;
        if (scenario == 2) candidates = 0;
        if (scenario == 4) ble_tls_ok = false;
        if (scenario == 5) ble_open_ok = false;
        if (scenario == 6) reset_after_tcp = true;
        if (scenario == 7) current = false;
        int result = wm_mesh_connect(&attempt, phase);
        assert((result == 0) == (scenario < 4));
        assert(tcp_calls <= 1); // A list of failed Wi-Fi peers cannot starve BLE.
        if (scenario == 0) {
            assert(tcp_calls == 1 && !ble_calls && !tls_calls);
            assert(!strcmp(attempt.carrier.name, "Wi-Fi TCP"));
        } else if (scenario < 6) {
            assert(ble_calls == 1);
            assert(tls_calls == (scenario != 5));
        } else assert(!ble_calls && !tls_calls);
        if (!result) assert(attempt.connection && !strcmp(attempt.identity.peer, peer));
        else assert(!attempt.connection);
        // Even failed BLE TLS must leave teardown ownership with the caller.
        if (attempt.carrier.close) attempt.carrier.close();
        assert(closes == (scenario > 0 && scenario < 5));
    }
    puts("Wi-Fi preference, BLE fallback, bounded retries, reset and failure ownership passed");
}
