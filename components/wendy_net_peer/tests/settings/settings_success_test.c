/* Ordinary saved policy, response transport fences and bounded application. */
#include <assert.h>
#include <stdio.h>
#include "../../src/settings.c"
static int64_t now;
static unsigned writes, changes, registrations;
static bool have_record, fail_write;
static struct record stored;
static const struct wcom_net_delegate *delegate;
bool wn_espnow_supported(void)
{
    return CONFIG_WENDY_WIFI_ENABLED;
}
#if CONFIG_WENDY_NET_BLE
static unsigned selected_profile;
void wble_mesh_set_profile(unsigned profile)
{
    selected_profile = profile;
}
#endif
int64_t esp_timer_get_time(void)
{
    return now;
}
size_t heap_caps_get_total_size(unsigned caps)
{
    assert(caps == MALLOC_CAP_SPIRAM);
#ifdef TEST_PSRAM
    return 8 * 1024 * 1024;
#else
 return 0;
#endif
}
void wn_peer_runtime_status(WendyComNetStatus *s)
{
    s->state = WendyComNetState_WENDY_COM_NET_OFF;
}
void wn_peer_configuration_changed(void)
{
    changes++;
}
WendyComResult wn_peer_topology(const WendyComNetTopologyParams *params,
                                WendyComNetTopologyPage *page)
{
    assert(!params->cursor);
    assert(page->has_status && !page->status.desired.enabled);
    return WendyComResult_WENDY_COM_RESULT_OK;
}
void wnt_page_release(WendyComNetTopologyPage *page)
{
    (void)page;
}
void wcom_cmd_set_net_delegate(const struct wcom_net_delegate *d)
{
    delegate = d;
    registrations++;
}
esp_err_t nvs_flash_init_partition(const char *name)
{
    assert(!strcmp(name, "wendy_pki"));
    return ESP_OK;
}
esp_err_t nvs_open_from_partition(const char *partition, const char *space, int mode,
                                  nvs_handle_t *h)
{
    assert(!strcmp(partition, "wendy_pki") && !strcmp(space, "net-settings"));
    *h = mode + 1;
    return ESP_OK;
}
void nvs_close(nvs_handle_t h)
{
    assert(h == 1 || h == 2);
}
esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *size)
{
    assert(h == 1 && (!strcmp(key, "config") || !strcmp(key, "config2") || !strcmp(key, "config3")) && *size == sizeof stored);
    if (!have_record)
        return ESP_ERR_NVS_NOT_FOUND;
    memcpy(out, &stored, sizeof stored);
    return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *in, size_t size)
{
    assert(h == 2 && !strcmp(key, "config3") && size == sizeof stored);
    if (fail_write)
        return ESP_FAIL;
    memcpy(&stored, in, size);
    have_record = true;
    writes++;
    return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t h)
{
    assert(h == 2);
    return ESP_OK;
}
static void applied(uint32_t token, bool drained)
{
    unsigned before = changes;
    now += 1000;
    delegate->reply_complete(token);
    wn_settings_poll(drained);
    assert(changes == before);
    now += 250000;
    wn_settings_poll(drained);
    if (drained)
        assert(changes == before + 1);
}
int main(void)
{
    bool boot_ble_selected, boot_wifi_selected;
    assert(wendy_net_peer_boot_radios(&boot_ble_selected, &boot_wifi_selected) == ESP_OK &&
           delegate && registrations == 1 && !writes);
    assert(wn_settings_init() == ESP_OK && registrations == 1);
    WendyComNetStatus status;
    uint32_t token = 999;
    assert(delegate->get(&status) == WendyComResult_WENDY_COM_RESULT_OK && !status.desired.enabled);
    assert(status.ble_supported == !!CONFIG_WENDY_NET_BLE &&
           status.wifi_supported == !!CONFIG_WENDY_WIFI_ENABLED && !status.nan_supported);
    WendyComNetTopologyParams query = WendyComNetTopologyParams_init_zero;
    WendyComNetTopologyPage page = WendyComNetTopologyPage_init_zero;
    assert(delegate->topology(&query, &page) == WendyComResult_WENDY_COM_RESULT_OK &&
           !page.runtime_available && !writes);
#if !WENDY_NET_NON_TRANSIT
    assert(status.desired.max_links == 8 && status.desired.wifi_links == 8);
    WendyComNetConfig too_many = status.desired;
    too_many.max_links = 9;
    assert(delegate->set(&too_many, &status, &token) == WendyComResult_WENDY_COM_RESULT_BAD_STATE);
#endif
    assert(status.ble_profiles_supported ==
           (CONFIG_WENDY_NET_BLE ? (CODED_PROFILES_SUPPORTED ? 7u : 1u) : 0u));
    WendyComNetConfig invalid_profile = status.desired;
    invalid_profile.ble_profile = (WendyComBleProfile)3;
    assert(delegate->set(&invalid_profile, &status, &token) ==
               WendyComResult_WENDY_COM_RESULT_NET_BLE_PROFILE_UNSUPPORTED &&
           !token && !writes);
#if !CODED_PROFILES_SUPPORTED
    invalid_profile.ble_profile = WendyComBleProfile_WENDY_COM_BLE_CODED_S2;
    assert(delegate->set(&invalid_profile, &status, &token) ==
               WendyComResult_WENDY_COM_RESULT_NET_BLE_PROFILE_UNSUPPORTED &&
           !token && !writes);
#endif
    WendyComNetConfig config = status.desired;
    config.enabled = true;
    if (!config.ble && !config.infrastructure_wifi) {
        config.ble = CONFIG_WENDY_NET_BLE;
        config.infrastructure_wifi = CONFIG_WENDY_WIFI_ENABLED;
    }
    assert(delegate->set(&config, &status, &token) == WendyComResult_WENDY_COM_RESULT_OK && token &&
           writes == 1);
    uint32_t first = token;
    assert(wn_settings_pending() && !changes);
    now += 1000000;
    wn_settings_poll(true);
    assert(!changes);
    delegate->reply_complete(first + 1);
    wn_settings_poll(true);
    assert(!changes);
    uint32_t ignored;
    assert(delegate->set(&config, &status, &ignored) == WendyComResult_WENDY_COM_RESULT_BUSY &&
           !ignored);
    applied(first, true);
    assert(changes == 1 && !wn_settings_pending());
    assert(delegate->set(&config, &status, &token) == WendyComResult_WENDY_COM_RESULT_OK &&
           !token && writes == 1);
    config.enabled = false;
    assert(delegate->set(&config, &status, &token) == WendyComResult_WENDY_COM_RESULT_OK && token &&
           writes == 2);
 /* Old callbacks cannot complete a later settings generation. */
    delegate->reply_complete(first);
    wn_settings_poll(true);
    assert(changes == 1);
    applied(token, false);
    assert(changes == 1 && wn_settings_pending());
    now += 5000000;
    wn_settings_poll(false);
    assert(changes == 2 && !wn_settings_pending());
    config.enabled = true;
    fail_write = true;
    assert(delegate->set(&config, &status, &token) ==
               WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR &&
           !token && !status.desired.enabled && !wn_settings_pending());
    fail_write = false;
    WendyComNetConfig unsupported = config;
    unsupported.nan = true;
    assert(delegate->set(&unsupported, &status, &token) ==
               WendyComResult_WENDY_COM_RESULT_NET_NO_NAN &&
           !token);
#if !CONFIG_WENDY_NET_BLE
    unsupported = config;
    unsupported.ble = true;
    assert(delegate->set(&unsupported, &status, &token) ==
           WendyComResult_WENDY_COM_RESULT_NET_NO_BLE);
#endif
#if !CONFIG_WENDY_WIFI_ENABLED
    unsupported = config;
    unsupported.infrastructure_wifi = true;
    assert(delegate->set(&unsupported, &status, &token) ==
           WendyComResult_WENDY_COM_RESULT_NET_NO_WIFI);
#endif
#if WENDY_NET_NON_TRANSIT
    unsupported = config;
    unsupported.ble = unsupported.infrastructure_wifi = true;
    assert(delegate->set(&unsupported, &status, &token) ==
           WendyComResult_WENDY_COM_RESULT_NET_ONE_CARRIER_ONLY);
    bool ble, wifi;
    assert(wendy_net_peer_boot_radios(&ble, &wifi) == ESP_OK && !ble && wifi);
    config.ble = true;
    config.infrastructure_wifi = false;
    assert(delegate->set(&config, &status, &token) ==
               WendyComResult_WENDY_COM_RESULT_APPLIED_RESTARTING &&
           token && status.restarting);
    assert(!wn_settings_restart_due());
    applied(token, true);
    assert(wn_settings_restart_due());
#else
 /* A client that vanishes before responding cannot stall settings forever. */
    assert(delegate->set(&config, &status, &token) == WendyComResult_WENDY_COM_RESULT_OK && token);
    unsigned before = changes;
    now += 45000000;
    wn_settings_poll(false);
    assert(changes == before + 1 && !wn_settings_pending());
#endif
#if CODED_PROFILES_SUPPORTED
    /* Simulate reboot: retain only the persisted NVS record. A profile-only
     * update must survive boot and preserve carrier/participation policy. */
    loaded = boot_selected = false;
    atomic_store(&restarting, false);
    atomic_store(&restart_ready, false);
    atomic_store(&awaiting_reply, false);
    atomic_store(&receipt, 0);
    memset(&apply, 0, sizeof apply);
    assert(wn_settings_init() == ESP_OK);
    config = wn_settings_get();
    bool enabled_before = config.enabled, ble_before = config.ble;
    bool wifi_before = config.infrastructure_wifi;
    config.ble_profile = WendyComBleProfile_WENDY_COM_BLE_CODED_S8;
    assert(delegate->set(&config, &status, &token) == WendyComResult_WENDY_COM_RESULT_OK && token &&
           !status.restarting && ((stored.flags >> 4) & 3u) == 2);
    applied(token, true);
    loaded = false;
    assert(wn_settings_init() == ESP_OK);
    bool boot_has_ble, boot_has_wifi;
    assert(wendy_net_peer_boot_radios(&boot_has_ble, &boot_has_wifi) == ESP_OK &&
           selected_profile == 2 && boot_has_ble == ble_before &&
           boot_has_wifi == !!CONFIG_WENDY_WIFI_ENABLED);
    config = wn_settings_get();
    assert(config.enabled == enabled_before && config.ble == ble_before &&
           config.infrastructure_wifi == wifi_before && config.ble_profile == 2);
    config.ble_profile = WendyComBleProfile_WENDY_COM_BLE_CODED_S2;
    assert(delegate->set(&config, &status, &token) ==
               WendyComResult_WENDY_COM_RESULT_APPLIED_RESTARTING &&
           token && status.restarting && !wn_settings_restart_due());
    /* Selecting saved intent cannot change the live host before its reply. */
    assert(selected_profile == 2);
    applied(token, true);
    assert(wn_settings_restart_due() && selected_profile == 2);
#endif
#if CONFIG_WENDY_WIFI_ENABLED
    /* A carrier-only toggle stays in the actor after the reply fence. */
    boot_selected = false;
    atomic_store(&restarting, false);
    atomic_store(&restart_ready, false);
    config = wn_settings_get();
    config.espnow = true;
    config.espnow_channel = 11;
    assert(config.espnow_rate == WendyComEspnowRate_WENDY_COM_ESPNOW_RATE_12_MBPS);
    config.espnow_rate = WendyComEspnowRate_WENDY_COM_ESPNOW_RATE_24_MBPS;
#if WENDY_NET_NON_TRANSIT
    assert(delegate->set(&config, &status, &token) ==
           WendyComResult_WENDY_COM_RESULT_NET_ONE_CARRIER_ONLY);
    config.ble = config.infrastructure_wifi = false;
    assert(delegate->set(&config, &status, &token) == WendyComResult_WENDY_COM_RESULT_OK);
    applied(token, true);
#else
    unsigned before_espnow = changes;
    assert(delegate->set(&config, &status, &token) == WendyComResult_WENDY_COM_RESULT_OK && token);
    assert(!wn_settings_try_espnow(&config));
    delegate->reply_complete(token);
    wn_settings_poll(true);
    now += 250000;
    wn_settings_poll(true);
    assert(changes == before_espnow && wn_settings_try_espnow(&config));
#endif
    assert(config.espnow && config.espnow_channel == 11);
    config.has_espnow = config.has_espnow_channel = config.has_espnow_links = false;
    config.has_espnow_rate = false;
    config.espnow_rate = WendyComEspnowRate_WENDY_COM_ESPNOW_RATE_DEFAULT;
    config.espnow = false;
    config.espnow_channel = config.espnow_links = 0;
    assert(delegate->set(&config, &status, &token) == WendyComResult_WENDY_COM_RESULT_OK && !token);
    assert(status.desired.espnow && status.desired.espnow_channel == 11);
    assert(status.desired.espnow_rate == WendyComEspnowRate_WENDY_COM_ESPNOW_RATE_24_MBPS);
    config = status.desired;
    config.espnow_rate = (WendyComEspnowRate)9;
    assert(delegate->set(&config, &status, &token) == WendyComResult_WENDY_COM_RESULT_BAD_STATE && !token);
#endif
    puts(
        "native settings: bounded receipt, persistence, typed capabilities and runtime radio selection PASS");
}
