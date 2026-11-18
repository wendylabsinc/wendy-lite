#include "settings.h"
#include "espnow_carrier.h"
#include "wendy_net_espnow_hosted.h"
#include "topology_record.h"
#if CONFIG_WENDY_NET_BLE
#include "wendy_ble_mesh.h"
#endif
#include "settings_apply.h"
#include "wendy_net_profile.h"
#include "wendy_com_cmd.h"
#include "esp_heap_caps.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <stdatomic.h>
#include <pthread.h>
#include <string.h>

#ifndef CONFIG_WENDY_NET_BLE
#define CONFIG_WENDY_NET_BLE 0
#endif
#ifndef CONFIG_WENDY_WIFI_ENABLED
#define CONFIG_WENDY_WIFI_ENABLED 0
#endif
#ifndef CONFIG_BT_NIMBLE_EXT_ADV_V2
#define CONFIG_BT_NIMBLE_EXT_ADV_V2 0
#endif
#if CONFIG_BT_NIMBLE_EXT_ADV_V2 && (CONFIG_IDF_TARGET_ESP32C5 || CONFIG_IDF_TARGET_ESP32C6)
#define CODED_PROFILES_SUPPORTED 1
#else
#define CODED_PROFILES_SUPPORTED 0
#endif
#ifndef CONFIG_WENDY_NET_BLE_CHANNELS
#define CONFIG_WENDY_NET_BLE_CHANNELS 1
#endif
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static bool loaded;
static bool boot_selected, boot_ble, boot_wifi;
static unsigned boot_profile;
static atomic_bool restarting, restart_ready, awaiting_reply;
static struct wnsa apply;
static atomic_uint receipt;
static WendyComNetConfig saved;
/* Own explicit management settings only. Peer material is never persisted. */
struct record {
    uint32_t magic, flags, links, ble, wifi, nan;
};
#define SETTINGS_MAGIC UINT32_C(0x574e5301)
static bool psram(void)
{
    return heap_caps_get_total_size(MALLOC_CAP_SPIRAM) > 0;
}
static bool same_base(const WendyComNetConfig *a, const WendyComNetConfig *b)
{
    return a->enabled == b->enabled && a->ble == b->ble && a->nan == b->nan &&
           a->infrastructure_wifi == b->infrastructure_wifi && a->max_links == b->max_links &&
           a->ble_links == b->ble_links && a->wifi_links == b->wifi_links &&
           a->nan_links == b->nan_links && a->ble_profile == b->ble_profile;
}
static bool apply_espnow_only;
static bool same_espnow(const WendyComNetConfig *a, const WendyComNetConfig *b)
{
    return a->espnow == b->espnow && a->espnow_channel == b->espnow_channel &&
           a->espnow_links == b->espnow_links && a->espnow_rate == b->espnow_rate;
}
static esp_err_t normalize(WendyComNetConfig *c)
{
    if ((unsigned)c->ble_profile > WendyComBleProfile_WENDY_COM_BLE_CODED_S8 ||
        (c->ble_profile && !CODED_PROFILES_SUPPORTED))
        return ESP_ERR_NOT_SUPPORTED;
    c->has_espnow = c->has_espnow_channel = c->has_espnow_links = true;
    c->has_espnow_rate = true;
    if (!c->espnow_rate)
        c->espnow_rate = WendyComEspnowRate_WENDY_COM_ESPNOW_RATE_12_MBPS;
    if (!wn_espnow_rate_valid(c->espnow_rate))
        return ESP_ERR_INVALID_ARG;
    if (!c->espnow_channel)
        c->espnow_channel = 1;
    if (!c->espnow_links)
        c->espnow_links = WENDY_NET_NON_TRANSIT ? 1 : 3;
    if (c->espnow_channel > 14 || c->espnow_links > (WENDY_NET_NON_TRANSIT ? 1u : 3u))
        return ESP_ERR_INVALID_ARG;
    if (c->espnow && !wn_espnow_supported())
        return ESP_ERR_NOT_SUPPORTED;
    if (!c->max_links)
        c->max_links = WENDY_NET_NON_TRANSIT ? 1 : CONFIG_WENDY_NET_MAX_LINKS;
    if (!c->ble_links)
        c->ble_links = c->max_links < CONFIG_WENDY_NET_BLE_CHANNELS ? c->max_links
                                                                    : CONFIG_WENDY_NET_BLE_CHANNELS;
    if (!c->wifi_links)
        c->wifi_links = c->max_links;
    if (!c->nan_links)
        c->nan_links = 1;
    if (c->max_links > CONFIG_WENDY_NET_MAX_LINKS || c->ble_links > CONFIG_WENDY_NET_BLE_CHANNELS ||
        c->wifi_links > CONFIG_WENDY_NET_MAX_LINKS || c->nan_links > 1)
        return ESP_ERR_INVALID_ARG;
    if (WENDY_NET_NON_TRANSIT &&
        (c->max_links != 1 || c->ble_links > 1 || c->wifi_links > 1 || c->nan_links > 1 ||
         (unsigned)c->ble + (unsigned)c->infrastructure_wifi + (unsigned)c->nan + (unsigned)c->espnow > 1))
        return ESP_ERR_NOT_SUPPORTED;
    if ((c->ble && !CONFIG_WENDY_NET_BLE) || c->nan ||
        (c->infrastructure_wifi && !CONFIG_WENDY_WIFI_ENABLED))
        return ESP_ERR_NOT_SUPPORTED;
    if (c->enabled && !c->ble && !c->infrastructure_wifi && !c->espnow)
        return ESP_ERR_INVALID_ARG;
    return ESP_OK;
}
WendyComNetConfig wn_settings_get(void)
{
    pthread_mutex_lock(&lock);
    WendyComNetConfig c = saved;
    pthread_mutex_unlock(&lock);
    return c;
}
static WendyComResult get(WendyComNetStatus *status)
{
    *status = (WendyComNetStatus)WendyComNetStatus_init_zero;
    status->has_desired = true;
    status->desired = wn_settings_get();
    status->ble_supported = CONFIG_WENDY_NET_BLE;
    status->has_espnow_supported = true;
    status->espnow_supported = wn_espnow_supported();
    status->ble_profiles_supported =
        CONFIG_WENDY_NET_BLE ? (CODED_PROFILES_SUPPORTED ? 7u : 1u) : 0u;
    status->wifi_supported = CONFIG_WENDY_WIFI_ENABLED;
    /* NAN runtime has not joined the two-task driver in this delivery. */
    status->nan_supported = false;
    status->psram = psram();
    status->restarting = wn_settings_restarting();
    wn_peer_runtime_status(status);
    return WendyComResult_WENDY_COM_RESULT_OK;
}
esp_err_t wendy_net_peer_get_status(WendyComNetStatus *status)
{
    if (!status)
        return ESP_ERR_INVALID_ARG;
    return get(status) == WendyComResult_WENDY_COM_RESULT_OK ? ESP_OK : ESP_FAIL;
}
static WendyComResult topology(const WendyComNetTopologyParams *params,
                               WendyComNetTopologyPage *page)
{
    page->has_status = true;
    get(&page->status);
    return wn_peer_topology(params, page);
}
static void reply_complete(uint32_t token)
{
    unsigned expected = token << 1;
    (void)atomic_compare_exchange_strong_explicit(&receipt, &expected, expected | 1u,
                                                  memory_order_release, memory_order_relaxed);
}
static WendyComResult set(const WendyComNetConfig *input, WendyComNetStatus *status,
                          uint32_t *token)
{
    *token = 0;
    WendyComNetConfig config = *input;
    get(status);
    if (!config.has_espnow)
        config.espnow = status->desired.espnow;
    if (!config.has_espnow_channel)
        config.espnow_channel = status->desired.espnow_channel;
    if (!config.has_espnow_links)
        config.espnow_links = status->desired.espnow_links;
    if (!config.has_espnow_rate)
        config.espnow_rate = status->desired.espnow_rate;
    WendyComResult rejected = WendyComResult_WENDY_COM_RESULT_OK;
    if (config.infrastructure_wifi && !status->wifi_supported)
        rejected = WendyComResult_WENDY_COM_RESULT_NET_NO_WIFI;
    else if (config.ble && !status->ble_supported)
        rejected = WendyComResult_WENDY_COM_RESULT_NET_NO_BLE;
    else if ((unsigned)config.ble_profile > WendyComBleProfile_WENDY_COM_BLE_CODED_S8 ||
             (config.ble_profile && !CODED_PROFILES_SUPPORTED))
        rejected = WendyComResult_WENDY_COM_RESULT_NET_BLE_PROFILE_UNSUPPORTED;
    else if (config.espnow && !status->espnow_supported)
        rejected = WendyComResult_WENDY_COM_RESULT_NET_NO_ESPNOW;
    else if (config.nan)
        rejected = WendyComResult_WENDY_COM_RESULT_NET_NO_NAN;
    else if (WENDY_NET_NON_TRANSIT &&
             (config.max_links > 1 || config.ble_links > 1 || config.wifi_links > 1 ||
              config.nan_links > 1 ||
              (unsigned)config.ble + (unsigned)config.infrastructure_wifi + (unsigned)config.espnow > 1))
        rejected = WendyComResult_WENDY_COM_RESULT_NET_ONE_CARRIER_ONLY;
    if (rejected != WendyComResult_WENDY_COM_RESULT_OK) {
        status->error_code = ESP_ERR_NOT_SUPPORTED;
        return rejected;
    }
    esp_err_t result = normalize(&config);
    if (result != ESP_OK) {
        status->error_code = (uint32_t)result;
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    }
    pthread_mutex_lock(&lock);
    if (apply.token || atomic_load(&restarting)) {
        pthread_mutex_unlock(&lock);
        get(status);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    bool unchanged_base = same_base(&config, &saved);
    if (!unchanged_base || !same_espnow(&config, &saved)) {
        struct record r = {SETTINGS_MAGIC,
                           (config.enabled ? 1u : 0) | (config.ble ? 2u : 0) |
                               (config.infrastructure_wifi ? 4u : 0) |
                               ((unsigned)config.ble_profile << 4) |
                               (config.espnow ? 64u : 0u) |
                               (config.espnow_channel << 8) | (config.espnow_links << 12) |
                               ((uint32_t)config.espnow_rate << 14),
                           config.max_links,
                           config.ble_links,
                           config.wifi_links,
                           config.nan_links};
        nvs_handle_t h;
        result = nvs_open_from_partition("wendy_pki", "net-settings", NVS_READWRITE, &h);
        if (result == ESP_OK) {
            result = nvs_set_blob(h, "config3", &r, sizeof r);
            if (result == ESP_OK)
                result = nvs_commit(h);
            nvs_close(h);
        }
        if (result == ESP_OK) {
            apply_espnow_only = unchanged_base;
            saved = config;
            atomic_store(&restarting,
                         boot_selected &&
                             (config.ble != boot_ble || config.infrastructure_wifi != boot_wifi ||
                              (unsigned)config.ble_profile != boot_profile));
            *token = wnsa_begin(&apply, esp_timer_get_time());
            atomic_store(&receipt, *token << 1);
            atomic_store(&awaiting_reply, true);
        }
    }
    pthread_mutex_unlock(&lock);
    get(status);
    status->error_code = (uint32_t)result;
    if (result != ESP_OK)
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    return wn_settings_restarting() ? WendyComResult_WENDY_COM_RESULT_APPLIED_RESTARTING
                                    : WendyComResult_WENDY_COM_RESULT_OK;
}
void wn_settings_poll(bool network_drained)
{
    /* The higher-priority actor must never wait behind a management NVS write. */
    if (pthread_mutex_trylock(&lock))
        return;
    int64_t now = esp_timer_get_time();
    if (apply.token &&
        atomic_load_explicit(&receipt, memory_order_acquire) == ((apply.token << 1) | 1u))
        wnsa_reply(&apply, apply.token, now);
    bool live = apply_espnow_only;
    bool ready = wnsa_poll(&apply, now, network_drained);
    if (ready) {
        atomic_store(&receipt, 0);
        atomic_store(&awaiting_reply, false);
        atomic_store(&restart_ready, atomic_load(&restarting));
    }
    pthread_mutex_unlock(&lock);
    if (ready && !live)
        wn_peer_configuration_changed();
}
bool wn_settings_pending(void)
{
    return atomic_load(&awaiting_reply);
}
bool wn_settings_restarting(void)
{
    return atomic_load(&restarting);
}
bool wn_settings_restart_due(void)
{
    return atomic_load(&restart_ready);
}
esp_err_t wn_settings_init(void)
{
    esp_err_t ready = nvs_flash_init_partition("wendy_pki");
    if (ready != ESP_OK)
        return ready;
    pthread_mutex_lock(&lock);
    if (!loaded) {
        saved = (WendyComNetConfig){.ble = CONFIG_WENDY_NET_BLE && !WENDY_NET_NON_TRANSIT,
                                    .infrastructure_wifi = CONFIG_WENDY_WIFI_ENABLED};
        (void)normalize(&saved);
        nvs_handle_t h;
        if (nvs_open_from_partition("wendy_pki", "net-settings", NVS_READONLY, &h) == ESP_OK) {
            struct record r;
            size_t size = sizeof r;
            unsigned valid_flags = 0x7ff7fu;
            esp_err_t result = nvs_get_blob(h, "config3", &r, &size);
            if (result == ESP_ERR_NVS_NOT_FOUND) {
                size = sizeof r;
                valid_flags = 0x3f7fu;
                result = nvs_get_blob(h, "config2", &r, &size);
            }
            if (result == ESP_ERR_NVS_NOT_FOUND) {
                size = sizeof r;
                valid_flags = 0x3fu;
                result = nvs_get_blob(h, "config", &r, &size);
            }
            if (result == ESP_OK && size == sizeof r &&
                r.magic == SETTINGS_MAGIC && !(r.flags & ~valid_flags)) {
                WendyComNetConfig c = {.enabled = (r.flags & 1) != 0,
                                       .ble = (r.flags & 2) != 0,
                                       .infrastructure_wifi = (r.flags & 4) != 0,
                                       .nan = (r.flags & 8) != 0,
                                       .ble_profile = (WendyComBleProfile)((r.flags >> 4) & 3u),
                                       .max_links = r.links,
                                       .ble_links = r.ble,
                                       .wifi_links = r.wifi,
                                       .nan_links = r.nan,
                                       .espnow = (r.flags & 64u) != 0,
                                       .espnow_channel = (r.flags >> 8) & 15u,
                                       .espnow_links = (r.flags >> 12) & 3u,
                                       .espnow_rate = (r.flags >> 14) & 31u};
                if (normalize(&c) == ESP_OK)
                    saved = c;
                else
                    ESP_LOGW("net-settings",
                             "saved policy unsupported by this firmware; mesh starts disabled");
            }
            nvs_close(h);
        }
        loaded = true;
    }
    pthread_mutex_unlock(&lock);
    static const struct wcom_net_delegate delegate = {.get = get,
                                                      .set = set,
                                                      .reply_complete = reply_complete,
                                                      .topology = topology,
                                                      .topology_release = wnt_page_release};
    wcom_cmd_set_net_delegate(&delegate);
    return ESP_OK;
}
esp_err_t wendy_net_peer_boot_radios(bool *ble, bool *wifi)
{
    if (!ble || !wifi)
        return ESP_ERR_INVALID_ARG;
    esp_err_t result = wn_settings_init();
    if (result != ESP_OK)
        return result;
    pthread_mutex_lock(&lock);
    boot_ble = saved.ble;
    boot_wifi = saved.infrastructure_wifi;
    boot_selected = true;
    boot_profile = (unsigned)saved.ble_profile;
#if CONFIG_WENDY_NET_BLE
    wble_mesh_set_profile(boot_profile);
#endif
    *ble = boot_ble;
    /* Management Wi-Fi is independent of its mesh carrier setting. */
    *wifi = CONFIG_WENDY_WIFI_ENABLED;
    pthread_mutex_unlock(&lock);
    return ESP_OK;
}

bool wn_settings_try_espnow(WendyComNetConfig *config)
{
    if (pthread_mutex_trylock(&lock))
        return false;
    bool ready = !apply.token && !atomic_load(&restarting);
    if (ready) {
        config->espnow = saved.espnow;
        config->espnow_channel = saved.espnow_channel;
        config->espnow_links = saved.espnow_links;
        config->espnow_rate = saved.espnow_rate;
    }
    pthread_mutex_unlock(&lock);
    return ready;
}
