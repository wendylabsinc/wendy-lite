#include "wendy_wifi.h"

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mdns.h"
#include "esp_mac.h"
#include "wendy_com.h"
#include "wendy_server.h"
#include "wendy_conf.h"
#if CONFIG_WENDY_MESH_LEAF

#endif

#if CONFIG_WENDY_CLOUD
#include "wendy_cloud.h"
#endif

#include <ctype.h>

#include "lwip/sockets.h"
#include "lwip/netdb.h"

static const char *TAG = "wendy_wifi";
ESP_EVENT_DEFINE_BASE(WENDY_WIFI_CONTROL_EVENT);

#define NVS_NAMESPACE  "wendy_prov"
#define NVS_KEY_SSID   "ssid"
#define NVS_KEY_PASS   "pass"

/* ── State ──────────────────────────────────────────────────────────── */

static EventGroupHandle_t s_wifi_events;
static bool s_infra_initialized = false;
static atomic_bool s_connected;
static TaskHandle_t s_services_task;
static pthread_mutex_t s_services_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_station_lock = PTHREAD_MUTEX_INITIALIZER;
static bool s_mdns_initialized, s_mdns_started, s_server_started;
#if CONFIG_WENDY_CLOUD
static bool s_cloud_started;
#endif

static void services_task(void *unused);

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1
#define WIFI_QUIESCED_BIT   BIT2

#define WIFI_MAX_RETRIES    5
#define WIFI_RETRY_DELAY_MS 10000
#define WIFI_QUIESCE_TIMEOUT_MS 5000
static int s_retry_count = 0;
static atomic_bool s_connect_requested;
static atomic_bool s_reconnect_pending;
static atomic_bool s_handoff_pending;
static wifi_config_t s_handoff_config; // Protected by s_station_lock.
static uint32_t s_request_generation, s_next_drain_id;
static atomic_int s_quiesced_id = -1;

static void connect_station(void)
{
    if (!s_connect_requested || s_connected) return;
    pthread_mutex_lock(&s_station_lock);
    if (!s_connect_requested || s_connected) {
        pthread_mutex_unlock(&s_station_lock);
        return;
    }
    esp_err_t err = esp_wifi_connect();
    if (err != ESP_OK && s_connect_requested && !s_connected) {
        ESP_LOGW(TAG, "WiFi connect request failed: %s; retrying in %d ms",
                 esp_err_to_name(err), WIFI_RETRY_DELAY_MS);
        s_reconnect_pending = true;
        xTaskNotifyGive(s_services_task);
    }
    pthread_mutex_unlock(&s_station_lock);
}

/* ── WiFi event handler ────────────────────────────────────────────── */

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WENDY_WIFI_CONTROL_EVENT) {
        s_quiesced_id = event_id;
        xEventGroupSetBits(s_wifi_events, WIFI_QUIESCED_BIT);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        const wifi_event_sta_connected_t *event = event_data;
        if (event) {
            ESP_LOGI(TAG, "WiFi associated: channel=%u authmode=%u",
                     (unsigned)event->channel, (unsigned)event->authmode);
        }
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *event = event_data;
        ESP_LOGW(TAG, "WiFi disconnected: reason=%u rssi=%d",
                 event ? (unsigned)event->reason : 0,
                 event ? (int)event->rssi : 0);
        s_connected = false;
        xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT);
        if (s_connect_requested && s_retry_count < WIFI_MAX_RETRIES) {
            s_retry_count++;
            ESP_LOGI(TAG, "retrying WiFi connection (%d/%d)", s_retry_count, WIFI_MAX_RETRIES);
            connect_station();
        } else {
            xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
            s_reconnect_pending = s_connect_requested;
            if (s_connect_requested) {
                ESP_LOGW(TAG, "WiFi unavailable after %d retries; retrying in %d ms",
                         WIFI_MAX_RETRIES, WIFI_RETRY_DELAY_MS);
            }
        }
        xTaskNotifyGive(s_services_task);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        if (!s_connect_requested) return;
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "connected, IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_count = 0;
        s_reconnect_pending = false;
        s_connected = true;
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
        // DHCP may complete after the synchronous connection wait timed out.
        // Keep service startup and its retries off the system event task.
        xTaskNotifyGive(s_services_task);
    }
}

/* ── WiFi infrastructure init (one-time, idempotent) ───────────────── */

static esp_err_t wifi_infra_init(void)
{
    if (s_infra_initialized) return ESP_OK;

    s_wifi_events = xEventGroupCreate();
    if (!s_wifi_events) return ESP_ERR_NO_MEM;
    if (!s_services_task &&
        xTaskCreate(services_task, "wifi_services", 4096, NULL, 5,
                    &s_services_task) != pdPASS) {
        vEventGroupDelete(s_wifi_events);
        s_wifi_events = NULL;
        return ESP_ERR_NO_MEM;
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    esp_event_handler_instance_t instance_control;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WENDY_WIFI_CONTROL_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_control));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    s_infra_initialized = true;
    return ESP_OK;
}

/* ── WiFi connect (configure + start + block until result) ─────────── */

static esp_err_t retry_handoff_later(uint32_t request, const char *step, esp_err_t err)
{
    pthread_mutex_lock(&s_station_lock);
    if (request == s_request_generation) {
        ESP_LOGW(TAG, "WiFi handoff %s failed: %s; retrying in %d ms",
                 step, esp_err_to_name(err), WIFI_RETRY_DELAY_MS);
        s_handoff_pending = true;
        xTaskNotifyGive(s_services_task);
    }
    pthread_mutex_unlock(&s_station_lock);
    return err;
}

static esp_err_t wait_for_drain(int32_t id)
{
    TickType_t started = xTaskGetTickCount();
    TickType_t timeout = pdMS_TO_TICKS(WIFI_QUIESCE_TIMEOUT_MS);
    TickType_t remaining = timeout;
    for (;;) {
        EventBits_t bits = xEventGroupWaitBits(s_wifi_events, WIFI_QUIESCED_BIT,
            pdTRUE, pdFALSE, remaining);
        if ((bits & WIFI_QUIESCED_BIT) && s_quiesced_id == id) return ESP_OK;
        TickType_t elapsed = xTaskGetTickCount() - started;
        if (!(bits & WIFI_QUIESCED_BIT) || elapsed >= timeout) return ESP_ERR_TIMEOUT;
        remaining = timeout - elapsed;
    }
}

static esp_err_t attempt_handoff(uint32_t request)
{
    pthread_mutex_lock(&s_station_lock);
    if (request != s_request_generation) {
        pthread_mutex_unlock(&s_station_lock);
        return ESP_ERR_INVALID_STATE;
    }
    // Each retry gets a new marker: an acknowledgement arriving after a timeout
    // must never authorize a later stop/configure sequence.
    s_next_drain_id = (s_next_drain_id + 1) & INT32_MAX;
    int32_t id = (int32_t)s_next_drain_id;
    xEventGroupClearBits(s_wifi_events, WIFI_QUIESCED_BIT);
    esp_err_t err = esp_wifi_stop();
    pthread_mutex_unlock(&s_station_lock);
    if (err != ESP_OK) return retry_handoff_later(request, "stop", err);
    err = esp_event_post(WENDY_WIFI_CONTROL_EVENT, id, NULL, 0,
                         pdMS_TO_TICKS(WIFI_QUIESCE_TIMEOUT_MS));
    if (err != ESP_OK) return retry_handoff_later(request, "event post", err);
    err = wait_for_drain(id);
    if (err != ESP_OK) return retry_handoff_later(request, "event drain", err);

    pthread_mutex_lock(&s_station_lock);
    if (request != s_request_generation) {
        pthread_mutex_unlock(&s_station_lock);
        return ESP_ERR_INVALID_STATE;
    }
    s_retry_count = 0;
    xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    err = esp_wifi_set_config(WIFI_IF_STA, &s_handoff_config);
    if (err == ESP_OK) err = esp_wifi_start();
    if (err == ESP_OK) {
        s_connect_requested = true;
        ESP_LOGI(TAG, "connecting to WiFi SSID '%s'...", (char *)s_handoff_config.sta.ssid);
        ESP_LOGI(TAG, "WiFi security: minimum authmode=%u SAE PWE=%u",
                 (unsigned)s_handoff_config.sta.threshold.authmode,
                 (unsigned)s_handoff_config.sta.sae_pwe_h2e);
        memset(&s_handoff_config, 0, sizeof(s_handoff_config));
    }
    pthread_mutex_unlock(&s_station_lock);
    if (err != ESP_OK) return retry_handoff_later(request, "configure/start", err);

    // Configuration owns the first request; STA_START must not duplicate it.
    connect_station();
    return ESP_OK;
}

static esp_err_t wifi_connect(const char *ssid, const char *password)
{
    wifi_config_t wifi_config = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_OPEN,
        },
    };
    strlcpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
    if (password && strlen(password) > 0) {
        strlcpy((char *)wifi_config.sta.password, password, sizeof(wifi_config.sta.password));
        wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
    // A SensorLink camera is a continuous source: modem sleep adds beacon/DTIM
    // waits between the TLS records that carry each frame.
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
#endif

    ESP_LOGI(TAG, "connecting to WiFi SSID '%s'...", ssid);
    // Own the credentials before returning an error: the caller's buffers may
    // disappear while the worker waits for the event loop to recover.
    pthread_mutex_lock(&s_station_lock);
    uint32_t request = ++s_request_generation;
    s_handoff_config = wifi_config;
    s_handoff_pending = false;
    s_connect_requested = false;
    s_reconnect_pending = false;
    s_connected = false;
    pthread_mutex_unlock(&s_station_lock);
    esp_err_t err = attempt_handoff(request);
    if (err != ESP_OK) return err;

    EventBits_t bits = xEventGroupWaitBits(s_wifi_events,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE, pdMS_TO_TICKS(30000));
    pthread_mutex_lock(&s_station_lock);
    bool current = request == s_request_generation;
    pthread_mutex_unlock(&s_station_lock);
    if (!current) return ESP_ERR_INVALID_STATE;

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi connected");
        return ESP_OK;
    }

    ESP_LOGE(TAG, "WiFi connection failed");
    return ESP_FAIL;
}

/* ── NVS credential helpers ────────────────────────────────────────── */

static esp_err_t load_nvs_creds(char *ssid, size_t ssid_len,
                                 char *pass, size_t pass_len)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return err;

    err = nvs_get_str(nvs, NVS_KEY_SSID, ssid, &ssid_len);
    if (err != ESP_OK) {
        nvs_close(nvs);
        return err;
    }

    err = nvs_get_str(nvs, NVS_KEY_PASS, pass, &pass_len);
    if (err != ESP_OK) {
        /* Password is optional (open networks) */
        pass[0] = '\0';
    }

    nvs_close(nvs);

    if (strlen(ssid) == 0) {
        return ESP_ERR_NOT_FOUND;
    }

    return ESP_OK;
}

static esp_err_t save_nvs_creds(const char *ssid, const char *password)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    nvs_set_str(nvs, NVS_KEY_SSID, ssid);
    nvs_set_str(nvs, NVS_KEY_PASS, password ? password : "");
    nvs_commit(nvs);
    nvs_close(nvs);

    ESP_LOGI(TAG, "credentials saved to NVS");
    return ESP_OK;
}

/* ── mDNS service registration ─────────────────────────────────────── */

static esp_err_t start_mdns_service(void)
{
    char hostname[CONFIG_WENDY_DEVICE_NAME_BUF_SIZE];
    size_t out = 0;
    // On WendyOS, we prefix the hostname with "wendyos-".
    // Here, we want to mimic this behavior, but want to use a different prefix.
    // This prefix should not be longer than "wendyos-" in order to not
    // overconstrain the hostname length. So we choose "wendylt-".
    const char prefix[] = "wendylt-";
    assert(sizeof(prefix) < sizeof(hostname));
    memcpy(hostname + out, prefix, sizeof(prefix) - 1);
    out += sizeof(prefix) - 1;
    const char *device_name = wendy_conf_get_resolved_device_name();
    for (size_t in = 0; device_name[in] && out < sizeof(hostname) - 1; in++) {
        unsigned char c = (unsigned char)device_name[in];
        if (c >= 'A' && c <= 'Z') {
            hostname[out++] = (char)(c + 32);
        } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
            hostname[out++] = (char)c;
        } else if (c == '_' || c == '.') {
            hostname[out++] = '-';
        }
        /* drop everything else */
    }
    hostname[out] = '\0';
    ESP_LOGI(TAG, "mDNS hostname: '%s'", hostname);

    esp_err_t err;
    if (!s_mdns_initialized) {
        err = mdns_init();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "mDNS init failed: %s", esp_err_to_name(err));
            return err;
        }
        s_mdns_initialized = true;
    }

    err = mdns_hostname_set(hostname);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS hostname set failed: %s", esp_err_to_name(err));
        return err;
    }

    return ESP_OK;
}

/* ── Start network services after an IP address is available ─────── */

static bool start_services(void)
{
    pthread_mutex_lock(&s_services_lock);
    if (!s_connected) {
        pthread_mutex_unlock(&s_services_lock);
        return true;
    }
    if (!s_mdns_started)
        s_mdns_started = start_mdns_service() == ESP_OK;
    bool ready = s_mdns_started;

    // Initialize the mTLS server accessible via the local network
    if (!s_server_started) {
        wendy_server_start();
        s_server_started = true;
    }

    // Initialize the mTLS server accessible via the cloud
#if CONFIG_WENDY_CLOUD
    if (!s_cloud_started && wendy_conf_has_enrollment()) {
        esp_err_t err = wendy_cloud_start();
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "cloud start failed: %s", esp_err_to_name(err));
            ready = false;
        } else {
            s_cloud_started = true;
        }
    }
#endif

    pthread_mutex_unlock(&s_services_lock);
    return ready;
}

static void services_task(void *unused)
{
    (void)unused;
    for (;;) {
        TickType_t wait = s_handoff_pending ||
            (s_connect_requested && !s_connected && s_reconnect_pending)
            ? pdMS_TO_TICKS(WIFI_RETRY_DELAY_MS) : portMAX_DELAY;
        uint32_t notified = ulTaskNotifyTake(pdTRUE, wait);
        // A fresh event restarts the delay. Never reconnect from the system
        // event task after the initial burst, or while shutting down.
        if (!notified && wait != portMAX_DELAY) {
            pthread_mutex_lock(&s_station_lock);
            bool handoff = atomic_exchange(&s_handoff_pending, false);
            uint32_t request = s_request_generation;
            pthread_mutex_unlock(&s_station_lock);
            if (handoff) {
                attempt_handoff(request);
            } else if (atomic_exchange(&s_reconnect_pending, false)) {
                ESP_LOGI(TAG, "retrying WiFi connection after backoff");
                connect_station();
            }
        }
        while (s_connected) {
            if (start_services()) break;
            // Retry resource failures without needing another WiFi event.
            ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(5000));
        }
    }
}

/* ── Public API ─────────────────────────────────────────────────────── */

esp_err_t wendy_wifi_init(void)
{
    esp_err_t err = wifi_infra_init();
    if (err != ESP_OK) return err;

    /* Try NVS credentials first */
    char ssid[33] = {0};
    char pass[65] = {0};

    if (load_nvs_creds(ssid, sizeof(ssid), pass, sizeof(pass)) == ESP_OK) {
        ESP_LOGI(TAG, "found NVS credentials for SSID '%s'", ssid);
        err = wifi_connect(ssid, pass);
        if (err == ESP_OK) {
            return ESP_OK;
        }
        ESP_LOGW(TAG, "NVS credentials failed");
    }

    /* Get credential from wendy-conf partition */
    struct wendy_conf_span ssid_span = wendy_conf_get_network_ssid();
    struct wendy_conf_span pass_span = wendy_conf_get_network_password();
    if (ssid_span.size > 0) {
        ESP_LOGI(TAG, "found wendy-conf credentials");
        if (ssid_span.size >= sizeof(ssid) || pass_span.size >= sizeof(pass)) {
            ESP_LOGW(TAG, "wendy-conf credentials too long, skipping");
        } else {
            memcpy(ssid, ssid_span.data, ssid_span.size);
            ssid[ssid_span.size] = '\0';
            memcpy(pass, pass_span.data, pass_span.size);
            pass[pass_span.size] = '\0';
            ESP_LOGI(TAG, "using wendy-conf SSID '%s'", ssid);
            err = wifi_connect(ssid, pass);
            if (err == ESP_OK) {
                return ESP_OK;
            }
        }
        ESP_LOGW(TAG, "wendy-conf credentials failed");
    }

    /* Fall back to compile-time config */
    if (strlen(CONFIG_WENDY_WIFI_SSID) > 0) {
        ESP_LOGI(TAG, "using compile-time SSID '%s'", CONFIG_WENDY_WIFI_SSID);
        err = wifi_connect(CONFIG_WENDY_WIFI_SSID, CONFIG_WENDY_WIFI_PASSWORD);
        if (err == ESP_OK) {
            return ESP_OK;
        }
        return ESP_FAIL;
    }

    ESP_LOGW(TAG, "no WiFi credentials available");
    return WENDY_WIFI_ERR_NO_CREDS;
}

esp_err_t wendy_wifi_try_connect(const char *ssid, const char *password)
{
    if (!ssid || strlen(ssid) == 0) return ESP_ERR_INVALID_ARG;

    esp_err_t err = wifi_infra_init();
    if (err != ESP_OK) return err;

    err = wifi_connect(ssid, password);
    if (err != ESP_OK) return err;

    /* Persist on success */
    save_nvs_creds(ssid, password);

    return ESP_OK;
}

bool wendy_wifi_is_connected(void)
{
    return s_connected;
}

void wendy_wifi_deinit(void)
{
    s_connect_requested = false;
    s_reconnect_pending = false;
    s_connected = false;
    pthread_mutex_lock(&s_station_lock);
    ++s_request_generation;
    s_handoff_pending = false;
    memset(&s_handoff_config, 0, sizeof(s_handoff_config));
    s_connect_requested = false;
    s_reconnect_pending = false;
    s_connected = false;
    esp_wifi_stop();
    esp_wifi_deinit();
    pthread_mutex_unlock(&s_station_lock);
    if (s_services_task) xTaskNotifyGive(s_services_task);
    pthread_mutex_lock(&s_services_lock);
    mdns_free();
    s_mdns_initialized = s_mdns_started = false;
    pthread_mutex_unlock(&s_services_lock);
}

#if CONFIG_WENDY_MESH_ESPNOW
esp_err_t wendy_wifi_mesh_radio_start(uint8_t channel)
{
    if (!channel || channel > 14 || !s_infra_initialized) return ESP_ERR_INVALID_STATE;
    if (s_connect_requested) {
        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK || ap.primary != channel)
            return ESP_ERR_INVALID_STATE;
        return ESP_OK;
    }
    esp_err_t err = esp_wifi_start();
    if (err != ESP_OK) return err;
    return esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}
#endif
