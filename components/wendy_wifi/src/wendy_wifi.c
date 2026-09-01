#include "wendy_wifi.h"

#include <string.h>
#include <stdlib.h>

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

#if CONFIG_WENDY_CLOUD
#include "wendy_cloud.h"
#endif

#include <ctype.h>

#include "lwip/sockets.h"
#include "lwip/netdb.h"

static const char *TAG = "wendy_wifi";

#define NVS_NAMESPACE  "wendy_prov"
#define NVS_KEY_SSID   "ssid"
#define NVS_KEY_PASS   "pass"

/* ── State ──────────────────────────────────────────────────────────── */

static EventGroupHandle_t s_wifi_events;
static bool s_infra_initialized = false;
static bool s_connected = false;
static bool s_services_started = false;

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1

#define WIFI_MAX_RETRIES    5
static int s_retry_count = 0;

/* ── WiFi event handler ────────────────────────────────────────────── */

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = false;
        if (s_retry_count < WIFI_MAX_RETRIES) {
            esp_wifi_connect();
            s_retry_count++;
            ESP_LOGI(TAG, "retrying WiFi connection (%d/%d)", s_retry_count, WIFI_MAX_RETRIES);
        } else {
            xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
            ESP_LOGE(TAG, "WiFi connection failed after %d retries", WIFI_MAX_RETRIES);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "connected, IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_count = 0;
        s_connected = true;
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    }
}

/* ── WiFi infrastructure init (one-time, idempotent) ───────────────── */

static esp_err_t wifi_infra_init(void)
{
    if (s_infra_initialized) return ESP_OK;

    s_wifi_events = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    s_infra_initialized = true;
    return ESP_OK;
}

/* ── WiFi connect (configure + start + block until result) ─────────── */

static esp_err_t wifi_connect(const char *ssid, const char *password)
{
    s_retry_count = 0;
    xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

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

    ESP_LOGI(TAG, "connecting to WiFi SSID '%s'...", ssid);

    EventBits_t bits = xEventGroupWaitBits(s_wifi_events,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE, pdMS_TO_TICKS(30000));

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

    esp_err_t err = mdns_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS init failed: %s", esp_err_to_name(err));
        return err;
    }

    err = mdns_hostname_set(hostname);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS hostname set failed: %s", esp_err_to_name(err));
        return err;
    }

    return ESP_OK;
}

/* ── Start mDNS + UDP listener (called after successful connect) ──── */

static void start_services(void)
{
    if (s_services_started) return;

    esp_err_t err = start_mdns_service();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mDNS initialization failed");
    }

    // Initialize the mTLS server accessible via the local network
    wendy_server_start();

    // Initialize the mTLS server accessible via the cloud
#if CONFIG_WENDY_CLOUD
    {
        esp_err_t err = wendy_cloud_start();
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "cloud start failed: %s", esp_err_to_name(err));
        }
    }
#endif

    s_services_started = true;
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
            start_services();
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
                start_services();
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
            start_services();
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

    /* Disconnect if currently connected */
    if (s_connected) {
        esp_wifi_disconnect();
        esp_wifi_stop();
        s_connected = false;
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    err = wifi_connect(ssid, password);
    if (err != ESP_OK) return err;

    /* Persist on success */
    save_nvs_creds(ssid, password);

    /* Start mDNS + UDP if not already running */
    start_services();

    return ESP_OK;
}

bool wendy_wifi_is_connected(void)
{
    return s_connected;
}

void wendy_wifi_deinit(void)
{
    mdns_free();
    esp_wifi_stop();
    esp_wifi_deinit();
    s_connected = false;
    s_services_started = false;
}
