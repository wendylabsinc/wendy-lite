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
#include "esp_http_client.h"
#include "esp_partition.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mdns.h"
#include "esp_mac.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

static const char *TAG = "wendy_wifi";

#define NVS_NAMESPACE  "wendy_prov"
#define NVS_KEY_SSID   "ssid"
#define NVS_KEY_PASS   "pass"

/* ── State ──────────────────────────────────────────────────────────── */

static wendy_wifi_callbacks_t s_callbacks;
static EventGroupHandle_t s_wifi_events;
static TaskHandle_t s_udp_task;
static bool s_infra_initialized = false;
static bool s_connected = false;
static bool s_services_started = false;

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1

#define WIFI_MAX_RETRIES    5
static int s_retry_count = 0;

/* Discovered server */
static char s_server_ip[64];
static uint16_t s_server_port;

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

static esp_err_t register_mdns_service(void)
{
    /* Build device name from BT MAC to match BLE advertising name */
    char device_name[32];
    char hostname[32];
    uint8_t mac[6];
    esp_err_t err = esp_read_mac(mac, ESP_MAC_BT);
    if (err != ESP_OK) {
        snprintf(device_name, sizeof(device_name), "Wendy-0000");
        snprintf(hostname, sizeof(hostname), "wendy-0000");
    } else {
        snprintf(device_name, sizeof(device_name), "Wendy-%02X%02X", mac[4], mac[5]);
        snprintf(hostname, sizeof(hostname), "wendy-%02x%02x", mac[4], mac[5]);
    }

    err = mdns_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS init failed: %s", esp_err_to_name(err));
        return err;
    }

    err = mdns_hostname_set(hostname);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS hostname set failed: %s", esp_err_to_name(err));
        return err;
    }

    err = mdns_service_add(device_name, "_wendy", "_tcp",
                           CONFIG_WENDY_WIFI_UDP_PORT, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS service add failed: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "registered mDNS service _wendy._tcp as '%s' on port %d",
             device_name, CONFIG_WENDY_WIFI_UDP_PORT);
    return ESP_OK;
}

/* ── HTTP download (streams directly to flash) ────────────────────── */

#define DL_CHUNK_SIZE 1024

static uint8_t s_dl_chunk[DL_CHUNK_SIZE];

static esp_err_t download_wasm(void)
{
    char url[128];
    snprintf(url, sizeof(url), "http://%s:%d/app.wasm", s_server_ip, s_server_port);
    ESP_LOGI(TAG, "downloading WASM from %s", url);

    esp_http_client_config_t config = {
        .url = url,
        .timeout_ms = 10000,
        .buffer_size = DL_CHUNK_SIZE,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "failed to init HTTP client");
        return ESP_FAIL;
    }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    int content_length = esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);

    if (status != 200 || content_length <= 0) {
        ESP_LOGE(TAG, "HTTP error: status=%d, content_length=%d", status, content_length);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    /* Find and erase the flash partition */
    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, 0x80, "wasm_a");
    if (!part) {
        ESP_LOGE(TAG, "wasm_a partition not found");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    if ((uint32_t)content_length + sizeof(uint32_t) > part->size) {
        ESP_LOGE(TAG, "WASM binary too large for partition (%d > %lu)",
                 content_length, (unsigned long)part->size);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "streaming %d bytes to flash...", content_length);
    esp_partition_erase_range(part, 0, part->size);

    /* Write size header first */
    uint32_t size = (uint32_t)content_length;
    esp_partition_write(part, 0, &size, sizeof(size));

    /* Stream HTTP body directly to flash, one chunk at a time */
    int flash_offset = sizeof(uint32_t);
    int total_read = 0;

    while (total_read < content_length) {
        int to_read = content_length - total_read;
        if (to_read > DL_CHUNK_SIZE) {
            to_read = DL_CHUNK_SIZE;
        }

        int read_len = esp_http_client_read(client, (char *)s_dl_chunk, to_read);
        if (read_len <= 0) {
            ESP_LOGE(TAG, "HTTP read error at offset %d", total_read);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            return ESP_FAIL;
        }

        esp_partition_write(part, flash_offset, s_dl_chunk, read_len);
        flash_offset += read_len;
        total_read += read_len;
    }

    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    ESP_LOGI(TAG, "downloaded %d bytes to flash", total_read);

    /* Notify callback — pass NULL data, caller loads from flash */
    if (s_callbacks.on_upload_complete) {
        s_callbacks.on_upload_complete(NULL, (uint32_t)total_read, 0);
    }

    return ESP_OK;
}

/* ── UDP listener task ─────────────────────────────────────────────── */

static void udp_listener_task(void *arg)
{
    ESP_LOGI(TAG, "UDP listener started on port %d", CONFIG_WENDY_WIFI_UDP_PORT);

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "failed to create UDP socket");
        vTaskDelete(NULL);
        return;
    }

    /* Allow broadcast reception */
    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    /* Allow address reuse */
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(CONFIG_WENDY_WIFI_UDP_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "failed to bind UDP socket");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    char rx_buf[64];
    for (;;) {
        struct sockaddr_in source_addr;
        socklen_t addrlen = sizeof(source_addr);
        int len = recvfrom(sock, rx_buf, sizeof(rx_buf) - 1, 0,
                           (struct sockaddr *)&source_addr, &addrlen);

        if (len > 0) {
            rx_buf[len] = '\0';

            /* Strip trailing newline/CR */
            while (len > 0 && (rx_buf[len - 1] == '\n' || rx_buf[len - 1] == '\r')) {
                rx_buf[--len] = '\0';
            }

            char parsed_ip[64];
            uint16_t parsed_port = 0;
            if (sscanf(rx_buf, "WENDY_RELOAD %63[^:]:%hu", parsed_ip, &parsed_port) == 2) {
                strlcpy(s_server_ip, parsed_ip, sizeof(s_server_ip));
                s_server_port = parsed_port;
                ESP_LOGI(TAG, "WENDY_RELOAD received, server at %s:%d", s_server_ip, s_server_port);
                download_wasm();
            } else if (strncmp(rx_buf, "WENDY_RELOAD", 12) == 0) {
                ESP_LOGW(TAG, "WENDY_RELOAD received but could not parse ip:port from '%s'", rx_buf);
            }
        }
    }
}

/* ── Start mDNS + UDP listener (called after successful connect) ──── */

static void start_services(void)
{
    if (s_services_started) return;

#if CONFIG_WENDY_CLOUD_PROV
    {
        extern bool wendy_cloud_is_provisioned(void);
        if (wendy_cloud_is_provisioned()) {
            ESP_LOGI(TAG, "cloud-provisioned: skipping UDP listener and mDNS");
            s_services_started = true;
            return;
        }
    }
#endif

    esp_err_t err = register_mdns_service();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mDNS registration failed");
    }

    BaseType_t ret = xTaskCreatePinnedToCore(
        udp_listener_task, "wendy_wifi_udp", 4096, NULL, 5,
        &s_udp_task, tskNO_AFFINITY);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "failed to create UDP listener task");
    }

    s_services_started = true;
}

/* ── Public API ─────────────────────────────────────────────────────── */

esp_err_t wendy_wifi_init(const wendy_wifi_callbacks_t *callbacks)
{
    if (callbacks) {
        s_callbacks = *callbacks;
    }

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
        ESP_LOGW(TAG, "NVS credentials failed, trying compile-time config");
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
    if (s_udp_task) {
        vTaskDelete(s_udp_task);
        s_udp_task = NULL;
    }
    mdns_free();
    esp_wifi_stop();
    esp_wifi_deinit();
    s_connected = false;
    s_services_started = false;
}
