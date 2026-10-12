#pragma once
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#undef strlcpy
#define strlcpy test_strlcpy
#define CONFIG_WENDY_CLOUD 1
#define CONFIG_WENDY_DEVICE_NAME_BUF_SIZE 64
#define CONFIG_WENDY_WIFI_SSID ""
#define CONFIG_WENDY_WIFI_PASSWORD ""
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NOT_FOUND 0x105
#define ESP_ERROR_CHECK(expr) assert((expr) == ESP_OK)
#define ESP_LOGI(tag, ...) do { (void)(tag); if (0) printf(__VA_ARGS__); } while (0)
#define ESP_LOGW(tag, ...) ESP_LOGI(tag, __VA_ARGS__)
#define ESP_LOGE(tag, ...) ESP_LOGI(tag, __VA_ARGS__)
const char *esp_err_to_name(esp_err_t error);
typedef uint32_t EventBits_t;
typedef uint32_t TickType_t;
typedef void *EventGroupHandle_t;
typedef void *TaskHandle_t;
#define BIT0 1u
#define BIT1 2u
#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
#define portMAX_DELAY UINT32_MAX
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
EventGroupHandle_t xEventGroupCreate(void);
void vEventGroupDelete(EventGroupHandle_t group);
EventBits_t xEventGroupClearBits(EventGroupHandle_t group, EventBits_t bits);
EventBits_t xEventGroupSetBits(EventGroupHandle_t group, EventBits_t bits);
EventBits_t xEventGroupWaitBits(EventGroupHandle_t group, EventBits_t bits, int clear, int all, TickType_t ticks);
int xTaskCreate(void (*task)(void *), const char *name, unsigned stack, void *arg, unsigned priority, TaskHandle_t *handle);
void xTaskNotifyGive(TaskHandle_t task);
uint32_t ulTaskNotifyTake(int clear, TickType_t ticks);
void vTaskDelay(TickType_t ticks);
typedef const char *esp_event_base_t;
extern const char wifi_event_base[], ip_event_base[];
#define WIFI_EVENT wifi_event_base
#define IP_EVENT ip_event_base
#define ESP_EVENT_ANY_ID -1
#define WIFI_EVENT_STA_START 1
#define WIFI_EVENT_STA_DISCONNECTED 2
#define IP_EVENT_STA_GOT_IP 3
typedef void *esp_event_handler_instance_t;
typedef struct { struct { uint32_t ip; } ip_info; } ip_event_got_ip_t;
#define IPSTR "%u"
#define IP2STR(ip) (*(ip))
esp_err_t esp_event_loop_create_default(void);
esp_err_t esp_event_handler_instance_register(esp_event_base_t base, int32_t id,
    void (*handler)(void *, esp_event_base_t, int32_t, void *), void *arg,
    esp_event_handler_instance_t *instance);
esp_err_t esp_netif_init(void);
void *esp_netif_create_default_wifi_sta(void);
typedef struct { int unused; } wifi_init_config_t;
typedef struct { struct { unsigned char ssid[32], password[64]; struct { int authmode; } threshold; } sta; } wifi_config_t;
#define WIFI_INIT_CONFIG_DEFAULT() ((wifi_init_config_t){0})
#define WIFI_AUTH_OPEN 0
#define WIFI_AUTH_WPA2_PSK 1
#define WIFI_MODE_STA 0
#define WIFI_IF_STA 0
esp_err_t esp_wifi_init(const wifi_init_config_t *config);
esp_err_t esp_wifi_connect(void);
esp_err_t esp_wifi_disconnect(void);
esp_err_t esp_wifi_set_mode(int mode);
esp_err_t esp_wifi_set_config(int interface, const wifi_config_t *config);
esp_err_t esp_wifi_start(void);
esp_err_t esp_wifi_stop(void);
esp_err_t esp_wifi_deinit(void);
typedef int nvs_handle_t;
#define NVS_READONLY 0
#define NVS_READWRITE 1
esp_err_t nvs_open(const char *name, int mode, nvs_handle_t *handle);
esp_err_t nvs_get_str(nvs_handle_t handle, const char *name, char *out, size_t *size);
esp_err_t nvs_set_str(nvs_handle_t handle, const char *name, const char *value);
esp_err_t nvs_commit(nvs_handle_t handle);
void nvs_close(nvs_handle_t handle);
esp_err_t mdns_init(void);
esp_err_t mdns_hostname_set(const char *hostname);
void mdns_free(void);
void wendy_server_start(void);
esp_err_t wendy_cloud_start(void);
struct wendy_conf_span { const uint8_t *data; size_t size; };
const char *wendy_conf_get_resolved_device_name(void);
struct wendy_conf_span wendy_conf_get_network_ssid(void);
struct wendy_conf_span wendy_conf_get_network_password(void);
bool wendy_conf_has_enrollment(void);
size_t strlcpy(char *dest, const char *source, size_t size);
