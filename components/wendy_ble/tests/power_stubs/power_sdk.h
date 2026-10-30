#ifndef POWER_TEST_SDK_H
#define POWER_TEST_SDK_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define NVS_READONLY 0
#define NVS_READWRITE 1
typedef unsigned nvs_handle_t;
esp_err_t nvs_flash_init(void);
esp_err_t nvs_open(const char *, int, nvs_handle_t *);
esp_err_t nvs_set_blob(nvs_handle_t, const char *, const void *, size_t);
esp_err_t nvs_get_blob(nvs_handle_t, const char *, void *, size_t *);
esp_err_t nvs_commit(nvs_handle_t);
void nvs_close(nvs_handle_t);
static inline const char *esp_err_to_name(esp_err_t e) {
    (void)e;
    return "test failure";
}
#define ESP_LOGI(tag, ...) ((void)(tag))
#define ESP_LOGW(tag, ...) ((void)(tag))
#define ESP_LOGE(tag, ...) ((void)(tag))
typedef enum {
    ESP_PWR_LVL_N15,
    ESP_PWR_LVL_N12,
    ESP_PWR_LVL_N9,
    ESP_PWR_LVL_N6,
    ESP_PWR_LVL_N3,
    ESP_PWR_LVL_N0,
    ESP_PWR_LVL_P3,
    ESP_PWR_LVL_P6,
    ESP_PWR_LVL_P9,
    ESP_PWR_LVL_P12,
    ESP_PWR_LVL_P15,
    ESP_PWR_LVL_P18,
    ESP_PWR_LVL_P20
} esp_power_level_t;
typedef enum {
    ESP_BLE_ENHANCED_PWR_TYPE_DEFAULT,
    ESP_BLE_ENHANCED_PWR_TYPE_SCAN,
    ESP_BLE_ENHANCED_PWR_TYPE_INIT,
    ESP_BLE_ENHANCED_PWR_TYPE_ADV,
    ESP_BLE_ENHANCED_PWR_TYPE_CONN
} esp_ble_enhanced_power_type_t;
esp_err_t esp_ble_tx_power_set_enhanced(esp_ble_enhanced_power_type_t, uint16_t, esp_power_level_t);
esp_power_level_t esp_ble_tx_power_get_enhanced(esp_ble_enhanced_power_type_t, uint16_t);
#define BLE_HS_EALREADY 2
#define BLE_GAP_EVENT_CONNECT 1
#define BLE_GAP_EVENT_DISCONNECT 2
#define BLE_GAP_EVENT_PHY_UPDATE_COMPLETE 3
struct ble_gap_event {
    int type;
    struct {
        int status;
        uint16_t conn_handle;
    } connect;
    struct {
        struct {
            uint16_t conn_handle;
        } conn;
    } disconnect;
    struct {
        int status;
        uint16_t conn_handle;
        uint8_t tx_phy, rx_phy;
    } phy_updated;
};
struct ble_gap_event_listener {
    int registered;
};
int ble_gap_event_listener_register(struct ble_gap_event_listener *,
                                    int (*)(struct ble_gap_event *, void *), void *);
int ble_gap_read_le_phy(uint16_t, uint8_t *, uint8_t *);
struct ble_npl_event {
    void (*fn)(struct ble_npl_event *);
};
struct ble_npl_eventq {
    struct ble_npl_event *queued;
};
struct ble_npl_eventq *nimble_port_get_dflt_eventq(void);
void ble_npl_event_init(struct ble_npl_event *, void (*)(struct ble_npl_event *), void *);
void ble_npl_eventq_put(struct ble_npl_eventq *, struct ble_npl_event *);
void ble_npl_eventq_remove(struct ble_npl_eventq *, struct ble_npl_event *);
#endif
