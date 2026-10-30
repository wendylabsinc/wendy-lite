/* Compile the production policy and generated wire types; only SDK effects are
 * stubbed. Exercise reply ordering and resets at deterministic boundaries. */
#include "power_sdk.h"
#include "wendy_ble.h"
#include "wendy_com_cmd.h"
#include <assert.h>
#include <string.h>
static const struct wcom_bluetooth_power_delegate *api;
static struct ble_npl_eventq queue;
static esp_power_level_t powers[5][8];
static int unknown_role = -1;
static bool write_failure;
static void (*commit_hook)(void);
static unsigned writes;
void wcom_cmd_set_bluetooth_power_delegate(const struct wcom_bluetooth_power_delegate *p) {
    api = p;
}
esp_err_t nvs_flash_init(void) { return ESP_OK; }
esp_err_t nvs_open(const char *n, int mode, nvs_handle_t *h) {
    (void)n;
    (void)mode;
    *h = 1;
    return ESP_OK;
}
esp_err_t nvs_get_blob(nvs_handle_t h, const char *n, void *p, size_t *s) {
    (void)h;
    (void)n;
    (void)p;
    (void)s;
    return ESP_FAIL;
}
esp_err_t nvs_set_blob(nvs_handle_t h, const char *n, const void *p, size_t s) {
    (void)h;
    (void)n;
    (void)p;
    (void)s;
    writes++;
    return write_failure ? ESP_FAIL : ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t h) {
    (void)h;
    if (commit_hook) {
        void (*f)(void) = commit_hook;
        commit_hook = NULL;
        f();
    }
    return ESP_OK;
}
void nvs_close(nvs_handle_t h) { (void)h; }
esp_err_t esp_ble_tx_power_set_enhanced(esp_ble_enhanced_power_type_t role, uint16_t h,
                                        esp_power_level_t p) {
    assert(h < 8);
    powers[role][h] = p;
    return ESP_OK;
}
esp_power_level_t esp_ble_tx_power_get_enhanced(esp_ble_enhanced_power_type_t role, uint16_t h) {
    return (int)role == unknown_role ? (esp_power_level_t)255 : powers[role][h];
}
int ble_gap_event_listener_register(struct ble_gap_event_listener *p,
                                    int (*f)(struct ble_gap_event *, void *), void *a) {
    (void)f;
    (void)a;
    if (p->registered)
        return BLE_HS_EALREADY;
    p->registered = 1;
    return 0;
}
int ble_gap_read_le_phy(uint16_t h, uint8_t *tx, uint8_t *rx) {
    (void)h;
    *tx = *rx = 1;
    return 0;
}
struct ble_npl_eventq *nimble_port_get_dflt_eventq(void) { return &queue; }
void ble_npl_event_init(struct ble_npl_event *e, void (*f)(struct ble_npl_event *), void *a) {
    (void)a;
    e->fn = f;
}
void ble_npl_eventq_put(struct ble_npl_eventq *q, struct ble_npl_event *e) {
    assert(!q->queued || q->queued == e);
    q->queued = e;
}
void ble_npl_eventq_remove(struct ble_npl_eventq *q, struct ble_npl_event *e) {
    if (q->queued == e)
        q->queued = NULL;
}
static void pump(void) {
    assert(queue.queued);
    struct ble_npl_event *e = queue.queued;
    queue.queued = NULL;
    e->fn(e);
}
static WendyComBluetoothPowerConfig config(int adv, int conn) {
    return (WendyComBluetoothPowerConfig){
        .has_advertising = true,
        .has_connections = true,
        .advertising = {.mode = WendyComBluetoothPowerMode_WENDY_COM_BT_POWER_DBM, .dbm = adv},
        .connections = {.mode = WendyComBluetoothPowerMode_WENDY_COM_BT_POWER_DBM, .dbm = conn}};
}
static WendyComBluetoothPowerStatus status(void) {
    WendyComBluetoothPowerStatus s;
    assert(api->get(&s) == 0);
    return s;
}
static void reset_during_save(void) {
    wendy_ble_power_host_reset();
    uint32_t token;
    WendyComBluetoothPowerStatus s;
    WendyComBluetoothPowerConfig c = config(0, 0);
    assert(api->set(&c, &s, &token) == WendyComResult_WENDY_COM_RESULT_BUSY);
    assert(wendy_ble_power_host_sync() == 0);
    assert(status().pending);
    assert(wendy_ble_power_advertising_request() == 12);
}
int main(void) {
    wendy_ble_power_init();
    assert(api);
    assert(wendy_ble_power_host_sync() == 0);
    wendy_ble_power_advertising_selected(20);
    wendy_ble_power_advertising_started();
    assert(status().has_applied);
    WendyComBluetoothPowerStatus s;
    uint32_t token, other;
    WendyComBluetoothPowerConfig c = config(-5, 9);
    assert(api->set(&c, &s, &token) == 0 && token && s.pending);
    assert(wendy_ble_power_advertising_request() == 20);
    wendy_ble_power_connected(7);
    assert(powers[ESP_BLE_ENHANCED_PWR_TYPE_CONN][7] == ESP_PWR_LVL_P20);
    assert(api->set(&c, &s, &other) == WendyComResult_WENDY_COM_RESULT_BUSY);
    api->reply_complete(token + 1);
    assert(!queue.queued);
    api->reply_complete(token);
    pump();
    s = status();
    assert(!s.pending && s.has_applied && s.advertising_dbm == -6 && s.connection_default_dbm == 9);
    assert(powers[ESP_BLE_ENHANCED_PWR_TYPE_CONN][7] == ESP_PWR_LVL_P9);
    WendyComBluetoothPowerConfig patch = {
        .has_advertising = true,
        .advertising = {.mode = WendyComBluetoothPowerMode_WENDY_COM_BT_POWER_DBM, .dbm = -12}};
    assert(api->set(&patch, &s, &token) == 0);
    patch = (WendyComBluetoothPowerConfig){
        .has_connections = true,
        .connections = {.mode = WendyComBluetoothPowerMode_WENDY_COM_BT_POWER_DBM, .dbm = 6}};
    assert(api->set(&patch, &s, &other) == WendyComResult_WENDY_COM_RESULT_BUSY);
    api->reply_complete(token);
    pump();
    assert(api->set(&patch, &s, &token) == 0);
    api->reply_complete(token);
    pump();
    assert(status().desired.advertising.dbm == -12 && status().desired.connections.dbm == 6);
    assert(api->set(&c, &s, &token) == 0);
    api->reply_complete(token);
    pump();
    unsigned before = writes;
    assert(api->set(&c, &s, &token) == 0 && !token && writes == before);
    assert(wendy_ble_power_advertising_add(1) == 0);
    c = config(12, 3);
    assert(api->set(&c, &s, &token) == 0);
    wendy_ble_power_host_reset();
    assert(wendy_ble_power_host_sync() == 0);
    assert(status().pending);
    assert(wendy_ble_power_advertising_request() == -6);
    api->reply_complete(token);
    pump();
    assert(status().applied.advertising.dbm == 12);
    assert(wendy_ble_power_advertising_add(1) == 0);
    c = config(6, 6);
    commit_hook = reset_during_save;
    assert(api->set(&c, &s, &token) == 0 && token);
    assert(wendy_ble_power_advertising_add(1) == 0);
    api->reply_complete(token);
    pump();
    assert(status().has_applied);
    assert(powers[ESP_BLE_ENHANCED_PWR_TYPE_ADV][1] == ESP_PWR_LVL_P6);
    wendy_ble_power_advertising_remove(1);
    c = config(9, 9);
    unknown_role = ESP_BLE_ENHANCED_PWR_TYPE_CONN;
    wendy_ble_power_connected(1);
    assert(api->set(&c, &s, &token) == 0);
    api->reply_complete(token);
    pump();
    s = status();
    assert(!s.has_applied && s.error[0] && !s.connections[0].current_known);
    unknown_role = -1;
    assert(api->set(&c, &s, &token) == 0);
    api->reply_complete(token);
    pump();
    assert(status().has_applied && !status().error[0]);
    c = config(0, 0);
    assert(api->set(&c, &s, &token) == 0);
    api->reply_complete(token);
    assert(queue.queued);
    wendy_ble_power_host_reset();
    assert(!queue.queued);
    assert(wendy_ble_power_host_sync() == 0);
    wendy_ble_power_advertising_selected(0);
    wendy_ble_power_advertising_started();
    assert(status().has_applied);
    write_failure = true;
    c = config(3, 3);
    assert(api->set(&c, &s, &token) == WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR);
    assert(!status().pending && status().desired.advertising.dbm == 0);
    write_failure = false;
    c = config(-16, 0);
    before = writes;
    assert(api->set(&c, &s, &token) == WendyComResult_WENDY_COM_RESULT_BAD_STATE &&
           writes == before);
    return 0;
}
