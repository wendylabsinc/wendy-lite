/* Device-wide Bluetooth power policy. Management changes are persisted once,
 * then applied on the NimBLE host only after the command reply drains. */
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "wendy_ble.h"
#include "wendy_com_cmd.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#if CONFIG_IDF_TARGET_ESP32C5 || CONFIG_IDF_TARGET_ESP32C6
#define POWER_SUPPORTED 1
#include "esp_bt.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "nimble/nimble_port.h"
#else
#define POWER_SUPPORTED 0
#endif
static const char *TAG = "bt-power";
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static WendyComBluetoothPowerStatus state;
/* Active controller policy changes only after the reply barrier. */
static WendyComBluetoothPowerConfig active;
static bool saving;
static uint8_t advertising_sets = 1; /* Set zero belongs to management/mesh. */
static pthread_once_t initialized = PTHREAD_ONCE_INIT;
static atomic_bool online;
static unsigned token_counter, waiting_token;
static const int8_t levels[] = {-15, -12, -9, -6, -3, 0, 3, 6, 9, 12, 15, 18, 20};
struct record {
    uint32_t magic;
    int32_t adv_mode, adv_dbm, conn_mode, conn_dbm;
};
#define POWER_MAGIC UINT32_C(0x57425001)
#if POWER_SUPPORTED
static struct ble_npl_event apply_event;
static bool event_initialized;
static struct ble_gap_event_listener power_listener;
#endif
static int selected(WendyComBluetoothPowerSetting setting) {
    if (setting.mode == WendyComBluetoothPowerMode_WENDY_COM_BT_POWER_MAXIMUM)
        return 20;
    if (setting.mode == WendyComBluetoothPowerMode_WENDY_COM_BT_POWER_DEFAULT) {
#ifdef CONFIG_BT_LE_DFT_TX_POWER_LEVEL_DBM_EFF
        return CONFIG_BT_LE_DFT_TX_POWER_LEVEL_DBM_EFF;
#else
        return 9;
#endif
    }
    int value = levels[0];
    for (unsigned i = 0; i < sizeof levels / sizeof levels[0]; i++)
        if (levels[i] <= setting.dbm)
            value = levels[i];
    return value;
}
static bool valid(WendyComBluetoothPowerSetting *setting) {
    if ((unsigned)setting->mode > WendyComBluetoothPowerMode_WENDY_COM_BT_POWER_DBM)
        return false;
    if (setting->mode != WendyComBluetoothPowerMode_WENDY_COM_BT_POWER_DBM) {
        setting->dbm = 0;
        return true;
    }
    return setting->dbm >= -15 && setting->dbm <= 20;
}
static bool same(const WendyComBluetoothPowerConfig *a, const WendyComBluetoothPowerConfig *b) {
    return a->advertising.mode == b->advertising.mode && a->advertising.dbm == b->advertising.dbm &&
           a->connections.mode == b->connections.mode && a->connections.dbm == b->connections.dbm;
}
static WendyComResult get(WendyComBluetoothPowerStatus *out) {
    pthread_mutex_lock(&lock);
    *out = state;
    out->available = atomic_load(&online);
    pthread_mutex_unlock(&lock);
    return WendyComResult_WENDY_COM_RESULT_OK;
}
static WendyComResult set(const WendyComBluetoothPowerConfig *input,
                          WendyComBluetoothPowerStatus *out, uint32_t *token) {
    *token = 0;
    WendyComBluetoothPowerConfig config = *input;
    if (!POWER_SUPPORTED || (!config.has_advertising && !config.has_connections) ||
        (config.has_advertising && !valid(&config.advertising)) ||
        (config.has_connections && !valid(&config.connections))) {
        get(out);
        snprintf(out->error, sizeof out->error, "Unsupported Bluetooth power setting");
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    }
    pthread_mutex_lock(&lock);
    /* Optional fields are a patch, merged while reserving this operation.
     * Independent clients cannot overwrite a field they did not supply. */
    if (!config.has_advertising)
        config.advertising = state.desired.advertising;
    if (!config.has_connections)
        config.connections = state.desired.connections;
    config.has_advertising = config.has_connections = true;
    bool busy = state.pending || waiting_token || saving;
    bool unchanged = same(&state.desired, &config) && !state.error[0] &&
                     (!atomic_load(&online) || state.has_applied);
    if (!busy && !unchanged) {
        saving = true;
        state.pending = true; /* Reserve across NVS writes and host resets. */
    }
    pthread_mutex_unlock(&lock);
    if (busy) {
        get(out);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    if (unchanged) {
        get(out);
        return WendyComResult_WENDY_COM_RESULT_OK;
    }
    struct record value = {POWER_MAGIC, config.advertising.mode, config.advertising.dbm,
                           config.connections.mode, config.connections.dbm};
    nvs_handle_t h;
    esp_err_t result = nvs_open("bt-radio", NVS_READWRITE, &h);
    if (result == ESP_OK) {
        result = nvs_set_blob(h, "power", &value, sizeof value);
        if (result == ESP_OK)
            result = nvs_commit(h);
        nvs_close(h);
    }
    if (result != ESP_OK) {
        pthread_mutex_lock(&lock);
        state.pending = false;
        saving = false;
        pthread_mutex_unlock(&lock);
        get(out);
        snprintf(out->error, sizeof out->error, "Saving Bluetooth power failed: %s",
                 esp_err_to_name(result));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }
    pthread_mutex_lock(&lock);
    state.desired = config;
    saving = false;
    if (!atomic_load(&online))
        active = config;
    state.error[0] = 0;
    state.pending = atomic_load(&online);
    if (state.pending) {
        if (!++token_counter)
            ++token_counter;
        waiting_token = token_counter;
        *token = waiting_token;
    }
    pthread_mutex_unlock(&lock);
    get(out);
    return WendyComResult_WENDY_COM_RESULT_OK;
}
#if POWER_SUPPORTED
static esp_power_level_t power_level(int dbm) {
    return dbm == 20 ? ESP_PWR_LVL_P20 : (esp_power_level_t)((int)ESP_PWR_LVL_N0 + dbm / 3);
}
static int power_dbm(esp_power_level_t level) {
    if (level == ESP_PWR_LVL_P20)
        return 20;
    if (level >= ESP_PWR_LVL_N15 && level <= ESP_PWR_LVL_P18)
        return ((int)level - (int)ESP_PWR_LVL_N0) * 3;
    return -127;
}
static int apply_controller(const WendyComBluetoothPowerConfig *config) {
    static const esp_ble_enhanced_power_type_t roles[] = {ESP_BLE_ENHANCED_PWR_TYPE_DEFAULT,
                                                          ESP_BLE_ENHANCED_PWR_TYPE_SCAN,
                                                          ESP_BLE_ENHANCED_PWR_TYPE_INIT};
    int target = selected(config->connections);
    for (unsigned i = 0; i < sizeof roles / sizeof roles[0]; i++) {
        esp_err_t result = esp_ble_tx_power_set_enhanced(roles[i], 0, power_level(target));
        int actual = power_dbm(esp_ble_tx_power_get_enhanced(roles[i], 0));
        ESP_LOGI(TAG,
                 "controller TX power: role=%u requested_dbm=%d selected_dbm=%d "
                 "result=%d",
                 (unsigned)roles[i], target, actual, (int)result);
        if (i == 0) {
            pthread_mutex_lock(&lock);
            state.connection_default_known = actual != -127;
            state.connection_default_dbm = actual;
            pthread_mutex_unlock(&lock);
        }
        if (result != ESP_OK || actual != target)
            return -1;
    }
    return 0;
}
static void apply(struct ble_npl_event *event) {
    (void)event;
    WendyComBluetoothPowerConfig desired;
    pthread_mutex_lock(&lock);
    if (saving || waiting_token || !atomic_load(&online)) {
        pthread_mutex_unlock(&lock);
        return;
    }
    desired = state.desired;
    active = desired;
    state.error[0] = 0;
    pthread_mutex_unlock(&lock);
    int result = apply_controller(&desired);
    uint16_t handles[8];
    unsigned count = 0;
    pthread_mutex_lock(&lock);
    for (unsigned i = 0; i < state.connections_count; i++)
        handles[count++] = (uint16_t)state.connections[i].handle;
    pthread_mutex_unlock(&lock);
    for (unsigned i = 0; i < count; i++)
        wendy_ble_power_connected(handles[i]);
    pthread_mutex_lock(&lock);
    if (state.error[0])
        result = -1;
    pthread_mutex_unlock(&lock);
    if (!result)
        result = wendy_ble_power_apply_advertising();
    pthread_mutex_lock(&lock);
    if (!result) {
        state.applied = desired;
        state.has_applied = true;
        state.error[0] = 0;
    } else if (!state.error[0])
        snprintf(state.error, sizeof state.error,
                 "Controller could not apply Bluetooth power; query actual values");
    if (result)
        state.has_applied = false;
    state.pending = false;
    pthread_mutex_unlock(&lock);
}
#endif
static void reply_complete(uint32_t token) {
    pthread_mutex_lock(&lock);
    bool ready = waiting_token && token == waiting_token;
    if (ready)
        waiting_token = 0;
    pthread_mutex_unlock(&lock);
#if POWER_SUPPORTED
    if (ready && atomic_load(&online))
        ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &apply_event);
#else
    (void)ready;
#endif
}
static void initialize(void) {
    state = (WendyComBluetoothPowerStatus)WendyComBluetoothPowerStatus_init_zero;
    state.has_desired = true;
    state.desired.has_advertising = state.desired.has_connections = true;
    /* Start at maximum power until an explicit policy is saved. */
    state.desired.advertising.mode = state.desired.connections.mode =
        WendyComBluetoothPowerMode_WENDY_COM_BT_POWER_MAXIMUM;
    state.advertising_set_supported = state.connections_set_supported = POWER_SUPPORTED;
    if (POWER_SUPPORTED) {
        state.supported_levels_dbm_count = sizeof levels / sizeof levels[0];
        for (unsigned i = 0; i < state.supported_levels_dbm_count; i++)
            state.supported_levels_dbm[i] = levels[i];
    }
    esp_err_t result = nvs_flash_init();
    if (result == ESP_OK) {
        nvs_handle_t h;
        if (nvs_open("bt-radio", NVS_READONLY, &h) == ESP_OK) {
            struct record value;
            size_t size = sizeof value;
            if (nvs_get_blob(h, "power", &value, &size) == ESP_OK && size == sizeof value &&
                value.magic == POWER_MAGIC) {
                WendyComBluetoothPowerConfig config = {
                    .has_advertising = true,
                    .has_connections = true,
                    .advertising = {.mode = (WendyComBluetoothPowerMode)value.adv_mode,
                                    .dbm = value.adv_dbm},
                    .connections = {.mode = (WendyComBluetoothPowerMode)value.conn_mode,
                                    .dbm = value.conn_dbm}};
                if (valid(&config.advertising) && valid(&config.connections))
                    state.desired = config;
            }
            nvs_close(h);
        }
    } else
        snprintf(state.error, sizeof state.error, "Bluetooth settings unavailable: %s",
                 esp_err_to_name(result));
    active = state.desired;
    static const struct wcom_bluetooth_power_delegate delegate = {
        .get = get, .set = set, .reply_complete = reply_complete};
    wcom_cmd_set_bluetooth_power_delegate(&delegate);
}
void wendy_ble_power_init(void) { pthread_once(&initialized, initialize); }
#if POWER_SUPPORTED
/* One host listener covers management, mesh and guest-created physical links.
 */
static int power_gap_event(struct ble_gap_event *event, void *arg) {
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (!event->connect.status)
            wendy_ble_power_connected(event->connect.conn_handle);
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        wendy_ble_power_disconnected(event->disconnect.conn.conn_handle);
        break;
    case BLE_GAP_EVENT_PHY_UPDATE_COMPLETE:
        if (!event->phy_updated.status)
            wendy_ble_power_phy_updated(event->phy_updated.conn_handle, event->phy_updated.tx_phy,
                                        event->phy_updated.rx_phy);
        break;
    default:
        break;
    }
    return 0;
}
#endif
int wendy_ble_power_host_sync(void) {
#if POWER_SUPPORTED
    /* NPL callbacks are installed by nimble_port_init, after policy init. */
    if (!event_initialized) {
        ble_npl_event_init(&apply_event, apply, NULL);
        event_initialized = true;
    }
    int listener_result = ble_gap_event_listener_register(&power_listener, power_gap_event, NULL);
    if (listener_result && listener_result != BLE_HS_EALREADY)
        return listener_result;
    WendyComBluetoothPowerConfig config;
    pthread_mutex_lock(&lock);
    /* Publishing online under the same lock makes concurrent saves reserve a
     * reply token instead of silently changing policy during host startup. */
    atomic_store(&online, true);
    if (!saving && !waiting_token) {
        active = state.desired;
        state.pending = false;
    }
    config = active;
    state.has_applied = false;
    pthread_mutex_unlock(&lock);
    if (apply_controller(&config)) {
        pthread_mutex_lock(&lock);
        snprintf(state.error, sizeof state.error,
                 "Controller could not initialize Bluetooth power");
        pthread_mutex_unlock(&lock);
        return -1;
    }
#endif
    return 0;
}
void wendy_ble_power_host_reset(void) {
#if POWER_SUPPORTED
    if (event_initialized)
        ble_npl_eventq_remove(nimble_port_get_dflt_eventq(), &apply_event);
#endif
    atomic_store(&online, false);
    pthread_mutex_lock(&lock);
    advertising_sets = 1;
    state.connections_count = 0;
    state.advertising_known = state.connection_default_known = false;
    state.has_applied = false;
    /* A USB/LAN reply may still be draining. Preserve its token, and the
     * reservation of an NVS save which runs outside this lock. */
    state.pending = saving || waiting_token != 0;
    pthread_mutex_unlock(&lock);
}
int8_t wendy_ble_power_advertising_request(void) {
    if (!POWER_SUPPORTED)
        return 127;
    pthread_mutex_lock(&lock);
    int power = selected(active.advertising);
    pthread_mutex_unlock(&lock);
    return (int8_t)power;
}
void wendy_ble_power_advertising_selected(int8_t actual) {
    pthread_mutex_lock(&lock);
    state.advertising_known = actual >= -15 && actual <= 20;
    state.advertising_dbm = actual;

    pthread_mutex_unlock(&lock);
}
void wendy_ble_power_connected(uint16_t handle) {
#if POWER_SUPPORTED
    pthread_mutex_lock(&lock);
    int target = selected(active.connections);
    pthread_mutex_unlock(&lock);
    esp_err_t result =
        esp_ble_tx_power_set_enhanced(ESP_BLE_ENHANCED_PWR_TYPE_CONN, handle, power_level(target));
    int actual = power_dbm(esp_ble_tx_power_get_enhanced(ESP_BLE_ENHANCED_PWR_TYPE_CONN, handle));
    uint8_t tx = 0, rx = 0;
    (void)ble_gap_read_le_phy(handle, &tx, &rx);
    ESP_LOGI(TAG,
             "connection TX power: handle=%u requested_dbm=%d selected_dbm=%d "
             "result=%d",
             handle, target, actual, (int)result);
    pthread_mutex_lock(&lock);
    unsigned i = 0;
    while (i < state.connections_count && state.connections[i].handle != handle)
        i++;
    if (i < 8) {
        if (i == state.connections_count)
            state.connections_count++;
        state.connections[i] = (WendyComBluetoothConnectionPower){.handle = handle,
                                                                  .current_known = actual != -127,
                                                                  .current_dbm = actual,
                                                                  .tx_phy = tx,
                                                                  .rx_phy = rx};
    }
    if (result != ESP_OK || actual != target)
        snprintf(state.error, sizeof state.error, "Connection power update failed: handle %u",
                 handle);
    pthread_mutex_unlock(&lock);
#else
    (void)handle;
#endif
}
void wendy_ble_power_disconnected(uint16_t handle) {
    pthread_mutex_lock(&lock);
    for (unsigned i = 0; i < state.connections_count; i++)
        if (state.connections[i].handle == handle) {
            for (unsigned j = i + 1; j < state.connections_count; j++)
                state.connections[j - 1] = state.connections[j];
            state.connections_count--;
            break;
        }
    pthread_mutex_unlock(&lock);
}

void wendy_ble_power_phy_updated(uint16_t handle, uint8_t tx, uint8_t rx) {
    pthread_mutex_lock(&lock);
    for (unsigned i = 0; i < state.connections_count; i++)
        if (state.connections[i].handle == handle) {
            state.connections[i].tx_phy = tx;
            state.connections[i].rx_phy = rx;
            break;
        }
    pthread_mutex_unlock(&lock);
}

static int apply_advertising_set(uint8_t instance) {
#if POWER_SUPPORTED
    int target = wendy_ble_power_advertising_request();
    esp_err_t result =
        esp_ble_tx_power_set_enhanced(ESP_BLE_ENHANCED_PWR_TYPE_ADV, instance, power_level(target));
    int actual = power_dbm(esp_ble_tx_power_get_enhanced(ESP_BLE_ENHANCED_PWR_TYPE_ADV, instance));
    if (!instance)
        wendy_ble_power_advertising_selected((int8_t)actual);
    if (result != ESP_OK || actual != target)
        return -1;
    ESP_LOGI(TAG, "advertising TX power: handle=%u requested_dbm=%d selected_dbm=%d result=%d",
             instance, target, actual, (int)result);
#else
    (void)instance;
#endif
    return 0;
}
int wendy_ble_power_advertising_add(uint8_t instance) {
    if (instance >= 8)
        return -1;
    pthread_mutex_lock(&lock);
    advertising_sets |= (uint8_t)(1u << instance);
    pthread_mutex_unlock(&lock);
    return apply_advertising_set(instance);
}
void wendy_ble_power_advertising_remove(uint8_t instance) {
    if (!instance || instance >= 8)
        return;
    pthread_mutex_lock(&lock);
    advertising_sets &= (uint8_t)~(1u << instance);
    pthread_mutex_unlock(&lock);
}
int wendy_ble_power_apply_advertising(void) {
    pthread_mutex_lock(&lock);
    uint8_t sets = advertising_sets;
    pthread_mutex_unlock(&lock);
    for (unsigned i = 0; i < 8; i++)
        if ((sets & (1u << i)) && apply_advertising_set((uint8_t)i))
            return -1;
    return 0;
}

/* Called only after the advertising owner successfully starts its set. During
 * a live change the apply event commits after all connection updates too. */
void wendy_ble_power_advertising_started(void) {
    pthread_mutex_lock(&lock);
    if (!state.pending && !state.error[0] && state.advertising_known &&
        state.connection_default_known && same(&active, &state.desired) &&
        state.advertising_dbm == selected(active.advertising) &&
        state.connection_default_dbm == selected(active.connections)) {
        state.applied = active;
        state.has_applied = true;
    }
    pthread_mutex_unlock(&lock);
}
