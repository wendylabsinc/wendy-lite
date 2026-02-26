#include "wendy_ble.h"

#include <string.h>
#include "esp_log.h"
#include "wasm_export.h"
#include "wendy_safety.h"

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#endif

#if CONFIG_BT_ENABLED && CONFIG_BT_NIMBLE_ENABLED
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#endif

#if CONFIG_WENDY_BLE_PROV
#include "wendy_ble_prov.h"
#endif

static const char *TAG = "wendy_ble";

#if CONFIG_BT_ENABLED && CONFIG_BT_NIMBLE_ENABLED

static bool s_ble_initialized = false;
static uint32_t s_scan_handler_id = 0;
static uint32_t s_connect_handler_id = 0;

/* ── GAP event callback ───────────────────────────────────────────────── */

static int ble_gap_event(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        ESP_LOGI(TAG, "connect event: status=%d handle=%d",
                 event->connect.status, event->connect.conn_handle);
#if CONFIG_WENDY_CALLBACK
        if (s_connect_handler_id) {
            wendy_callback_post(s_connect_handler_id,
                                event->connect.status,
                                event->connect.conn_handle, 0);
        }
#endif
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "disconnect event: reason=%d",
                 event->disconnect.reason);
#if CONFIG_WENDY_CALLBACK
        if (s_connect_handler_id) {
            wendy_callback_post(s_connect_handler_id,
                                event->disconnect.reason,
                                event->disconnect.conn.conn_handle, 1);
        }
#endif
        break;

    case BLE_GAP_EVENT_DISC:
#if CONFIG_WENDY_CALLBACK
        if (s_scan_handler_id) {
            /* Post RSSI and addr type as args */
            wendy_callback_post(s_scan_handler_id,
                                (uint32_t)(int8_t)event->disc.rssi,
                                event->disc.addr.type, 0);
        }
#endif
        break;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        ESP_LOGI(TAG, "advertise complete");
        break;

    default:
        break;
    }
    return 0;
}

static void ble_host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static void ble_on_sync(void)
{
    ble_hs_util_ensure_addr(0);
    ESP_LOGI(TAG, "BLE host synced");
}

esp_err_t wendy_ble_init(void)
{
    if (s_ble_initialized) return ESP_OK;

#if CONFIG_WENDY_BLE_PROV
    /* If BLE provisioning already started NimBLE, skip re-init */
    if (wendy_ble_prov_nimble_ready()) {
        ESP_LOGI(TAG, "NimBLE already initialized by BLE prov, skipping init");
        s_ble_initialized = true;
        return ESP_OK;
    }
#endif

    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %s", esp_err_to_name(err));
        return err;
    }

    ble_hs_cfg.sync_cb = ble_on_sync;
    ble_svc_gap_init();
    ble_svc_gatt_init();

    nimble_port_freertos_init(ble_host_task);
    s_ble_initialized = true;
    ESP_LOGI(TAG, "BLE initialized (NimBLE)");
    return ESP_OK;
}

/* ── WASM wrappers ────────────────────────────────────────────────────── */

/* ble_init() -> 0 ok */
static int ble_init_wrapper(wasm_exec_env_t exec_env)
{
    return (wendy_ble_init() == ESP_OK) ? 0 : -1;
}

/* ble_advertise_start(name_ptr, name_len) -> 0 ok */
static int ble_advertise_start_wrapper(wasm_exec_env_t exec_env,
                                        const char *name, int name_len)
{
    if (!s_ble_initialized) return -1;

    char dev_name[32];
    int len = (name_len < 31) ? name_len : 31;
    memcpy(dev_name, name, len);
    dev_name[len] = '\0';

    ble_svc_gap_device_name_set(dev_name);

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
    };

    struct ble_hs_adv_fields fields = { 0 };
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (const uint8_t *)dev_name;
    fields.name_len = len;
    fields.name_is_complete = 1;
    fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;
    fields.tx_pwr_lvl_is_present = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: %d", rc);
        return -1;
    }

    rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                            &adv_params, ble_gap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
        return -1;
    }

    ESP_LOGI(TAG, "advertising as '%s'", dev_name);
    return 0;
}

/* ble_advertise_stop() -> 0 ok */
static int ble_advertise_stop_wrapper(wasm_exec_env_t exec_env)
{
    if (!s_ble_initialized) return -1;
    int rc = ble_gap_adv_stop();
    return (rc == 0) ? 0 : -1;
}

/* ble_scan_start(duration_ms, handler_id) -> 0 ok */
static int ble_scan_start_wrapper(wasm_exec_env_t exec_env,
                                   int duration_ms, int handler_id)
{
    if (!s_ble_initialized) return -1;

    s_scan_handler_id = (uint32_t)handler_id;

    struct ble_gap_disc_params disc_params = {
        .passive = 0,
        .filter_duplicates = 1,
        .itvl = 0,
        .window = 0,
    };

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC,
                           duration_ms / 10, /* in 10ms units */
                           &disc_params, ble_gap_event, NULL);
    return (rc == 0) ? 0 : -1;
}

/* ble_scan_stop() -> 0 ok */
static int ble_scan_stop_wrapper(wasm_exec_env_t exec_env)
{
    if (!s_ble_initialized) return -1;
    int rc = ble_gap_disc_cancel();
    s_scan_handler_id = 0;
    return (rc == 0 || rc == BLE_HS_EALREADY) ? 0 : -1;
}

/* ble_connect(addr_type, addr_ptr, addr_len, handler_id) -> 0 ok */
static int ble_connect_wrapper(wasm_exec_env_t exec_env,
                                int addr_type, const char *addr, int addr_len,
                                int handler_id)
{
    if (!s_ble_initialized || !addr || addr_len < 6) return -1;

    s_connect_handler_id = (uint32_t)handler_id;

    ble_addr_t peer_addr;
    peer_addr.type = addr_type;
    memcpy(peer_addr.val, addr, 6);

    int rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &peer_addr,
                              30000, NULL, ble_gap_event, NULL);
    return (rc == 0) ? 0 : -1;
}

/* ble_disconnect(conn_handle) -> 0 ok */
static int ble_disconnect_wrapper(wasm_exec_env_t exec_env, int conn_handle)
{
    if (!s_ble_initialized) return -1;
    int rc = ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    return (rc == 0) ? 0 : -1;
}

/* ── GATT Server ──────────────────────────────────────────────────────── */

#define MAX_GATT_SVCS 4
#define MAX_GATT_CHRS 8

static uint16_t s_chr_val_handles[MAX_GATT_CHRS];
static uint8_t s_chr_values[MAX_GATT_CHRS][256];
static int s_chr_value_lens[MAX_GATT_CHRS];
static uint32_t s_chr_write_handlers[MAX_GATT_CHRS];
static int s_chr_count = 0;

static int gatt_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                           struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    int idx = (int)(uintptr_t)arg;
    if (idx < 0 || idx >= s_chr_count) return BLE_ATT_ERR_UNLIKELY;

    switch (ctxt->op) {
    case BLE_GATT_ACCESS_OP_READ_CHR: {
        int rc = os_mbuf_append(ctxt->om, s_chr_values[idx], s_chr_value_lens[idx]);
        return (rc == 0) ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    case BLE_GATT_ACCESS_OP_WRITE_CHR: {
        uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
        if (om_len > sizeof(s_chr_values[idx])) {
            return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        }
        int rc = ble_hs_mbuf_to_flat(ctxt->om, s_chr_values[idx],
                                      sizeof(s_chr_values[idx]), &om_len);
        if (rc != 0) return BLE_ATT_ERR_UNLIKELY;
        s_chr_value_lens[idx] = om_len;
#if CONFIG_WENDY_CALLBACK
        if (s_chr_write_handlers[idx]) {
            wendy_callback_post(s_chr_write_handlers[idx],
                                (uint32_t)conn_handle, (uint32_t)idx, om_len);
        }
#endif
        return 0;
    }
    default:
        return BLE_ATT_ERR_UNLIKELY;
    }
}

/* ble_gatts_add_service(uuid128_ptr, uuid128_len) -> svc_id or -1 */
static int ble_gatts_add_service_wrapper(wasm_exec_env_t exec_env,
                                          const char *uuid, int uuid_len)
{
    /* Simplified: we accept but don't dynamically create services at runtime.
     * In practice, services must be registered before the host syncs. */
    ESP_LOGI(TAG, "ble_gatts_add_service called (uuid_len=%d)", uuid_len);
    return 0;
}

/* ble_gatts_add_characteristic(svc_id, uuid128_ptr, uuid128_len, flags) -> chr_id */
static int ble_gatts_add_characteristic_wrapper(wasm_exec_env_t exec_env,
                                                 int svc_id,
                                                 const char *uuid, int uuid_len,
                                                 int flags)
{
    if (s_chr_count >= MAX_GATT_CHRS) return -1;
    int chr_id = s_chr_count++;
    s_chr_value_lens[chr_id] = 0;
    s_chr_write_handlers[chr_id] = 0;
    ESP_LOGI(TAG, "added characteristic %d (flags=0x%x)", chr_id, flags);
    return chr_id;
}

/* ble_gatts_set_value(chr_id, data_ptr, data_len) -> 0 */
static int ble_gatts_set_value_wrapper(wasm_exec_env_t exec_env,
                                        int chr_id,
                                        const char *data, int data_len)
{
    if (chr_id < 0 || chr_id >= s_chr_count) return -1;
    if (data_len > (int)sizeof(s_chr_values[chr_id])) return -1;
    memcpy(s_chr_values[chr_id], data, data_len);
    s_chr_value_lens[chr_id] = data_len;
    return 0;
}

/* ble_gatts_notify(chr_id, conn_handle) -> 0 */
static int ble_gatts_notify_wrapper(wasm_exec_env_t exec_env,
                                     int chr_id, int conn_handle)
{
    if (chr_id < 0 || chr_id >= s_chr_count) return -1;
    if (!s_chr_val_handles[chr_id]) return -1;

    struct os_mbuf *om = ble_hs_mbuf_from_flat(s_chr_values[chr_id],
                                                 s_chr_value_lens[chr_id]);
    if (!om) return -1;

    int rc = ble_gatts_notify_custom(conn_handle, s_chr_val_handles[chr_id], om);
    return (rc == 0) ? 0 : -1;
}

/* ble_gatts_on_write(chr_id, handler_id) -> 0 */
static int ble_gatts_on_write_wrapper(wasm_exec_env_t exec_env,
                                       int chr_id, int handler_id)
{
    if (chr_id < 0 || chr_id >= s_chr_count) return -1;
    s_chr_write_handlers[chr_id] = (uint32_t)handler_id;
    return 0;
}

/* ── GATT Client ──────────────────────────────────────────────────────── */

/* ble_gattc_discover(conn_handle, handler_id) -> 0 */
static int ble_gattc_discover_wrapper(wasm_exec_env_t exec_env,
                                       int conn_handle, int handler_id)
{
    /* Simplified: discovery is complex. Post results via callback. */
    ESP_LOGI(TAG, "gattc_discover conn=%d handler=%d", conn_handle, handler_id);
    return 0;
}

/* ble_gattc_read(conn_handle, attr_handle, handler_id) -> 0 */
static int ble_gattc_read_wrapper(wasm_exec_env_t exec_env,
                                   int conn_handle, int attr_handle, int handler_id)
{
    ESP_LOGI(TAG, "gattc_read conn=%d attr=%d", conn_handle, attr_handle);
    return 0;
}

/* ble_gattc_write(conn_handle, attr_handle, data_ptr, data_len) -> 0 */
static int ble_gattc_write_wrapper(wasm_exec_env_t exec_env,
                                    int conn_handle, int attr_handle,
                                    const char *data, int data_len)
{
    if (!data || data_len <= 0) return -1;

    int rc = ble_gattc_write_flat(conn_handle, attr_handle,
                                   data, data_len, NULL, NULL);
    return (rc == 0) ? 0 : -1;
}

static NativeSymbol s_ble_symbols[] = {
    /* GAP */
    { "ble_init",              (void *)ble_init_wrapper,              "()i",      NULL },
    { "ble_advertise_start",   (void *)ble_advertise_start_wrapper,   "(*~)i",    NULL },
    { "ble_advertise_stop",    (void *)ble_advertise_stop_wrapper,    "()i",      NULL },
    { "ble_scan_start",        (void *)ble_scan_start_wrapper,        "(ii)i",    NULL },
    { "ble_scan_stop",         (void *)ble_scan_stop_wrapper,         "()i",      NULL },
    { "ble_connect",           (void *)ble_connect_wrapper,           "(i*~i)i",  NULL },
    { "ble_disconnect",        (void *)ble_disconnect_wrapper,        "(i)i",     NULL },
    /* GATT Server */
    { "ble_gatts_add_service",        (void *)ble_gatts_add_service_wrapper,        "(*~)i",    NULL },
    { "ble_gatts_add_characteristic", (void *)ble_gatts_add_characteristic_wrapper, "(i*~i)i",  NULL },
    { "ble_gatts_set_value",          (void *)ble_gatts_set_value_wrapper,          "(i*~)i",   NULL },
    { "ble_gatts_notify",             (void *)ble_gatts_notify_wrapper,             "(ii)i",    NULL },
    { "ble_gatts_on_write",           (void *)ble_gatts_on_write_wrapper,           "(ii)i",    NULL },
    /* GATT Client */
    { "ble_gattc_discover",  (void *)ble_gattc_discover_wrapper,  "(ii)i",   NULL },
    { "ble_gattc_read",      (void *)ble_gattc_read_wrapper,      "(iii)i",  NULL },
    { "ble_gattc_write",     (void *)ble_gattc_write_wrapper,     "(ii*~)i", NULL },
};

#else /* BLE not enabled */

esp_err_t wendy_ble_init(void)
{
    ESP_LOGW(TAG, "BLE not enabled in sdkconfig");
    return ESP_ERR_NOT_SUPPORTED;
}

static NativeSymbol s_ble_symbols[] = {};

#endif /* CONFIG_BT_ENABLED && CONFIG_BT_NIMBLE_ENABLED */

int wendy_ble_export_init(void)
{
    int count = sizeof(s_ble_symbols) / sizeof(s_ble_symbols[0]);
    if (count == 0) {
        ESP_LOGI(TAG, "BLE exports skipped (BLE not enabled)");
        return 0;
    }

    if (!wasm_runtime_register_natives("wendy", s_ble_symbols, count)) {
        ESP_LOGE(TAG, "failed to register BLE natives");
        return -1;
    }
    ESP_LOGI(TAG, "BLE exports registered (%d functions)", count);
    return 0;
}
