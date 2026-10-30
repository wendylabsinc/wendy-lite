#include "wendy_ble_export.h"

#include <string.h>
#include "esp_log.h"
#include "wasm_export.h"
#include "wendy_safety.h"

#include "wendy_ble.h"

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#endif

#if CONFIG_BT_ENABLED && CONFIG_BT_NIMBLE_ENABLED
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#if CONFIG_BT_NIMBLE_EXT_ADV
#include "host/ble_hs_adv.h"
#include "host/ble_hs_mbuf.h"
#define GUEST_ADV_INSTANCE 1
#endif
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#endif

static const char *TAG = "wendy_ble_export";

#if CONFIG_BT_ENABLED && CONFIG_BT_NIMBLE_ENABLED

/* The NimBLE stack is owned and started by wendy_ble (the WendyCom BLE
 * transport); this only records whether the guest has called ble_init(). */
static bool s_ble_initialized = false;
static uint32_t s_scan_handler_id = 0;
static uint32_t s_connect_handler_id = 0;

/* ── GAP event callback ───────────────────────────────────────────────── */

static int ble_gap_event(struct ble_gap_event *event, void *arg) {
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        ESP_LOGI(TAG, "connect event: status=%d handle=%d", event->connect.status,
                 event->connect.conn_handle);
#if CONFIG_WENDY_CALLBACK
        if (s_connect_handler_id) {
            wendy_callback_post(s_connect_handler_id, event->connect.status,
                                event->connect.conn_handle, 0);
        }
#endif
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "disconnect event: reason=%d", event->disconnect.reason);
#if CONFIG_WENDY_CALLBACK
        if (s_connect_handler_id) {
            wendy_callback_post(s_connect_handler_id, event->disconnect.reason,
                                event->disconnect.conn.conn_handle, 1);
        }
#endif
        break;

    case BLE_GAP_EVENT_DISC:
#if CONFIG_WENDY_CALLBACK
        if (s_scan_handler_id) {
            /* Post RSSI and addr type as args */
            wendy_callback_post(s_scan_handler_id, (uint32_t)(int8_t)event->disc.rssi,
                                event->disc.addr.type, 0);
        }
#endif
        break;

#if CONFIG_BT_NIMBLE_EXT_ADV
    case BLE_GAP_EVENT_EXT_DISC:
#if CONFIG_WENDY_CALLBACK
        if (s_scan_handler_id &&
            event->ext_disc.data_status == BLE_GAP_EXT_ADV_DATA_STATUS_COMPLETE)
            wendy_callback_post(s_scan_handler_id, (uint32_t)(int8_t)event->ext_disc.rssi,
                                event->ext_disc.addr.type, 0);
#endif
        break;
#endif
    case BLE_GAP_EVENT_ADV_COMPLETE:
        ESP_LOGI(TAG, "advertise complete");
        break;

    default:
        break;
    }
    return 0;
}

/* ── WASM wrappers ────────────────────────────────────────────────────── */

/* ble_init() -> 0 ok
 *
 * Brings up the shared NimBLE stack through wendy_ble, which owns it. The
 * transport normally started it at boot already, in which case this is a
 * no-op that just marks the guest API usable. */
static int ble_init_wrapper(wasm_exec_env_t exec_env) {
    if (wendy_ble_host_init() != ESP_OK)
        return -1;
    s_ble_initialized = true;
    return 0;
}

/* ble_advertise_start(name_ptr, name_len) -> 0 ok */
static int ble_advertise_start_wrapper(wasm_exec_env_t exec_env, const char *name, int name_len) {
    if (!s_ble_initialized)
        return -1;

    if (!name || name_len < 0)
        return -1;
    /* Flags and name headers leave 26 bytes in a 31-byte payload. */
    char dev_name[27];
    int len = name_len < 26 ? name_len : 26;
    memcpy(dev_name, name, (size_t)len);
    dev_name[len] = '\0';

    struct ble_hs_adv_fields fields = {0};
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (const uint8_t *)dev_name;
    fields.name_len = len;
    fields.name_is_complete = len == name_len;
    /* Do not publish a fixed TX-power AD field: device policy can change the
     * controller power in place while this payload remains unchanged. */

    int rc;
#if CONFIG_BT_NIMBLE_EXT_ADV
#if CONFIG_BT_NIMBLE_MAX_EXT_ADV_INSTANCES > GUEST_ADV_INSTANCE
    /* Guest advertisements never borrow or overwrite management/mesh set 0. */
    if (ble_gap_ext_adv_active(GUEST_ADV_INSTANCE))
        return -1;
    uint8_t own_type;
    if (ble_hs_id_infer_auto(0, &own_type))
        return -1;
    struct ble_gap_ext_adv_params params = {.connectable = 1,
                                            .scannable = 1,
                                            .legacy_pdu = 1,
                                            .own_addr_type = own_type,
                                            .primary_phy = 1,
                                            .secondary_phy = 1,
                                            .sid = GUEST_ADV_INSTANCE,
#if CONFIG_WENDY_BLE
                                            .tx_power = wendy_ble_power_advertising_request()
#else
                                            .tx_power = 127
#endif
    };
    rc = ble_gap_ext_adv_configure(GUEST_ADV_INSTANCE, &params, NULL, ble_gap_event, NULL);
    if (rc)
        return -1;
    uint8_t data[31], size = 0;
    rc = ble_hs_adv_set_fields(&fields, data, &size, sizeof data);
    if (!rc) {
        struct os_mbuf *buffer = ble_hs_mbuf_from_flat(data, size);
        rc = buffer ? ble_gap_ext_adv_set_data(GUEST_ADV_INSTANCE, buffer) : BLE_HS_ENOMEM;
    }
#if CONFIG_WENDY_BLE
    if (!rc)
        rc = wendy_ble_power_advertising_add(GUEST_ADV_INSTANCE);
#endif
    if (!rc)
        rc = ble_gap_ext_adv_start(GUEST_ADV_INSTANCE, 0, 0);
    if (rc) {
        ble_gap_ext_adv_remove(GUEST_ADV_INSTANCE);
#if CONFIG_WENDY_BLE
        wendy_ble_power_advertising_remove(GUEST_ADV_INSTANCE);
#endif
    }
#else
    (void)fields;
    ESP_LOGE(TAG, "Guest advertising requires a separate extended advertising set");
    return -1;
#endif
#else
    struct ble_gap_adv_params params = {.conn_mode = BLE_GAP_CONN_MODE_UND,
                                        .disc_mode = BLE_GAP_DISC_MODE_GEN};
    rc = ble_gap_adv_set_fields(&fields);
#if CONFIG_WENDY_BLE
    if (!rc)
        rc = wendy_ble_power_apply_advertising();
#endif
    if (!rc)
        rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER, &params, ble_gap_event,
                               NULL);
#endif
    if (rc) {
        ESP_LOGE(TAG, "Guest advertisement failed: %d", rc);
        return -1;
    }

    ESP_LOGI(TAG, "advertising as '%s'", dev_name);
    return 0;
}

/* ble_advertise_stop() -> 0 ok */
static int ble_advertise_stop_wrapper(wasm_exec_env_t exec_env) {
    if (!s_ble_initialized)
        return -1;
#if CONFIG_BT_NIMBLE_EXT_ADV
    int rc = ble_gap_ext_adv_stop(GUEST_ADV_INSTANCE);
    if (!rc || rc == BLE_HS_EALREADY) {
        rc = ble_gap_ext_adv_remove(GUEST_ADV_INSTANCE);
#if CONFIG_WENDY_BLE
        wendy_ble_power_advertising_remove(GUEST_ADV_INSTANCE);
#endif
    }
#else
    int rc = ble_gap_adv_stop();
#endif
    return (rc == 0 || rc == BLE_HS_EALREADY) ? 0 : -1;
}

/* ble_scan_start(duration_ms, handler_id) -> 0 ok */
static int ble_scan_start_wrapper(wasm_exec_env_t exec_env, int duration_ms, int handler_id) {
    if (!s_ble_initialized)
        return -1;

    s_scan_handler_id = (uint32_t)handler_id;

    struct ble_gap_disc_params disc_params = {
        .passive = 0,
        .filter_duplicates = 1,
        .itvl = 0,
        .window = 0,
    };

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC,
                          duration_ms, /* SDK legacy wrapper accepts milliseconds too. */
                          &disc_params, ble_gap_event, NULL);
    return (rc == 0) ? 0 : -1;
}

/* ble_scan_stop() -> 0 ok */
static int ble_scan_stop_wrapper(wasm_exec_env_t exec_env) {
    if (!s_ble_initialized)
        return -1;
    int rc = ble_gap_disc_cancel();
    s_scan_handler_id = 0;
    return (rc == 0 || rc == BLE_HS_EALREADY) ? 0 : -1;
}

/* ble_connect(addr_type, addr_ptr, addr_len, handler_id) -> 0 ok */
static int ble_connect_wrapper(wasm_exec_env_t exec_env, int addr_type, const char *addr,
                               int addr_len, int handler_id) {
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
