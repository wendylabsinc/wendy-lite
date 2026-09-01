#include "wendy_ble.h"

#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"


//--- globals ---//

static const char *TAG = "wendy_ble";


#if CONFIG_WENDY_BLE

#include "wendy_conf.h"
#include "wendy_ble_l2cap.h"
#include "wendy_ble_tls.h"
#include "wendy_com_link.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"


//--- literals ---//

#define ADV_ITVL_MIN_MS  100
#define ADV_ITVL_MAX_MS  150

#define SESSION_TASK_STACK  4096

// Company identifier 0xFFFF is the range the Bluetooth SIG reserves for
// internal use and testing, which is what a device ID in an advertisement is.
#define MFG_COMPANY_ID_LO  0xFF
#define MFG_COMPANY_ID_HI  0xFF

// A scan response holds 31 bytes: the name costs 2 + len, the manufacturer
// data 2 + 2 + len. The ID gets a fixed allowance (it is short and stable),
// and the name takes whatever is left.
#define SCAN_RSP_BUDGET    31
#define DEVICE_ID_ADV_MAX  12

// Leave the name at least a few bytes, and keep the budget arithmetic in
// _start_advertising() from underflowing its size_t.
_Static_assert(DEVICE_ID_ADV_MAX + 4 + 2 + 4 <= SCAN_RSP_BUDGET,
               "DEVICE_ID_ADV_MAX leaves no room for a local name");

/* Info service 4E57454E-4459-0002-000x-000000000000 — "NWENDY", service 2,
 * the same base WendyOS uses for the Wi-Fi provisioning service (0001).
 * NimBLE stores 128-bit UUIDs least significant byte first, so these read
 * backwards compared to the canonical string form. */
#define WENDY_BLE_UUID128(lo)                                             \
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (lo), 0x00,      \
                     0x02, 0x00, 0x59, 0x44, 0x4E, 0x45, 0x57, 0x4E)


//--- types ---//

/* Which value a characteristic read should return. Passed through the
 * ble_gatt_chr_def arg, so it must never be 0 — that is what an absent arg
 * looks like. */
enum info_field {
    INFO_PSM = 1,
    INFO_DEVICE_ID,
    INFO_DEVICE_NAME,
    INFO_DISPLAY_NAME,
    INFO_MTLS,
};


//--- globals ---//

static const ble_uuid128_t _uuid_svc          = WENDY_BLE_UUID128(0x00);
static const ble_uuid128_t _uuid_psm          = WENDY_BLE_UUID128(0x01);
static const ble_uuid128_t _uuid_device_id    = WENDY_BLE_UUID128(0x02);
static const ble_uuid128_t _uuid_device_name  = WENDY_BLE_UUID128(0x03);
static const ble_uuid128_t _uuid_display_name = WENDY_BLE_UUID128(0x04);
static const ble_uuid128_t _uuid_mtls         = WENDY_BLE_UUID128(0x05);

static bool  _host_initialized;
static bool  _started;
static bool  _provisioned;
static uint8_t _own_addr_type;

static char *_device_id;
static char *_device_name;
static char *_display_name;

static uint8_t _mfg_data[2 + DEVICE_ID_ADV_MAX];
static uint8_t _mfg_data_len;


//--- internal functions ---//

static int _info_access(uint16_t conn_handle, uint16_t attr_handle,
                        struct ble_gatt_access_ctxt *ctxt, void *arg);

static const struct ble_gatt_chr_def _info_chrs[] = {
    {
        .uuid      = &_uuid_psm.u,
        .access_cb = _info_access,
        .arg       = (void *)(uintptr_t)INFO_PSM,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {
        .uuid      = &_uuid_device_id.u,
        .access_cb = _info_access,
        .arg       = (void *)(uintptr_t)INFO_DEVICE_ID,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {
        .uuid      = &_uuid_device_name.u,
        .access_cb = _info_access,
        .arg       = (void *)(uintptr_t)INFO_DEVICE_NAME,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {
        .uuid      = &_uuid_display_name.u,
        .access_cb = _info_access,
        .arg       = (void *)(uintptr_t)INFO_DISPLAY_NAME,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    {
        .uuid      = &_uuid_mtls.u,
        .access_cb = _info_access,
        .arg       = (void *)(uintptr_t)INFO_MTLS,
        .flags     = BLE_GATT_CHR_F_READ,
    },
    { 0 },
};

static const struct ble_gatt_svc_def _gatt_svcs[] = {
    {
        .type            = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid            = &_uuid_svc.u,
        .characteristics = _info_chrs,
    },
    { 0 },
};

static int _info_access(uint16_t conn_handle, uint16_t attr_handle,
                        struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle;
    (void)attr_handle;

    if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR)
        return BLE_ATT_ERR_UNLIKELY;

    // Both are little-endian on the wire, which is also the native byte order
    // on every target this builds for.
    uint16_t psm  = CONFIG_WENDY_BLE_PSM;
    uint8_t  mtls = _provisioned ? 1 : 0;

    const void *data;
    uint16_t len;

    switch ((enum info_field)(uintptr_t)arg) {
        case INFO_PSM:
            data = &psm;
            len = sizeof(psm);
            break;
        case INFO_DEVICE_ID:
            data = _device_id ? _device_id : "";
            len = (uint16_t)strlen(data);
            break;
        case INFO_DEVICE_NAME:
            data = _device_name ? _device_name : "";
            len = (uint16_t)strlen(data);
            break;
        case INFO_DISPLAY_NAME:
            data = _display_name ? _display_name : "";
            len = (uint16_t)strlen(data);
            break;
        case INFO_MTLS:
            data = &mtls;
            len = sizeof(mtls);
            break;
        default:
            return BLE_ATT_ERR_UNLIKELY;
    }

    if (len == 0)
        return 0; // an empty read is a valid answer, not an error

    return os_mbuf_append(ctxt->om, data, len) == 0 ? 0
                                                    : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static int _gap_event(struct ble_gap_event *event, void *arg);

/// Advertise the service UUID in the advertisement itself so a central can
/// filter for it in-stack (CoreBluetooth's scanForPeripheralsWithServices:
/// matches on the advertisement, not the scan response), and put the identity
/// in the scan response, where there is room for it.
static void _start_advertising(void)
{
    struct ble_hs_adv_fields adv = {0};
    adv.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    adv.uuids128 = &_uuid_svc;
    adv.num_uuids128 = 1;
    adv.uuids128_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&adv);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: %d", rc);
        return;
    }

    struct ble_hs_adv_fields rsp = {0};
    if (_mfg_data_len > 0) {
        rsp.mfg_data = _mfg_data;
        rsp.mfg_data_len = _mfg_data_len;
    }
    if (_device_name && _device_name[0]) {
        size_t name_len = strlen(_device_name);
        size_t budget = SCAN_RSP_BUDGET - 2 - (_mfg_data_len ? _mfg_data_len + 2 : 0);
        if (name_len > budget) {
            ESP_LOGW(TAG, "advertised name truncated to %u bytes", (unsigned)budget);
            name_len = budget;
        }
        rsp.name = (const uint8_t *)_device_name;
        rsp.name_len = (uint8_t)name_len;
        rsp.name_is_complete = (name_len == strlen(_device_name));
    }

    rc = ble_gap_adv_rsp_set_fields(&rsp);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_rsp_set_fields failed: %d", rc);
        return;
    }

    struct ble_gap_adv_params params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min  = BLE_GAP_ADV_ITVL_MS(ADV_ITVL_MIN_MS),
        .itvl_max  = BLE_GAP_ADV_ITVL_MS(ADV_ITVL_MAX_MS),
    };

    rc = ble_gap_adv_start(_own_addr_type, NULL, BLE_HS_FOREVER,
                           &params, _gap_event, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
        return;
    }

    ESP_LOGI(TAG, "advertising as '%s' (id '%s')",
             _device_name ? _device_name : "",
             _device_id ? _device_id : "");
}

static int _gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;

    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            ESP_LOGI(TAG, "connect: status=%d handle=%d",
                     event->connect.status, event->connect.conn_handle);
            // A failed connect leaves advertising stopped; a successful one is
            // undirected connectable, so it stops too.
            if (event->connect.status != 0)
                _start_advertising();
            break;

        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGI(TAG, "disconnect: reason=%d", event->disconnect.reason);
            _start_advertising();
            break;

        case BLE_GAP_EVENT_ADV_COMPLETE:
            _start_advertising();
            break;

        case BLE_GAP_EVENT_MTU:
            ESP_LOGD(TAG, "ATT MTU now %d", event->mtu.value);
            break;

        default:
            break;
    }
    return 0;
}

static void _on_sync(void)
{
    int rc = ble_hs_util_ensure_addr(0);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_util_ensure_addr failed: %d", rc);
        return;
    }
    rc = ble_hs_id_infer_auto(0, &_own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: %d", rc);
        return;
    }

    ESP_LOGI(TAG, "BLE host synced");

    if (_started)
        _start_advertising();
}

static void _on_reset(int reason)
{
    ESP_LOGW(TAG, "BLE host reset: reason=%d", reason);
}

static void _host_task(void *param)
{
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static char *_dup_or_empty(const char *s)
{
    return strdup(s ? s : "");
}

/// Bringing the stack up costs tens of KiB on a chip that is already tight
/// with WiFi and the WAMR pool resident, and a shortfall shows up much later
/// as mbedtls_ssl_setup returning ALLOC_FAILED. Log both numbers so the cost
/// is visible in the boot log rather than inferred from a failure.
static void _log_heap(const char *when)
{
    ESP_LOGI(TAG, "heap %s BLE init: free=%u largest_block=%u",
             when,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}

/// Pack the device ID into the manufacturer-data payload advertised in the
/// scan response: two bytes of company ID followed by the ID itself.
static void _build_mfg_data(void)
{
    _mfg_data_len = 0;
    if (!_device_id || !_device_id[0])
        return;

    size_t id_len = strlen(_device_id);
    if (id_len > DEVICE_ID_ADV_MAX) {
        // Truncating would put a wrong ID on the air, and a wrong ID is worse
        // than no device: a scan would show an identity that matches nothing.
        // The ID is a build-time property of the firmware, not something a
        // user can get wrong at runtime, so refusing to boot is the fastest
        // way to surface it.
        ESP_LOGE(TAG, "device id '%s' is %u bytes, more than the %d that fit "
                      "in the advertisement",
                 _device_id, (unsigned)id_len, DEVICE_ID_ADV_MAX);
        esp_system_abort("wendy_ble: device id too long to advertise");
    }

    _mfg_data[0] = MFG_COMPANY_ID_LO;
    _mfg_data[1] = MFG_COMPANY_ID_HI;
    memcpy(&_mfg_data[2], _device_id, id_len);
    _mfg_data_len = (uint8_t)(2 + id_len);
}


/* ── Session task ───────────────────────────────────────────────────────
 *
 * Waits for a peer to open the channel, runs the TLS handshake, then hands
 * the encrypted stream to the wcom task and waits for the link to die.
 *
 * Ownership rule: exactly one task touches the mbedTLS context at a time.
 * This task owns it up to wcom_core_exec(); the wcom task owns it from when
 * that operation runs until the link is removed (which also happens on the
 * wcom task); ownership comes back here only once _link_closed is signalled.
 */

static SemaphoreHandle_t _link_closed;
static int _link_id;   // wcom task only

static ssize_t _stream_read(void *ctx, void *buf, size_t len)
{
    (void)ctx;
    ssize_t n = wble_tls_read(buf, len);
    switch (n) {
        case WBLE_ERR_WANT_READ:  return WCOM_STREAM_ERR_WANT_READ;
        case WBLE_ERR_WANT_WRITE: return WCOM_STREAM_ERR_WANT_WRITE;
        case WBLE_ERR_UNKNOWN:    return WCOM_STREAM_ERR_UNKNOWN;
        default:                  return n;
    }
}

static ssize_t _stream_write(void *ctx, const void *buf, size_t len)
{
    (void)ctx;
    ssize_t n = wble_tls_write(buf, len);
    switch (n) {
        case WBLE_ERR_WANT_READ:  return WCOM_STREAM_ERR_WANT_READ;
        case WBLE_ERR_WANT_WRITE: return WCOM_STREAM_ERR_WANT_WRITE;
        case WBLE_ERR_UNKNOWN:    return WCOM_STREAM_ERR_UNKNOWN;
        default:                  return n;
    }
}

static int _stream_wakeup_fd(void *ctx)
{
    (void)ctx;
    return wble_l2cap_wakeup_fd();
}

static bool _stream_can_read(void *ctx)
{
    (void)ctx;
    // Decrypted bytes already inside mbedTLS count as readable: no transport
    // event is coming to announce them.
    return wble_tls_pending() || wble_l2cap_can_read();
}

static bool _stream_can_write(void *ctx)
{
    (void)ctx;
    return wble_l2cap_can_write();
}

static const struct wcom_stream_ops _stream_ops = {
    .read      = _stream_read,
    .write     = _stream_write,
    .wakeup_fd = _stream_wakeup_fd,
    .can_read  = _stream_can_read,
    .can_write = _stream_can_write,
};

/// Runs on the wcom task.
static void _on_link_state_change(struct wcom_state_change_handler *handler,
                                  int link_id, enum wcom_link_state state)
{
    (void)handler;
    if (link_id != _link_id || state == WCOM_LINK_STATE_CONNECTED)
        return;

    ESP_LOGI(TAG, "link %d closed (state %d)", link_id, (int)state);
    _link_id = 0;
    wcom_remove_link(link_id);
    // Tearing down TLS and the channel is the session task's job: it owns
    // those contexts again from here.
    xSemaphoreGive(_link_closed);
}

static struct wcom_state_change_handler _state_handler = {
    .func = _on_link_state_change,
};

/// Runs on the wcom task.
static void _add_link_exec(struct wcom_operation *op)
{
    (void)op;
    static bool subscribed = false;
    if (!subscribed) {
        wcom_add_state_change_handler(&_state_handler);
        subscribed = true;
    }

    _link_id = wcom_add_stream_link(&_stream_ops, NULL);
    if (_link_id < 0) {
        ESP_LOGE(TAG, "no free wcom link for the BLE session");
        _link_id = 0;
        xSemaphoreGive(_link_closed);
        return;
    }
    ESP_LOGI(TAG, "link %d up", _link_id);
}

static void _session_task(void *arg)
{
    (void)arg;
    static struct wcom_operation add_link_op = { .func = _add_link_exec };

    for (;;) {
        if (!wble_l2cap_wait_session(portMAX_DELAY))
            continue;

        ESP_LOGI(TAG, "session started");
        if (wble_tls_session_start() == ESP_OK) {
            // Drop a stale signal from a previous session before handing the
            // stream over, or the wait below would return immediately.
            xSemaphoreTake(_link_closed, 0);
            wcom_core_exec(&add_link_op);
            xSemaphoreTake(_link_closed, portMAX_DELAY);
        }
        wble_tls_session_end();
        wble_l2cap_end_session();
        ESP_LOGI(TAG, "session ended");
    }
}


//--- public functions ---//

esp_err_t wendy_ble_host_init(void)
{
    if (_host_initialized)
        return ESP_OK;

    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %s", esp_err_to_name(err));
        return err;
    }

    ble_hs_cfg.sync_cb  = _on_sync;
    ble_hs_cfg.reset_cb = _on_reset;

    ble_svc_gap_init();
    ble_svc_gatt_init();

    int rc = ble_gatts_count_cfg(_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_count_cfg failed: %d", rc);
        return ESP_FAIL;
    }
    rc = ble_gatts_add_svcs(_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_add_svcs failed: %d", rc);
        return ESP_FAIL;
    }

    // The host task must start last: services have to be registered before the
    // stack syncs and the GATT database is built.
    nimble_port_freertos_init(_host_task);

    _host_initialized = true;
    ESP_LOGI(TAG, "NimBLE host started");
    return ESP_OK;
}

esp_err_t wendy_ble_start(const char *device_id,
                          const char *device_name,
                          const char *display_name)
{
    if (_started)
        return ESP_OK;

    struct wendy_conf_span key   = wendy_conf_get_private_key();
    struct wendy_conf_span cert  = wendy_conf_get_certificate();
    struct wendy_conf_span chain = wendy_conf_get_chain_of_trust();
    _provisioned = key.size > 0 && cert.size > 0 && chain.size > 0;

#if CONFIG_WENDY_BLE_REQUIRE_MTLS
    if (!_provisioned) {
        ESP_LOGW(TAG, "device not provisioned and mTLS is required: "
                      "not advertising");
        return ESP_ERR_INVALID_STATE;
    }
#endif

    _device_id    = _dup_or_empty(device_id);
    _device_name  = _dup_or_empty(device_name);
    _display_name = _dup_or_empty(display_name);
    if (!_device_id || !_device_name || !_display_name) {
        ESP_LOGE(TAG, "out of memory");
        return ESP_ERR_NO_MEM;
    }

    _build_mfg_data();

    // The GAP service name is what a central reads from the standard 0x2A00
    // characteristic; keep it in step with the advertised name.
    ble_svc_gap_device_name_set(_device_name);

    _log_heap("before");
    esp_err_t err = wendy_ble_host_init();
    if (err != ESP_OK)
        return err;
    _log_heap("after");

    err = wble_l2cap_init();
    if (err != ESP_OK)
        return err;

    _link_closed = xSemaphoreCreateBinary();
    if (!_link_closed) {
        ESP_LOGE(TAG, "semaphore allocation failed");
        return ESP_ERR_NO_MEM;
    }

    if (xTaskCreatePinnedToCore(_session_task, "wendy_ble",
                                SESSION_TASK_STACK, NULL,
                                CONFIG_WENDY_BLE_TASK_PRIORITY, NULL,
                                CONFIG_WENDY_BLE_TASK_CORE_AFFINITY) != pdPASS) {
        ESP_LOGE(TAG, "session task creation failed");
        return ESP_ERR_NO_MEM;
    }

    _started = true;

    if (_provisioned)
        ESP_LOGI(TAG, "full mTLS enabled: only authenticated clients will be accepted");
    else
        ESP_LOGI(TAG, "mTLS disabled: any client will be accepted");

    // If the host synced before this ran, _on_sync skipped advertising because
    // _started was still false; start it here instead.
    if (ble_hs_synced())
        _start_advertising();

    return ESP_OK;
}

#else /* !CONFIG_WENDY_BLE */

esp_err_t wendy_ble_host_init(void)
{
    ESP_LOGW(TAG, "CONFIG_WENDY_BLE is not set");
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t wendy_ble_start(const char *device_id,
                          const char *device_name,
                          const char *display_name)
{
    (void)device_id;
    (void)device_name;
    (void)display_name;
    return ESP_ERR_NOT_SUPPORTED;
}

#endif /* CONFIG_WENDY_BLE */
