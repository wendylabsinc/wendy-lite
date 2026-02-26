#include "wendy_ble_prov.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#if CONFIG_WENDY_BLE_PROV && CONFIG_BT_ENABLED && CONFIG_BT_NIMBLE_ENABLED

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

static const char *TAG = "wendy_ble_prov";

/* ── Custom 128-bit UUIDs ──────────────────────────────────────────── */

/* Service:  4e57454e-4459-0001-0000-000000000000  ("WENDY" prefix) */
static const ble_uuid128_t s_prov_svc_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                     0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e, 0x00, 0x00);

/* SSID:     4e57454e-4459-0001-0001-000000000000 */
static const ble_uuid128_t s_ssid_chr_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                     0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e, 0x00, 0x00);

/* Password: 4e57454e-4459-0001-0002-000000000000 */
static const ble_uuid128_t s_pass_chr_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
                     0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e, 0x00, 0x00);

/* Command:  4e57454e-4459-0001-0003-000000000000 */
static const ble_uuid128_t s_cmd_chr_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
                     0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e, 0x00, 0x00);

/* Status:   4e57454e-4459-0001-0004-000000000000 */
static const ble_uuid128_t s_status_chr_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00,
                     0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e, 0x00, 0x00);

/* Device Name: 4e57454e-4459-0001-0005-000000000000 */
static const ble_uuid128_t s_devname_chr_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00,
                     0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e, 0x00, 0x00);

/* ── State ──────────────────────────────────────────────────────────── */

static bool s_nimble_ready = false;
static wendy_ble_prov_callbacks_t s_callbacks;

/* Buffers for credentials (written by BLE task, read by main) */
static char s_prov_ssid[33];
static char s_prov_pass[65];

/* Status characteristic value: [status_byte] [ip_string...] */
static uint8_t s_status_val[48] = { WENDY_BLE_PROV_STATUS_NO_CREDS };
static int s_status_val_len = 1;

/* Device name (built at init) */
static char s_device_name[32];

/* Handle for status characteristic (for notifications) */
static uint16_t s_status_chr_val_handle;

/* Current connection handle for notifications (-1 = none) */
static uint16_t s_conn_handle = 0xFFFF;

/* ── GATT access callbacks ─────────────────────────────────────────── */

static int gatt_ssid_access(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
        uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
        if (om_len > 32) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        ble_hs_mbuf_to_flat(ctxt->om, s_prov_ssid, sizeof(s_prov_ssid) - 1, &om_len);
        s_prov_ssid[om_len] = '\0';
        ESP_LOGI(TAG, "SSID written: '%s'", s_prov_ssid);
        return 0;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

static int gatt_pass_access(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
        uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
        if (om_len > 64) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        ble_hs_mbuf_to_flat(ctxt->om, s_prov_pass, sizeof(s_prov_pass) - 1, &om_len);
        s_prov_pass[om_len] = '\0';
        ESP_LOGI(TAG, "password written (%d bytes)", om_len);
        return 0;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

static int gatt_cmd_access(uint16_t conn_handle, uint16_t attr_handle,
                            struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
        uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
        if (om_len < 1) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;

        uint8_t cmd;
        ble_hs_mbuf_to_flat(ctxt->om, &cmd, 1, &om_len);

        if (cmd == 0x01) {
            /* Connect command */
            ESP_LOGI(TAG, "connect command received");
            if (s_callbacks.on_wifi_creds) {
                s_callbacks.on_wifi_creds(s_prov_ssid, s_prov_pass);
            }
        } else if (cmd == 0x02) {
            /* Clear credentials command */
            ESP_LOGI(TAG, "clear credentials command received");
            if (s_callbacks.on_clear_creds) {
                s_callbacks.on_clear_creds();
            }
        } else {
            ESP_LOGW(TAG, "unknown command: 0x%02x", cmd);
        }
        return 0;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

static int gatt_status_access(uint16_t conn_handle, uint16_t attr_handle,
                               struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        int rc = os_mbuf_append(ctxt->om, s_status_val, s_status_val_len);
        return (rc == 0) ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

static int gatt_devname_access(uint16_t conn_handle, uint16_t attr_handle,
                                struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        int rc = os_mbuf_append(ctxt->om, s_device_name, strlen(s_device_name));
        return (rc == 0) ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

/* ── GATT service table ────────────────────────────────────────────── */

static const struct ble_gatt_svc_def s_gatt_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &s_prov_svc_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                /* SSID - write only */
                .uuid = &s_ssid_chr_uuid.u,
                .access_cb = gatt_ssid_access,
                .flags = BLE_GATT_CHR_F_WRITE,
            },
            {
                /* Password - write only */
                .uuid = &s_pass_chr_uuid.u,
                .access_cb = gatt_pass_access,
                .flags = BLE_GATT_CHR_F_WRITE,
            },
            {
                /* Command - write only */
                .uuid = &s_cmd_chr_uuid.u,
                .access_cb = gatt_cmd_access,
                .flags = BLE_GATT_CHR_F_WRITE,
            },
            {
                /* Status - read + notify */
                .uuid = &s_status_chr_uuid.u,
                .access_cb = gatt_status_access,
                .val_handle = &s_status_chr_val_handle,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
            },
            {
                /* Device Name - read only */
                .uuid = &s_devname_chr_uuid.u,
                .access_cb = gatt_devname_access,
                .flags = BLE_GATT_CHR_F_READ,
            },
            { 0 }, /* sentinel */
        },
    },
    { 0 }, /* sentinel */
};

/* ── GAP event handler ─────────────────────────────────────────────── */

static void start_advertising(void);

static int prov_gap_event(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        ESP_LOGI(TAG, "client connected: handle=%d status=%d",
                 event->connect.conn_handle, event->connect.status);
        if (event->connect.status == 0) {
            s_conn_handle = event->connect.conn_handle;
        } else {
            /* Connection failed, re-advertise */
            start_advertising();
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "client disconnected: reason=%d", event->disconnect.reason);
        s_conn_handle = 0xFFFF;
        /* Re-advertise after disconnect */
        start_advertising();
        break;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        ESP_LOGD(TAG, "advertise complete");
        /* Re-advertise */
        start_advertising();
        break;

    case BLE_GAP_EVENT_SUBSCRIBE:
        ESP_LOGI(TAG, "subscribe: attr_handle=%d", event->subscribe.attr_handle);
        break;

    default:
        break;
    }
    return 0;
}

/* ── Advertising ───────────────────────────────────────────────────── */

static void start_advertising(void)
{
    struct ble_hs_adv_fields fields = { 0 };
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (const uint8_t *)s_device_name;
    fields.name_len = strlen(s_device_name);
    fields.name_is_complete = 1;
    fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;
    fields.tx_pwr_lvl_is_present = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: %d", rc);
        return;
    }

    /* Include service UUID in scan response */
    struct ble_hs_adv_fields rsp_fields = { 0 };
    rsp_fields.uuids128 = (ble_uuid128_t[]){ s_prov_svc_uuid };
    rsp_fields.num_uuids128 = 1;
    rsp_fields.uuids128_is_complete = 1;

    rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_rsp_set_fields failed: %d", rc);
        return;
    }

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
    };

    rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                           &adv_params, prov_gap_event, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
    } else {
        ESP_LOGI(TAG, "advertising as '%s'", s_device_name);
    }
}

/* ── Build device name from BT MAC ─────────────────────────────────── */

static void build_device_name(void)
{
    uint8_t addr[6];
    /* Get the public address that NimBLE will use */
    int rc = ble_hs_id_copy_addr(BLE_ADDR_PUBLIC, addr, NULL);
    if (rc != 0) {
        /* Fallback: use a fixed suffix */
        snprintf(s_device_name, sizeof(s_device_name),
                 "%s-0000", CONFIG_WENDY_BLE_PROV_DEVICE_PREFIX);
        return;
    }

    /* Use last 2 bytes of MAC for suffix */
    snprintf(s_device_name, sizeof(s_device_name),
             "%s-%02X%02X", CONFIG_WENDY_BLE_PROV_DEVICE_PREFIX,
             addr[1], addr[0]);
}

/* ── NimBLE host sync callback ─────────────────────────────────────── */

static void prov_on_sync(void)
{
    ble_hs_util_ensure_addr(0);

    /* Now that the host is synced we can read the real BT address */
    build_device_name();
    ble_svc_gap_device_name_set(s_device_name);

    ESP_LOGI(TAG, "BLE host synced, starting advertising");
    start_advertising();
}

static void ble_host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/* ── Public API ─────────────────────────────────────────────────────── */

esp_err_t wendy_ble_prov_init(const wendy_ble_prov_callbacks_t *callbacks)
{
    if (s_nimble_ready) return ESP_OK;

    if (callbacks) {
        s_callbacks = *callbacks;
    }

    /* Initialize NimBLE */
    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %s", esp_err_to_name(err));
        return err;
    }

    /* Configure host callbacks */
    ble_hs_cfg.sync_cb = prov_on_sync;

    /* Initialize GAP and GATT services */
    ble_svc_gap_init();
    ble_svc_gatt_init();

    /* Register our provisioning GATT service */
    int rc = ble_gatts_count_cfg(s_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_count_cfg failed: %d", rc);
        return ESP_FAIL;
    }

    rc = ble_gatts_add_svcs(s_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_add_svcs failed: %d", rc);
        return ESP_FAIL;
    }

    /* Build device name — will use fallback until host syncs and we
     * get the real address in prov_on_sync, but we set GAP name here */
    snprintf(s_device_name, sizeof(s_device_name),
             "%s-INIT", CONFIG_WENDY_BLE_PROV_DEVICE_PREFIX);
    ble_svc_gap_device_name_set(s_device_name);

    /* Start the NimBLE host task */
    nimble_port_freertos_init(ble_host_task);
    s_nimble_ready = true;

    /* After a short delay the host will sync and we can read the MAC.
     * We defer building the real name to the sync callback context,
     * but we need the host task running first. We'll update the name
     * on first advertising. */

    ESP_LOGI(TAG, "BLE provisioning initialized");
    return ESP_OK;
}

void wendy_ble_prov_set_status(wendy_ble_prov_status_t status, const char *ip_addr)
{
    s_status_val[0] = (uint8_t)status;
    if (status == WENDY_BLE_PROV_STATUS_CONNECTED && ip_addr) {
        int ip_len = strlen(ip_addr);
        if (ip_len > (int)sizeof(s_status_val) - 1) {
            ip_len = sizeof(s_status_val) - 1;
        }
        memcpy(&s_status_val[1], ip_addr, ip_len);
        s_status_val_len = 1 + ip_len;
    } else {
        s_status_val_len = 1;
    }

    /* Send notification if a client is subscribed */
    if (s_conn_handle != 0xFFFF && s_status_chr_val_handle != 0) {
        struct os_mbuf *om = ble_hs_mbuf_from_flat(s_status_val, s_status_val_len);
        if (om) {
            ble_gatts_notify_custom(s_conn_handle, s_status_chr_val_handle, om);
        }
    }

    ESP_LOGI(TAG, "status updated: %d%s%s", status,
             ip_addr ? " ip=" : "", ip_addr ? ip_addr : "");
}

bool wendy_ble_prov_nimble_ready(void)
{
    return s_nimble_ready;
}

#else /* BLE prov not enabled */

esp_err_t wendy_ble_prov_init(const wendy_ble_prov_callbacks_t *callbacks)
{
    (void)callbacks;
    return ESP_ERR_NOT_SUPPORTED;
}

void wendy_ble_prov_set_status(wendy_ble_prov_status_t status, const char *ip_addr)
{
    (void)status;
    (void)ip_addr;
}

bool wendy_ble_prov_nimble_ready(void)
{
    return false;
}

#endif /* CONFIG_WENDY_BLE_PROV */
