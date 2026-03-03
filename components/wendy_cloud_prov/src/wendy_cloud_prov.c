#include "wendy_cloud_prov.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"

#if CONFIG_WENDY_CLOUD_PROV && CONFIG_BT_ENABLED && CONFIG_BT_NIMBLE_ENABLED

#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "services/gatt/ble_svc_gatt.h"

static const char *TAG = "wendy_cloud_prov";

#define NVS_NAMESPACE   "wendy_cloud"
#define NVS_KEY_LOCKED  "locked"
#define NVS_KEY_CERT    "cert"
#define NVS_KEY_KEY     "key"
#define NVS_KEY_URL     "url"

#ifndef CONFIG_WENDY_CLOUD_PROV_CERT_BUF_SIZE
#define CONFIG_WENDY_CLOUD_PROV_CERT_BUF_SIZE 2048
#endif

#ifndef CONFIG_WENDY_CLOUD_PROV_KEY_BUF_SIZE
#define CONFIG_WENDY_CLOUD_PROV_KEY_BUF_SIZE 2048
#endif

#ifndef CONFIG_WENDY_CLOUD_PROV_URL_BUF_SIZE
#define CONFIG_WENDY_CLOUD_PROV_URL_BUF_SIZE 256
#endif

/* ── Custom 128-bit UUIDs ──────────────────────────────────────────── */

/* Service:  4e57454e-4459-0002-0000-000000000000  ("WENDY" prefix, service 0002) */
static const ble_uuid128_t s_cloud_svc_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x02, 0x00, 0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e);

/* Certificate: 4e57454e-4459-0002-0001-000000000000 */
static const ble_uuid128_t s_cert_chr_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                     0x02, 0x00, 0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e);

/* Private Key: 4e57454e-4459-0002-0002-000000000000 */
static const ble_uuid128_t s_key_chr_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                     0x02, 0x00, 0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e);

/* Cloud URL: 4e57454e-4459-0002-0003-000000000000 */
static const ble_uuid128_t s_url_chr_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
                     0x02, 0x00, 0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e);

/* Command: 4e57454e-4459-0002-0004-000000000000 */
static const ble_uuid128_t s_cmd_chr_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
                     0x02, 0x00, 0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e);

/* Status: 4e57454e-4459-0002-0005-000000000000 */
static const ble_uuid128_t s_status_chr_uuid =
    BLE_UUID128_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
                     0x02, 0x00, 0x59, 0x44, 0x4e, 0x45, 0x57, 0x4e);

/* ── State ──────────────────────────────────────────────────────────── */

static bool s_provisioned = false;

/* Receive buffers (chunked writes append here) */
static char s_cert_buf[CONFIG_WENDY_CLOUD_PROV_CERT_BUF_SIZE];
static size_t s_cert_len = 0;

static char s_key_buf[CONFIG_WENDY_CLOUD_PROV_KEY_BUF_SIZE];
static size_t s_key_len = 0;

static char s_url_buf[CONFIG_WENDY_CLOUD_PROV_URL_BUF_SIZE];
static size_t s_url_len = 0;

/* Status characteristic */
static uint8_t s_status_val = WENDY_CLOUD_PROV_NOT_PROVISIONED;
static uint16_t s_status_chr_val_handle;

/* ── Helpers ────────────────────────────────────────────────────────── */

static void set_status(wendy_cloud_prov_status_t status)
{
    s_status_val = (uint8_t)status;

    if (s_status_chr_val_handle != 0) {
        ble_gatts_chr_updated(s_status_chr_val_handle);
    }

    ESP_LOGI(TAG, "status: %d", status);
}

static void reset_buffers(void)
{
    s_cert_len = 0;
    s_key_len = 0;
    s_url_len = 0;
    memset(s_cert_buf, 0, sizeof(s_cert_buf));
    memset(s_key_buf, 0, sizeof(s_key_buf));
    memset(s_url_buf, 0, sizeof(s_url_buf));
}

static esp_err_t commit_to_nvs(void)
{
    if (s_cert_len == 0 || s_key_len == 0 || s_url_len == 0) {
        ESP_LOGE(TAG, "commit failed: cert=%d key=%d url=%d",
                 (int)s_cert_len, (int)s_key_len, (int)s_url_len);
        return ESP_ERR_INVALID_STATE;
    }

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_blob(nvs, NVS_KEY_CERT, s_cert_buf, s_cert_len);
    if (err != ESP_OK) goto fail;

    err = nvs_set_blob(nvs, NVS_KEY_KEY, s_key_buf, s_key_len);
    if (err != ESP_OK) goto fail;

    /* Null-terminate URL for nvs_set_str */
    s_url_buf[s_url_len] = '\0';
    err = nvs_set_str(nvs, NVS_KEY_URL, s_url_buf);
    if (err != ESP_OK) goto fail;

    /* Write locked flag last for atomicity */
    err = nvs_set_u8(nvs, NVS_KEY_LOCKED, 1);
    if (err != ESP_OK) goto fail;

    err = nvs_commit(nvs);
    if (err != ESP_OK) goto fail;

    nvs_close(nvs);
    s_provisioned = true;
    ESP_LOGI(TAG, "cloud provisioning committed to NVS");
    return ESP_OK;

fail:
    ESP_LOGE(TAG, "NVS write failed: %s", esp_err_to_name(err));
    nvs_close(nvs);
    return err;
}

/* ── GATT access callbacks ─────────────────────────────────────────── */

static int gatt_cert_access(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    if (s_provisioned) {
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
    if (s_cert_len + om_len > sizeof(s_cert_buf)) {
        ESP_LOGE(TAG, "cert buffer overflow");
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    ble_hs_mbuf_to_flat(ctxt->om, s_cert_buf + s_cert_len,
                         sizeof(s_cert_buf) - s_cert_len, &om_len);
    s_cert_len += om_len;
    set_status(WENDY_CLOUD_PROV_RECEIVING);
    ESP_LOGD(TAG, "cert chunk: +%d = %d total", om_len, (int)s_cert_len);
    return 0;
}

static int gatt_key_access(uint16_t conn_handle, uint16_t attr_handle,
                            struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    if (s_provisioned) {
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
    if (s_key_len + om_len > sizeof(s_key_buf)) {
        ESP_LOGE(TAG, "key buffer overflow");
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    ble_hs_mbuf_to_flat(ctxt->om, s_key_buf + s_key_len,
                         sizeof(s_key_buf) - s_key_len, &om_len);
    s_key_len += om_len;
    set_status(WENDY_CLOUD_PROV_RECEIVING);
    ESP_LOGD(TAG, "key chunk: +%d = %d total", om_len, (int)s_key_len);
    return 0;
}

static int gatt_url_access(uint16_t conn_handle, uint16_t attr_handle,
                            struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    if (s_provisioned) {
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
    /* Reserve 1 byte for null terminator */
    if (s_url_len + om_len >= sizeof(s_url_buf)) {
        ESP_LOGE(TAG, "url buffer overflow");
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    ble_hs_mbuf_to_flat(ctxt->om, s_url_buf + s_url_len,
                         sizeof(s_url_buf) - s_url_len - 1, &om_len);
    s_url_len += om_len;
    set_status(WENDY_CLOUD_PROV_RECEIVING);
    ESP_LOGD(TAG, "url chunk: +%d = %d total", om_len, (int)s_url_len);
    return 0;
}

static int gatt_cmd_access(uint16_t conn_handle, uint16_t attr_handle,
                            struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    if (s_provisioned) {
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
    if (om_len < 1) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;

    uint8_t cmd;
    ble_hs_mbuf_to_flat(ctxt->om, &cmd, 1, &om_len);

    if (cmd == 0x01) {
        /* Commit */
        ESP_LOGI(TAG, "commit command received");
        esp_err_t err = commit_to_nvs();
        if (err == ESP_OK) {
            set_status(WENDY_CLOUD_PROV_COMMITTED);
        } else {
            set_status(WENDY_CLOUD_PROV_FAILED);
        }
    } else if (cmd == 0xFF) {
        /* Reset buffers */
        ESP_LOGI(TAG, "reset buffers command received");
        reset_buffers();
        set_status(WENDY_CLOUD_PROV_NOT_PROVISIONED);
    } else {
        ESP_LOGW(TAG, "unknown command: 0x%02x", cmd);
    }

    return 0;
}

static int gatt_status_access(uint16_t conn_handle, uint16_t attr_handle,
                               struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        int rc = os_mbuf_append(ctxt->om, &s_status_val, 1);
        return (rc == 0) ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

/* ── GATT service table ────────────────────────────────────────────── */

static const struct ble_gatt_svc_def s_cloud_gatt_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &s_cloud_svc_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                /* Certificate - write only (chunked append) */
                .uuid = &s_cert_chr_uuid.u,
                .access_cb = gatt_cert_access,
                .flags = BLE_GATT_CHR_F_WRITE,
            },
            {
                /* Private Key - write only (chunked append) */
                .uuid = &s_key_chr_uuid.u,
                .access_cb = gatt_key_access,
                .flags = BLE_GATT_CHR_F_WRITE,
            },
            {
                /* Cloud URL - write only */
                .uuid = &s_url_chr_uuid.u,
                .access_cb = gatt_url_access,
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
            { 0 }, /* sentinel */
        },
    },
    { 0 }, /* sentinel */
};

/* ── Public API ─────────────────────────────────────────────────────── */

esp_err_t wendy_cloud_prov_init(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGI(TAG, "no cloud provisioning data in NVS");
        s_provisioned = false;
        return ESP_OK;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        s_provisioned = false;
        return ESP_OK;
    }

    uint8_t locked = 0;
    err = nvs_get_u8(nvs, NVS_KEY_LOCKED, &locked);
    nvs_close(nvs);

    if (err == ESP_OK && locked == 1) {
        s_provisioned = true;
        s_status_val = WENDY_CLOUD_PROV_ALREADY_LOCKED;
        ESP_LOGI(TAG, "device is cloud-provisioned");
    } else {
        s_provisioned = false;
        ESP_LOGI(TAG, "device is not cloud-provisioned");
    }

    return ESP_OK;
}

esp_err_t wendy_cloud_prov_register_gatt(void)
{
    int rc = ble_gatts_count_cfg(s_cloud_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_count_cfg failed: %d", rc);
        return ESP_FAIL;
    }

    rc = ble_gatts_add_svcs(s_cloud_gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_add_svcs failed: %d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "cloud prov GATT service registered");
    return ESP_OK;
}

bool wendy_cloud_is_provisioned(void)
{
    return s_provisioned;
}

esp_err_t wendy_cloud_get_url(char *buf, size_t buf_len)
{
    if (!s_provisioned) return ESP_ERR_INVALID_STATE;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return err;

    err = nvs_get_str(nvs, NVS_KEY_URL, buf, &buf_len);
    nvs_close(nvs);
    return err;
}

esp_err_t wendy_cloud_get_cert(char *buf, size_t buf_len, size_t *out_len)
{
    if (!s_provisioned) return ESP_ERR_INVALID_STATE;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return err;

    size_t len = buf_len;
    err = nvs_get_blob(nvs, NVS_KEY_CERT, buf, &len);
    nvs_close(nvs);

    if (err == ESP_OK && out_len) {
        *out_len = len;
    }
    return err;
}

esp_err_t wendy_cloud_get_key(char *buf, size_t buf_len, size_t *out_len)
{
    if (!s_provisioned) return ESP_ERR_INVALID_STATE;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return err;

    size_t len = buf_len;
    err = nvs_get_blob(nvs, NVS_KEY_KEY, buf, &len);
    nvs_close(nvs);

    if (err == ESP_OK && out_len) {
        *out_len = len;
    }
    return err;
}

#else /* Cloud prov not enabled */

esp_err_t wendy_cloud_prov_init(void)
{
    return ESP_OK;
}

esp_err_t wendy_cloud_prov_register_gatt(void)
{
    return ESP_ERR_NOT_SUPPORTED;
}

bool wendy_cloud_is_provisioned(void)
{
    return false;
}

esp_err_t wendy_cloud_get_url(char *buf, size_t buf_len)
{
    (void)buf; (void)buf_len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t wendy_cloud_get_cert(char *buf, size_t buf_len, size_t *out_len)
{
    (void)buf; (void)buf_len; (void)out_len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t wendy_cloud_get_key(char *buf, size_t buf_len, size_t *out_len)
{
    (void)buf; (void)buf_len; (void)out_len;
    return ESP_ERR_NOT_SUPPORTED;
}

#endif /* CONFIG_WENDY_CLOUD_PROV */
