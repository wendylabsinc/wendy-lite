#include "wendy_storage.h"

#include <string.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "wasm_export.h"
#include "wendy_safety.h"

static const char *TAG = "wendy_storage";

#define NVS_NAMESPACE "wendy_app"
#define STORAGE_WRITE_RATE 10  /* max writes per second */

static nvs_handle_t s_nvs_handle;
static bool s_initialized = false;

esp_err_t wendy_storage_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &s_nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return err;
    }
    s_initialized = true;
    ESP_LOGI(TAG, "NVS storage initialized (namespace=%s)", NVS_NAMESPACE);
    return ESP_OK;
}

/* storage_get(key_ptr, key_len, val_ptr, val_len) -> i32 (bytes read, or -1) */
static int storage_get_wrapper(wasm_exec_env_t exec_env,
                                const char *key, int key_len,
                                char *val, int val_len)
{
    if (!s_initialized || !key || key_len <= 0 || !val || val_len <= 0) {
        return -1;
    }

    /* Build null-terminated key */
    char key_buf[64];
    if (key_len >= (int)sizeof(key_buf)) {
        key_len = sizeof(key_buf) - 1;
    }
    memcpy(key_buf, key, key_len);
    key_buf[key_len] = '\0';

    size_t required = val_len;
    esp_err_t err = nvs_get_blob(s_nvs_handle, key_buf, val, &required);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return 0; /* key not found */
    }
    if (err != ESP_OK) {
        return -1;
    }
    return (int)required;
}

/* storage_set(key_ptr, key_len, val_ptr, val_len) -> i32 (0 ok, -1 err) */
static int storage_set_wrapper(wasm_exec_env_t exec_env,
                                const char *key, int key_len,
                                const char *val, int val_len)
{
    if (!s_initialized || !key || key_len <= 0 || !val || val_len <= 0) {
        return -1;
    }

    if (!wendy_safety_rate_check("storage_write", STORAGE_WRITE_RATE)) {
        ESP_LOGW(TAG, "storage write rate limited");
        return -1;
    }

    char key_buf[64];
    if (key_len >= (int)sizeof(key_buf)) {
        key_len = sizeof(key_buf) - 1;
    }
    memcpy(key_buf, key, key_len);
    key_buf[key_len] = '\0';

    esp_err_t err = nvs_set_blob(s_nvs_handle, key_buf, val, val_len);
    if (err != ESP_OK) {
        return -1;
    }
    nvs_commit(s_nvs_handle);
    return 0;
}

/* storage_delete(key_ptr, key_len) -> i32 */
static int storage_delete_wrapper(wasm_exec_env_t exec_env,
                                   const char *key, int key_len)
{
    if (!s_initialized || !key || key_len <= 0) {
        return -1;
    }

    if (!wendy_safety_rate_check("storage_write", STORAGE_WRITE_RATE)) {
        return -1;
    }

    char key_buf[64];
    if (key_len >= (int)sizeof(key_buf)) {
        key_len = sizeof(key_buf) - 1;
    }
    memcpy(key_buf, key, key_len);
    key_buf[key_len] = '\0';

    esp_err_t err = nvs_erase_key(s_nvs_handle, key_buf);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return 0;
    }
    if (err != ESP_OK) {
        return -1;
    }
    nvs_commit(s_nvs_handle);
    return 0;
}

/* storage_exists(key_ptr, key_len) -> i32 (1 exists, 0 not found, -1 error) */
static int storage_exists_wrapper(wasm_exec_env_t exec_env,
                                   const char *key, int key_len)
{
    if (!s_initialized || !key || key_len <= 0) {
        return -1;
    }

    char key_buf[64];
    if (key_len >= (int)sizeof(key_buf)) {
        key_len = sizeof(key_buf) - 1;
    }
    memcpy(key_buf, key, key_len);
    key_buf[key_len] = '\0';

    size_t required = 0;
    esp_err_t err = nvs_get_blob(s_nvs_handle, key_buf, NULL, &required);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return 0;
    }
    if (err == ESP_OK || err == ESP_ERR_NVS_INVALID_LENGTH) {
        return 1;
    }
    return -1;
}

static NativeSymbol s_storage_symbols[] = {
    { "storage_get",    (void *)storage_get_wrapper,    "(*~*~)i", NULL },
    { "storage_set",    (void *)storage_set_wrapper,    "(*~*~)i", NULL },
    { "storage_delete", (void *)storage_delete_wrapper, "(*~)i",   NULL },
    { "storage_exists", (void *)storage_exists_wrapper, "(*~)i",   NULL },
};

int wendy_storage_export_init(void)
{
    if (!s_initialized) {
        if (wendy_storage_init() != ESP_OK) {
            return -1;
        }
    }

    if (!wasm_runtime_register_natives("wendy",
                                       s_storage_symbols,
                                       sizeof(s_storage_symbols) / sizeof(s_storage_symbols[0]))) {
        ESP_LOGE(TAG, "failed to register storage natives");
        return -1;
    }
    ESP_LOGI(TAG, "storage exports registered");
    return 0;
}
