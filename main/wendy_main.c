#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_partition.h"
#include "nvs_flash.h"

#include "esp_netif.h"

#include "wendy_wasm.h"
#include "wendy_hal.h"
#include "wendy_hal_export.h"

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#endif

#if CONFIG_WENDY_NET
#include "wendy_net.h"
#endif

#if CONFIG_WENDY_USB_CDC_ENABLED
#include "wendy_usb.h"
#endif

#if CONFIG_WENDY_WIFI_ENABLED
#include "wendy_wifi.h"
#include "wendy_com.h"
#endif

#if CONFIG_WENDY_CLOUD_PROV
#include "wendy_cloud_prov.h"
#endif

#if CONFIG_WENDY_BLE_PROV
#include "wendy_ble_prov.h"
#include "nvs.h"
#endif

static const char *TAG = "wendy_main";

/* ── Event bits ─────────────────────────────────────────────────────── */

#if CONFIG_WENDY_USB_CDC_ENABLED
#define EVT_RUN_REQUEST       BIT0
#define EVT_STOP_REQUEST      BIT1
#define EVT_RESET_REQUEST     BIT2
#endif
#define EVT_PROV_WIFI_CREDS   BIT3
#define EVT_PROV_CLEAR_CREDS  BIT4

static EventGroupHandle_t s_events;

/* ── WASM app state ─────────────────────────────────────────────────── */

static wendy_wasm_module_handle_t s_current_module = NULL;
static pthread_t s_wasm_exec_thread;
static atomic_bool s_wasm_active = false;
static atomic_bool s_wasm_flash_busy = false;
static bool s_current_module_flash_backed = false;
static bool wasm_app_auto_start_enabled = true;

/* ── Flash-write session (one upload at a time, USB or WiFi) ──────────── */

static const esp_partition_t *s_persist_part = NULL;
static uint8_t s_persist_slot = 0;
static bool s_persist_load_pending = false;
static uint8_t s_persist_load_slot = 0;

#define WENDY_WASM_THREAD_STACK_SIZE 8192

static void reset_guest_resources(void)
{
#if CONFIG_WENDY_NET
    wendy_net_guest_reset();
#endif
#if CONFIG_WENDY_HAL_TIMER
    wendy_hal_timer_cancel_all();
#endif
#if CONFIG_WENDY_HAL_RMT
    wendy_hal_rmt_release_all();
#endif
#if CONFIG_WENDY_CALLBACK
    wendy_callback_reset();
#endif
}

static void mark_current_module_unloaded(void)
{
    s_current_module = NULL;
    s_current_module_flash_backed = false;
    s_wasm_flash_busy = false;
}

static void stop_current_module_for_flash_write(void)
{
    if (s_current_module && s_wasm_active) {
        ESP_LOGI(TAG, "stopping flash-backed WASM before flash write...");
        wendy_wasm_stop(s_current_module);
    }
}

/* Spin until the WASM exec thread observes the stop and clears s_wasm_active,
 * or the timeout expires. Returns false (and logs) if the guest hung. */
static bool wait_for_wasm_inactive(uint32_t timeout_ms)
{
    const uint32_t step_ms = 100;
    const uint32_t steps = (timeout_ms + step_ms - 1) / step_ms;
    for (uint32_t i = 0; i < steps && s_wasm_active; i++) {
        vTaskDelay(pdMS_TO_TICKS(step_ms));
    }
    if (s_wasm_active) {
        ESP_LOGW(TAG, "WASM guest still active after %lums; continuing anyway",
                 (unsigned long)timeout_ms);
        return false;
    }
    return true;
}

static esp_err_t load_wasm_module_from_flash(const char *partition_label,
                                             wendy_wasm_module_handle_t *out)
{
    s_wasm_flash_busy = true;
    esp_err_t err = wendy_wasm_load_from_partition(partition_label, out);
    if (err != ESP_OK) {
        s_wasm_flash_busy = false;
    }
    return err;
}

/* ── Transport-agnostic flash-write API ────────────────────────────────
 *
 * Both USB and WiFi upload paths drive this. Begin reserves the partition
 * (after stopping any flash-backed guest), chunks append, end signals the
 * main loop to load the new slot, abort invalidates the size header so a
 * partially-written partition won't be picked up.
 */

static const char *partition_label_for(uint8_t slot)
{
    return (slot == 0) ? "wasm_a" : "wasm_b";
}

static esp_err_t wasm_persist_begin(uint8_t slot, uint32_t total_len)
{
    if (s_persist_part) {
        ESP_LOGE(TAG, "persist session already active");
        return ESP_ERR_INVALID_STATE;
    }
    if (slot != 0) {
        return ESP_ERR_NOT_FOUND;
    }
    if (total_len == 0) {
        return ESP_ERR_INVALID_SIZE;
    }

    /* Stop any flash-backed guest before erasing under it. */
    stop_current_module_for_flash_write();
    for (int i = 0; i < 100 && s_wasm_flash_busy; i++) {
        stop_current_module_for_flash_write();
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (s_wasm_flash_busy) {
        ESP_LOGE(TAG, "timed out waiting for flash-backed WASM to stop");
        return ESP_ERR_TIMEOUT;
    }

    const char *label = partition_label_for(slot);
    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, 0x80 + slot, label);
    if (!part) {
        ESP_LOGE(TAG, "partition '%s' not found", label);
        return ESP_ERR_NOT_FOUND;
    }
    if (total_len + sizeof(uint32_t) > part->size) {
        ESP_LOGE(TAG, "binary too large for partition (%lu > %lu)",
                 (unsigned long)total_len, (unsigned long)part->size);
        return ESP_ERR_INVALID_SIZE;
    }

    /* Only erase as many sectors as the incoming binary actually needs.
     * Erasing the whole partition makes the P4's 12 MiB wasm_a slot take
     * ~40 s of NOR erase, during which cross-core IPC for cache disable
     * starves the ESP-Hosted SDIO link to the C6 and the host
     * eventually resets itself. Leaving the tail un-erased is safe -
     * the loader reads only sizeof(uint32_t) + wasm_len bytes from the
     * start of the partition. */
    const uint32_t needed = total_len + sizeof(uint32_t);
    const uint32_t sector = part->erase_size ? part->erase_size : 4096;
    const uint32_t erase_len = (needed + sector - 1) & ~(sector - 1);
    esp_err_t err = esp_partition_erase_range(part, 0, erase_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "erase failed: %s", esp_err_to_name(err));
        return err;
    }
    err = esp_partition_write(part, 0, &total_len, sizeof(total_len));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "size header write failed: %s", esp_err_to_name(err));
        return err;
    }

    s_persist_part = part;
    s_persist_slot = slot;
    ESP_LOGI(TAG, "persist begin: slot=%d size=%lu (erased %lu of %lu bytes)",
             slot, (unsigned long)total_len,
             (unsigned long)erase_len, (unsigned long)part->size);
    return ESP_OK;
}

static esp_err_t wasm_persist_chunk(uint32_t offset, const uint8_t *data, uint32_t len)
{
    if (!s_persist_part) {
        return ESP_ERR_INVALID_STATE;
    }
    return esp_partition_write(s_persist_part,
                               sizeof(uint32_t) + offset, data, len);
}

static esp_err_t wasm_persist_end(uint8_t slot)
{
    if (!s_persist_part || slot != s_persist_slot) {
        return ESP_ERR_INVALID_STATE;
    }
    s_persist_part = NULL;
    s_persist_load_slot = slot;
    s_persist_load_pending = true;
    ESP_LOGI(TAG, "persist end: slot=%d", slot);
    return ESP_OK;
}

static void wasm_persist_abort(uint8_t slot)
{
    if (!s_persist_part) return;
    (void)slot;
    /* Zero the size header so load_from_partition rejects the slot.
     * 1->0 bit transitions are always legal on NOR flash, no erase needed. */
    uint32_t zero = 0;
    esp_partition_write(s_persist_part, 0, &zero, sizeof(zero));
    s_persist_part = NULL;
    ESP_LOGW(TAG, "persist abort: slot=%d (size header invalidated)", s_persist_slot);
}

/* ── BLE provisioning state ─────────────────────────────────────────── */

#if CONFIG_WENDY_BLE_PROV
static char s_ble_prov_ssid[33];
static char s_ble_prov_pass[65];

static void on_ble_wifi_creds(const char *ssid, const char *password)
{
    strlcpy(s_ble_prov_ssid, ssid, sizeof(s_ble_prov_ssid));
    strlcpy(s_ble_prov_pass, password, sizeof(s_ble_prov_pass));
    xEventGroupSetBits(s_events, EVT_PROV_WIFI_CREDS);
}

static void on_ble_clear_creds(void)
{
    xEventGroupSetBits(s_events, EVT_PROV_CLEAR_CREDS);
}
#endif /* CONFIG_WENDY_BLE_PROV */

/* ── stdout redirect ────────────────────────────────────────────────── */

static void wasm_output_cb(const char *data, uint32_t len, void *ctx)
{
#if CONFIG_WENDY_USB_CDC_ENABLED
    wendy_usb_send_stdout(data, len);
#endif
    fwrite(data, 1, len, stdout);
    fflush(stdout);
}

/* ── USB protocol callbacks ─────────────────────────────────────────── */

#if CONFIG_WENDY_USB_CDC_ENABLED
static void on_run(void)  { xEventGroupSetBits(s_events, EVT_RUN_REQUEST); }
static void on_stop(void) { xEventGroupSetBits(s_events, EVT_STOP_REQUEST); }
static void on_reset(void){ xEventGroupSetBits(s_events, EVT_RESET_REQUEST); }
#endif /* CONFIG_WENDY_USB_CDC_ENABLED */

/* -- WASM execution ---------------------------------------------------- */

/* Runs WASM code on a dedicated pthread */
static void *wasm_exec_thread_entry(void *arg)
{
    wendy_wasm_module_handle_t module = (wendy_wasm_module_handle_t)arg;

    esp_err_t err = wendy_wasm_run(module);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WASM execution failed");
    } else {
        ESP_LOGI(TAG, "WASM execution completed normally");
    }

    reset_guest_resources();
    if (s_current_module_flash_backed) {
        s_wasm_flash_busy = false;
    }
    s_wasm_active = false;
    return NULL;
}

static bool start_loaded_wasm_module(void)
{
    ESP_LOGI(TAG, "running WASM module on dedicated execution thread");

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, WENDY_WASM_THREAD_STACK_SIZE);

    /* Set before pthread_create so the management thread, which polls
     * s_wasm_active after wendy_wasm_stop(), cannot observe a stale false. */
    s_wasm_active = true;
    int ret = pthread_create(&s_wasm_exec_thread, &attr,
                             wasm_exec_thread_entry, s_current_module);
    pthread_attr_destroy(&attr);
    if (ret != 0) {
        ESP_LOGE(TAG, "failed to create WASM execution thread");
        s_wasm_active = false;
        return false;
    }
    pthread_detach(s_wasm_exec_thread);
    return true;
}

static void wasm_app_stop(void)
{
    if (!s_current_module) return;
    wendy_wasm_stop(s_current_module);
    wait_for_wasm_inactive(5000);
    reset_guest_resources();
    wendy_wasm_unload(s_current_module);
    mark_current_module_unloaded();
}

static esp_err_t wasm_app_start(uint8_t slot)
{
    static bool initialized;

    wasm_app_stop();

    ESP_LOGI(TAG, "loading WASM from flash slot %d...", slot);

    if (initialized) {
        wendy_wasm_reinit();
    } else {
        /* Initialize the WASM runtime — must be in pthread context */
        wendy_wasm_config_t wasm_cfg = WENDY_WASM_CONFIG_DEFAULT();
        wasm_cfg.output_cb  = wasm_output_cb;
        wasm_cfg.output_ctx = NULL;

        esp_err_t err = wendy_wasm_init(&wasm_cfg);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "WASM runtime init failed");
            return err;
        }

        initialized = true;
    }

    /* Register HAL native functions with WAMR */
    esp_err_t err = wendy_hal_export_init();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "some HAL exports failed to register");
        return err;
    }

    wendy_wasm_module_handle_t flash_module = NULL;
    err = load_wasm_module_from_flash(partition_label_for(slot), &flash_module);
    if (err == ESP_OK) {
        s_current_module = flash_module;
        s_current_module_flash_backed = true;
        if (!start_loaded_wasm_module()) {
            wendy_wasm_unload(s_current_module);
            mark_current_module_unloaded();
            return ESP_FAIL;
        }
    } else {
        ESP_LOGE(TAG, "failed to load WASM from flash: %s", esp_err_to_name(err));
        return err;
    }

    return ESP_OK;
}

static void wasm_app_auto_start(struct wcom_operation *op)
{
    if (wasm_app_auto_start_enabled) {
        wasm_app_auto_start_enabled = false;
        esp_err_t err = wasm_app_start(0);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "auto-start WASM app failed: %s", esp_err_to_name(err));
        }
    }
}

/* ── App delegate (wendy_com protocol callbacks) ───────────────────── */

static WendyComResult com_push_begin(size_t size)
{
    wasm_app_auto_start_enabled = false;
    esp_err_t e = wasm_persist_begin(0, (uint32_t)size);
    return e == ESP_OK ? WendyComResult_WENDY_COM_RESULT_OK
                       : WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
}

static WendyComResult com_push_data(size_t offset, const uint8_t *data, size_t size)
{
    wasm_app_auto_start_enabled = false;
    esp_err_t e = wasm_persist_chunk((uint32_t)offset, data, (uint32_t)size);
    return e == ESP_OK ? WendyComResult_WENDY_COM_RESULT_OK
                       : WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
}

static WendyComResult com_push_end(void)
{
    wasm_app_auto_start_enabled = false;
    esp_err_t e = wasm_persist_end(0);
    return e == ESP_OK ? WendyComResult_WENDY_COM_RESULT_OK
                       : WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
}

static void com_push_abort(void)
{
    wasm_persist_abort(0);
}

static WendyComResult com_app_start(void)
{
    wasm_app_auto_start_enabled = false;
    uint8_t slot = 0;
    if (s_persist_load_pending) {
        slot = s_persist_load_slot;
        s_persist_load_pending = false;
    }
    esp_err_t e = wasm_app_start(slot);
    return e == ESP_OK ? WendyComResult_WENDY_COM_RESULT_OK
                       : WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
}

static WendyComResult com_app_stop(void)
{
    wasm_app_auto_start_enabled = false;
    wasm_app_stop();
    return WendyComResult_WENDY_COM_RESULT_OK;
}

static WendyComResult com_reboot(void)
{
    wasm_app_auto_start_enabled = false;
    wasm_app_stop();
    esp_restart();
    return WendyComResult_WENDY_COM_RESULT_OK;
}

/* ── HAL initialization ─────────────────────────────────────────────── */

static void init_hal(void)
{
#if CONFIG_WENDY_HAL_I2C
    int ret = wendy_hal_i2c_init(
        CONFIG_WENDY_HAL_I2C_PORT,
        CONFIG_WENDY_HAL_I2C_SDA,
        CONFIG_WENDY_HAL_I2C_SCL,
        CONFIG_WENDY_HAL_I2C_FREQ_HZ);
    if (ret != 0) {
        ESP_LOGW(TAG, "I2C init failed (may not have hardware connected)");
    }
#endif
}

/* ── Entry point ────────────────────────────────────────────────────── */

void app_main(void)
{
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "  Wendy MCU Firmware v%d.%d.%d",
             CONFIG_WENDY_FIRMWARE_VERSION_MAJOR,
             CONFIG_WENDY_FIRMWARE_VERSION_MINOR,
             CONFIG_WENDY_FIRMWARE_VERSION_PATCH);
    ESP_LOGI(TAG, "  WASM Runtime: WAMR (C)");
    ESP_LOGI(TAG, "  Target: %s", CONFIG_IDF_TARGET);
    ESP_LOGI(TAG, "========================================");

    /* NVS */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    s_events = xEventGroupCreate();

    /* Pre-allocate the WAMR memory pool while RAM is still plentiful,
     * before WiFi and BLE claim large chunks. */
    err = wendy_wasm_prealloc_pool(CONFIG_WENDY_WASM_POOL_SIZE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WAMR pool pre-allocation failed");
    }

    /* Initialize hardware */
    init_hal();

    /* Initialize USB CDC protocol (if enabled) */
#if CONFIG_WENDY_USB_CDC_ENABLED
    wendy_usb_callbacks_t usb_cbs = {
        .on_upload_begin  = wasm_persist_begin,
        .on_upload_chunk  = wasm_persist_chunk,
        .on_upload_end    = wasm_persist_end,
        .on_upload_abort  = wasm_persist_abort,
        .on_run           = on_run,
        .on_stop          = on_stop,
        .on_reset         = on_reset,
    };
    err = wendy_usb_init(&usb_cbs);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "USB CDC init failed (running headless)");
    }
#endif

    /* Initialize cloud provisioning (must be before BLE so locked flag is ready) */
#if CONFIG_WENDY_CLOUD_PROV
    err = wendy_cloud_prov_init();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "cloud provisioning init failed");
    }
#endif

    /* Initialize BLE provisioning and discovery (if enabled) */
#if CONFIG_WENDY_BLE_PROV
    wendy_ble_prov_callbacks_t ble_prov_cbs = {
        .on_wifi_creds  = on_ble_wifi_creds,
        .on_clear_creds = on_ble_clear_creds,
    };
    err = wendy_ble_prov_init(&ble_prov_cbs);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "BLE provisioning init failed");
    }
#endif

    /* Initialize main com infrastructure */
    static const struct wcom_app_delegate app_delegate = {
        .on_app_push_begin = com_push_begin,
        .on_app_push_data  = com_push_data,
        .on_app_push_end   = com_push_end,
        .on_app_push_abort = com_push_abort,
        .on_app_start      = com_app_start,
        .on_app_stop       = com_app_stop,
        .on_reboot         = com_reboot,
    };
    wcom_set_app_delegate(&app_delegate);
    wcom_start();

    /* Initialize WiFi transport (if enabled) */
#if CONFIG_WENDY_WIFI_ENABLED
    err = wendy_wifi_init();
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "WiFi connected");
#if CONFIG_WENDY_BLE_PROV
        /* Get IP address for BLE status */
        esp_netif_ip_info_t ip_info;
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
            wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_CONNECTED, ip_str);
        } else {
            wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_CONNECTED, NULL);
        }
#endif
    } else if (err == WENDY_WIFI_ERR_NO_CREDS) {
        ESP_LOGW(TAG, "no WiFi credentials, waiting for BLE provisioning...");
#if CONFIG_WENDY_BLE_PROV
        wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_NO_CREDS, NULL);

        /* Provisioning wait loop — blocks until WiFi connects via BLE */
        bool provisioned = false;
        while (!provisioned) {
            EventBits_t bits = xEventGroupWaitBits(
                s_events,
                EVT_PROV_WIFI_CREDS | EVT_PROV_CLEAR_CREDS,
                pdTRUE, pdFALSE, portMAX_DELAY);

            if (bits & EVT_PROV_CLEAR_CREDS) {
                ESP_LOGI(TAG, "clearing saved WiFi credentials");
                nvs_handle_t nvs;
                if (nvs_open("wendy_prov", NVS_READWRITE, &nvs) == ESP_OK) {
                    nvs_erase_all(nvs);
                    nvs_commit(nvs);
                    nvs_close(nvs);
                }
                wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_NO_CREDS, NULL);
            }

            if (bits & EVT_PROV_WIFI_CREDS) {
                ESP_LOGI(TAG, "BLE provisioning: connecting to '%s'...", s_ble_prov_ssid);
                wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_CONNECTING, NULL);

                esp_err_t conn_err = wendy_wifi_try_connect(s_ble_prov_ssid, s_ble_prov_pass);
                if (conn_err == ESP_OK) {
                    esp_netif_ip_info_t ip_info;
                    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
                    if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
                        char ip_str[16];
                        snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
                        wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_CONNECTED, ip_str);
                    } else {
                        wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_CONNECTED, NULL);
                    }
                    provisioned = true;
                } else {
                    ESP_LOGW(TAG, "BLE provisioning: WiFi connection failed");
                    wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_FAILED, NULL);
                }
            }
        }
#endif /* CONFIG_WENDY_BLE_PROV */
    } else {
        ESP_LOGW(TAG, "WiFi init failed (running without WiFi)");
#if CONFIG_WENDY_BLE_PROV
        wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_FAILED, NULL);

        /* Enter provisioning wait loop on hard failure too */
        bool provisioned = false;
        while (!provisioned) {
            EventBits_t bits = xEventGroupWaitBits(
                s_events,
                EVT_PROV_WIFI_CREDS | EVT_PROV_CLEAR_CREDS,
                pdTRUE, pdFALSE, portMAX_DELAY);

            if (bits & EVT_PROV_CLEAR_CREDS) {
                nvs_handle_t nvs;
                if (nvs_open("wendy_prov", NVS_READWRITE, &nvs) == ESP_OK) {
                    nvs_erase_all(nvs);
                    nvs_commit(nvs);
                    nvs_close(nvs);
                }
                wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_NO_CREDS, NULL);
            }

            if (bits & EVT_PROV_WIFI_CREDS) {
                wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_CONNECTING, NULL);
                esp_err_t conn_err = wendy_wifi_try_connect(s_ble_prov_ssid, s_ble_prov_pass);
                if (conn_err == ESP_OK) {
                    esp_netif_ip_info_t ip_info;
                    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
                    if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
                        char ip_str[16];
                        snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
                        wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_CONNECTED, ip_str);
                    } else {
                        wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_CONNECTED, NULL);
                    }
                    provisioned = true;
                } else {
                    wendy_ble_prov_set_status(WENDY_BLE_PROV_STATUS_FAILED, NULL);
                }
            }
        }
#endif /* CONFIG_WENDY_BLE_PROV */
    }
#endif /* CONFIG_WENDY_WIFI_ENABLED */

    // Start the wasm app, but we do that from the wcom thread,
    // in order to have all commands executed by the same thread.
    static struct wcom_operation op = {
        .func = wasm_app_auto_start,
    };
    wcom_exec(&op);

    /* app_main returns; FreeRTOS scheduler keeps running */
}
