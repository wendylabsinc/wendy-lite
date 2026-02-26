#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_partition.h"
#include "nvs_flash.h"

#include "wendy_wasm.h"
#include "wendy_hal.h"
#include "wendy_hal_export.h"

#if CONFIG_WENDY_USB_CDC_ENABLED
#include "wendy_usb.h"
#endif

#if CONFIG_WENDY_WIFI_ENABLED
#include "wendy_wifi.h"
#endif

#if CONFIG_WENDY_DEMO_EMBEDDED
#include "demo_wasm.h"
#endif

static const char *TAG = "wendy_main";

/* ── Event bits ─────────────────────────────────────────────────────── */

#define EVT_UPLOAD_READY   BIT0
#define EVT_RUN_REQUEST    BIT1
#define EVT_STOP_REQUEST   BIT2
#define EVT_RESET_REQUEST  BIT3

static EventGroupHandle_t s_events;

/* ── WASM app state ─────────────────────────────────────────────────── */

static wendy_wasm_module_handle_t s_current_module = NULL;
static uint8_t *s_pending_wasm = NULL;
static uint32_t s_pending_wasm_len = 0;
static pthread_t s_wasm_thread;
static bool s_wasm_thread_active = false;

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
static void on_upload_complete(const uint8_t *data, uint32_t len, uint8_t slot)
{
    ESP_LOGI(TAG, "WASM binary uploaded: %lu bytes, slot %d",
             (unsigned long)len, slot);

    if (s_pending_wasm) {
        free(s_pending_wasm);
    }
    s_pending_wasm = malloc(len);
    if (s_pending_wasm) {
        memcpy(s_pending_wasm, data, len);
        s_pending_wasm_len = len;
        xEventGroupSetBits(s_events, EVT_UPLOAD_READY);
    }

    /* Persist to flash */
    const char *label = (slot == 0) ? "wasm_a" : "wasm_b";
    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, 0x80 + slot, label);
    if (part) {
        esp_partition_erase_range(part, 0, part->size);
        esp_partition_write(part, 0, &len, sizeof(len));
        esp_partition_write(part, sizeof(len), data, len);
        ESP_LOGI(TAG, "persisted to partition '%s'", label);
    }
}

static void on_run(void)  { xEventGroupSetBits(s_events, EVT_RUN_REQUEST); }
static void on_stop(void) { xEventGroupSetBits(s_events, EVT_STOP_REQUEST); }
static void on_reset(void){ xEventGroupSetBits(s_events, EVT_RESET_REQUEST); }
#endif /* CONFIG_WENDY_USB_CDC_ENABLED */

/* ── WiFi callbacks ────────────────────────────────────────────────── */

#if CONFIG_WENDY_WIFI_ENABLED
static void wifi_on_upload_complete(const uint8_t *data, uint32_t len, uint8_t slot)
{
    ESP_LOGI(TAG, "WASM binary downloaded via WiFi: %lu bytes (on flash)",
             (unsigned long)len);

    /* Data was streamed directly to flash — signal the main thread
     * to load from the wasm_a partition instead of from a RAM buffer. */
    if (s_pending_wasm) {
        free(s_pending_wasm);
        s_pending_wasm = NULL;
    }
    s_pending_wasm_len = 0;
    xEventGroupSetBits(s_events, EVT_UPLOAD_READY);
}

static void wifi_on_run(void)  { xEventGroupSetBits(s_events, EVT_RUN_REQUEST); }
static void wifi_on_stop(void) { xEventGroupSetBits(s_events, EVT_STOP_REQUEST); }
static void wifi_on_reset(void){ xEventGroupSetBits(s_events, EVT_RESET_REQUEST); }
#endif /* CONFIG_WENDY_WIFI_ENABLED */

/* ── WASM execution thread ─────────────────────────────────────────── */

static void *wasm_exec_thread(void *arg)
{
    wendy_wasm_module_handle_t module = (wendy_wasm_module_handle_t)arg;

    esp_err_t err = wendy_wasm_run(module);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WASM execution failed");
    } else {
        ESP_LOGI(TAG, "WASM execution completed normally");
    }

    s_wasm_thread_active = false;
    return NULL;
}

static void start_wasm_module(const uint8_t *wasm_buf, uint32_t wasm_len)
{
    if (s_current_module) {
        wendy_wasm_stop(s_current_module);
        for (int i = 0; i < 50 && s_wasm_thread_active; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        wendy_wasm_unload(s_current_module);
        s_current_module = NULL;

        /* Reinitialize WAMR runtime to clear internal state */
        wendy_wasm_reinit();
        wendy_hal_export_init();
    }

    esp_err_t err = wendy_wasm_load(wasm_buf, wasm_len, &s_current_module);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to load WASM module");
        return;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8192);

    s_wasm_thread_active = true;
    int ret = pthread_create(&s_wasm_thread, &attr, wasm_exec_thread, s_current_module);
    pthread_attr_destroy(&attr);
    if (ret != 0) {
        ESP_LOGE(TAG, "failed to create WASM execution thread");
        s_wasm_thread_active = false;
        wendy_wasm_unload(s_current_module);
        s_current_module = NULL;
    } else {
        pthread_detach(s_wasm_thread);
    }
}

/* ── WASM management thread (runs in pthread context for WAMR) ─────── */

static void *wasm_main_thread(void *arg)
{
    /* Initialize the WASM runtime — must be in pthread context */
    wendy_wasm_config_t wasm_cfg = WENDY_WASM_CONFIG_DEFAULT();
    wasm_cfg.output_cb  = wasm_output_cb;
    wasm_cfg.output_ctx = NULL;

    esp_err_t err = wendy_wasm_init(&wasm_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WASM runtime init failed");
        return NULL;
    }

    /* Register HAL native functions with WAMR */
    err = wendy_hal_export_init();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "some HAL exports failed to register");
    }

    /*
     * Boot logic:
     * 1. If WENDY_DEMO_EMBEDDED is set, run the compiled-in demo WASM
     * 2. Otherwise, try loading from flash partition (previous upload)
     * 3. Otherwise, wait for USB upload
     */
#if CONFIG_WENDY_DEMO_EMBEDDED
    /* If WiFi already downloaded a binary before this thread started,
     * skip the embedded demo — the event loop will load from flash. */
    if (xEventGroupGetBits(s_events) & EVT_UPLOAD_READY) {
        ESP_LOGI(TAG, "WiFi download ready, skipping embedded demo");
    } else {
        ESP_LOGI(TAG, "running embedded demo WASM (%lu bytes)...",
                 (unsigned long)demo_wasm_binary_len);
        start_wasm_module(demo_wasm_binary, demo_wasm_binary_len);
    }
#else
    /* If WiFi (or another transport) already set s_pending_wasm before
     * this thread started, skip the flash load and use it directly. */
    if (s_pending_wasm && s_pending_wasm_len > 0) {
        ESP_LOGI(TAG, "WASM binary already pending (%lu bytes), starting...",
                 (unsigned long)s_pending_wasm_len);
        start_wasm_module(s_pending_wasm, s_pending_wasm_len);
    } else {
        wendy_wasm_module_handle_t flash_module = NULL;
        err = wendy_wasm_load_from_partition("wasm_a", &flash_module);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "found WASM binary in flash, auto-starting...");
            s_current_module = flash_module;

            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setstacksize(&attr, 8192);
            s_wasm_thread_active = true;
            if (pthread_create(&s_wasm_thread, &attr, wasm_exec_thread, s_current_module) == 0) {
                pthread_detach(s_wasm_thread);
            } else {
                s_wasm_thread_active = false;
            }
            pthread_attr_destroy(&attr);
        } else {
            ESP_LOGI(TAG, "no WASM binary in flash, waiting for upload...");
        }
    }
#endif

    /* Main event loop */
    for (;;) {
        EventBits_t bits = xEventGroupWaitBits(
            s_events,
            EVT_UPLOAD_READY | EVT_RUN_REQUEST | EVT_STOP_REQUEST | EVT_RESET_REQUEST,
            pdTRUE, pdFALSE, portMAX_DELAY);

        if (bits & EVT_STOP_REQUEST) {
            ESP_LOGI(TAG, "stopping WASM module...");
            if (s_current_module) {
                wendy_wasm_stop(s_current_module);
            }
        }

        if (bits & EVT_RESET_REQUEST) {
            ESP_LOGI(TAG, "resetting device...");
            if (s_current_module) {
                wendy_wasm_stop(s_current_module);
                vTaskDelay(pdMS_TO_TICKS(100));
                wendy_wasm_unload(s_current_module);
                s_current_module = NULL;
            }
            esp_restart();
        }

        if ((bits & EVT_UPLOAD_READY) || (bits & EVT_RUN_REQUEST)) {
            if (s_pending_wasm && s_pending_wasm_len > 0) {
                ESP_LOGI(TAG, "starting WASM module (%lu bytes)...",
                         (unsigned long)s_pending_wasm_len);
                start_wasm_module(s_pending_wasm, s_pending_wasm_len);
            } else if (bits & EVT_UPLOAD_READY) {
                /* WiFi download wrote directly to flash — load from partition */
                ESP_LOGI(TAG, "loading WASM from flash (WiFi download)...");

                /* Stop and wait for execution thread to finish */
                if (s_current_module) {
                    wendy_wasm_stop(s_current_module);
                    for (int i = 0; i < 50 && s_wasm_thread_active; i++) {
                        vTaskDelay(pdMS_TO_TICKS(100));
                    }
                    wendy_wasm_unload(s_current_module);
                    s_current_module = NULL;
                }

                /* Reinitialize WAMR runtime to clear internal state,
                 * then re-register HAL native symbols */
                wendy_wasm_reinit();
                wendy_hal_export_init();

                wendy_wasm_module_handle_t flash_module = NULL;
                esp_err_t lerr = wendy_wasm_load_from_partition("wasm_a", &flash_module);
                if (lerr == ESP_OK) {
                    s_current_module = flash_module;
                    pthread_attr_t a;
                    pthread_attr_init(&a);
                    pthread_attr_setstacksize(&a, 8192);
                    s_wasm_thread_active = true;
                    if (pthread_create(&s_wasm_thread, &a, wasm_exec_thread, s_current_module) == 0) {
                        pthread_detach(s_wasm_thread);
                    } else {
                        s_wasm_thread_active = false;
                    }
                    pthread_attr_destroy(&a);
                } else {
                    ESP_LOGE(TAG, "failed to load WASM from flash");
                }
            }
        }
    }

    return NULL;
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
    ESP_LOGI(TAG, "  Target: ESP32-C6");
    ESP_LOGI(TAG, "========================================");

    /* NVS */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    s_events = xEventGroupCreate();

    /* Initialize hardware */
    init_hal();

    /* Initialize USB CDC protocol (if enabled) */
#if CONFIG_WENDY_USB_CDC_ENABLED
    wendy_usb_callbacks_t usb_cbs = {
        .on_upload_complete = on_upload_complete,
        .on_run             = on_run,
        .on_stop            = on_stop,
        .on_reset           = on_reset,
    };
    err = wendy_usb_init(&usb_cbs);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "USB CDC init failed (running headless)");
    }
#endif

    /* Initialize WiFi transport (if enabled) */
#if CONFIG_WENDY_WIFI_ENABLED
    wendy_wifi_callbacks_t wifi_cbs = {
        .on_upload_complete = wifi_on_upload_complete,
        .on_run             = wifi_on_run,
        .on_stop            = wifi_on_stop,
        .on_reset           = wifi_on_reset,
    };
    err = wendy_wifi_init(&wifi_cbs);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "WiFi init failed (running without WiFi)");
    }
#endif

    /*
     * Spawn the WASM management thread.
     * WAMR internally uses pthread_self() for thread-env tracking,
     * so all WAMR API calls must happen from pthread context —
     * not from the FreeRTOS app_main task.
     */
    pthread_t wasm_main;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 16384);

    int ret = pthread_create(&wasm_main, &attr, wasm_main_thread, NULL);
    pthread_attr_destroy(&attr);
    if (ret != 0) {
        ESP_LOGE(TAG, "failed to create WASM main thread");
        return;
    }
    pthread_detach(wasm_main);

    /* app_main returns; FreeRTOS scheduler keeps running */
}
