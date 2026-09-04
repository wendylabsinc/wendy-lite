#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_attr.h"
#include "esp_system.h"
#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "esp_vfs_eventfd.h"
#include "nvs_flash.h"

#include "wendy_core.h"
#include "wendy_conf.h"

#if CONFIG_WENDY_WASM
#include "wendy_wasm.h"
#include "wendy_hal.h"
#include "wendy_hal_export.h"
#endif

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#endif

#if CONFIG_WENDY_NET
#include "wendy_net.h"
#endif

#include "wendy_stdio.h"

#if CONFIG_WENDY_USJ
#include "wendy_usj.h"
#endif

#if CONFIG_WENDY_WIFI_ENABLED
#include "wendy_wifi.h"
#include "wendy_com.h"
#endif

static const char *TAG = "wendy_core";

/* ── Event bits ─────────────────────────────────────────────────────── */

#define EVT_APP_START_REQUEST BIT6

static EventGroupHandle_t s_events;

/* ── Reboot boot-params ─────────────────────────────────────────────────
 *
 * Written by the REBOOT command right before esp_restart() and consumed by
 * the next boot. They live in LP SRAM, which survives a software reset but
 * not a hardware one, and are one-shot: the magic is invalidated at every
 * boot so any other reboot path (guest sys_reboot(), panic, WDT, ...) comes
 * up with defaults.
 */

#define REBOOT_PARAMS_MAGIC 0xB007C0DEu

typedef struct {
    uint32_t magic;
    uint32_t app_auto_start_delay_ms;
    bool     app_auto_start;
} reboot_params_t;

static RTC_NOINIT_ATTR reboot_params_t s_reboot_params;

/* Captured once at boot; consumed at the end of wendy_core_init(). */
static bool     s_boot_app_auto_start = true;
static uint32_t s_boot_app_auto_start_delay_ms = 0;

static void capture_boot_params(void)
{
    if (esp_reset_reason() == ESP_RST_SW && s_reboot_params.magic == REBOOT_PARAMS_MAGIC) {
        s_boot_app_auto_start          = s_reboot_params.app_auto_start;
        s_boot_app_auto_start_delay_ms = s_reboot_params.app_auto_start_delay_ms;
        ESP_LOGI(TAG, "reboot params: app_auto_start=%d delay=%" PRIu32 "ms",
                 (int)s_boot_app_auto_start, s_boot_app_auto_start_delay_ms);
    }
    s_reboot_params.magic = 0;
}

/* ── WASM app state ─────────────────────────────────────────────────── */

#if CONFIG_WENDY_WASM
static wendy_wasm_module_handle_t s_current_module = NULL;
static pthread_t s_wasm_exec_thread;
static pthread_t s_wasm_control_thread;
static QueueHandle_t s_wasm_control_queue;
static atomic_bool s_wasm_active = false;
static atomic_bool s_wasm_flash_busy = false;
static bool s_current_module_flash_backed = false;
#endif
static bool s_app_auto_start_enabled = true;

/* ── Flash-write session (one upload at a time, USB or WiFi) ──────────── */

#if CONFIG_WENDY_WASM
static const esp_partition_t *s_persist_part = NULL;
static uint8_t s_persist_slot = 0;
#endif
static bool s_persist_load_pending = false;
static uint8_t s_persist_load_slot = 0;
static char s_device_name[CONFIG_WENDY_DEVICE_NAME_BUF_SIZE];

#if CONFIG_WENDY_WASM

#define WENDY_WASM_THREAD_STACK_SIZE 8192
#define WENDY_WASM_CONTROL_QUEUE_LEN 4
#define WENDY_WASM_CONTROL_QUEUE_TIMEOUT_MS 1000
#define WENDY_WASM_CONTROL_RESPONSE_TIMEOUT_MS 10000

typedef enum {
    WASM_CONTROL_START,
    WASM_CONTROL_STOP,
    WASM_CONTROL_STOP_FOR_FLASH,
} wasm_control_command_t;

typedef struct {
    wasm_control_command_t command;
    uint8_t slot;
    esp_err_t result;
    atomic_uint ref_count;
    SemaphoreHandle_t done;
    StaticSemaphore_t done_storage;
} wasm_control_request_t;

static esp_err_t wasm_control_call(wasm_control_command_t command, uint8_t slot);

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
        ESP_LOGW(TAG, "WASM guest still active after %lums; operation aborted",
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

#endif /* CONFIG_WENDY_WASM */

static esp_err_t wasm_persist_begin(uint8_t slot, uint32_t total_len)
{
#if CONFIG_WENDY_WASM
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

    /* Stop any flash-backed guest before erasing under it. WAMR's stop API
     * must run from the same pthread-owned control path as the rest of its
     * lifecycle, not directly from the FreeRTOS transport task. */
    esp_err_t control_err = wasm_control_call(WASM_CONTROL_STOP_FOR_FLASH, 0);
    if (control_err != ESP_OK) {
        ESP_LOGE(TAG, "failed to stop flash-backed WASM: %s",
                 esp_err_to_name(control_err));
        return control_err;
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
#else
    (void)slot;
    (void)total_len;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

static esp_err_t wasm_persist_chunk(uint32_t offset, const uint8_t *data, uint32_t len)
{
#if CONFIG_WENDY_WASM
    if (!s_persist_part) {
        return ESP_ERR_INVALID_STATE;
    }
    return esp_partition_write(s_persist_part,
                               sizeof(uint32_t) + offset, data, len);
#else
    (void)offset;
    (void)data;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

static esp_err_t wasm_persist_end(uint8_t slot)
{
#if CONFIG_WENDY_WASM
    if (!s_persist_part || slot != s_persist_slot) {
        return ESP_ERR_INVALID_STATE;
    }
    s_persist_part = NULL;
    s_persist_load_slot = slot;
    s_persist_load_pending = true;
    ESP_LOGI(TAG, "persist end: slot=%d", slot);
    return ESP_OK;
#else
    (void)slot;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

static void wasm_persist_abort(uint8_t slot)
{
    (void)slot;
#if CONFIG_WENDY_WASM
    if (!s_persist_part) return;
    /* Zero the size header so load_from_partition rejects the slot.
     * 1->0 bit transitions are always legal on NOR flash, no erase needed. */
    uint32_t zero = 0;
    esp_partition_write(s_persist_part, 0, &zero, sizeof(zero));
    s_persist_part = NULL;
    ESP_LOGW(TAG, "persist abort: slot=%d (size header invalidated)", s_persist_slot);
#endif
}

/* ── stdout redirect ────────────────────────────────────────────────── */

#if CONFIG_WENDY_WASM
static void wasm_output_cb(const char *data, uint32_t len, void *ctx)
{
    fwrite(data, 1, len, stdout);
    fflush(stdout);
}
#endif /* CONFIG_WENDY_WASM */

/* -- WASM execution ---------------------------------------------------- */

#if CONFIG_WENDY_WASM

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

/* These lifecycle implementations are only called by wasm_control_thread_entry.
 * WAMR uses pthread TLS internally, so invoking them from the raw FreeRTOS wcom
 * task can assert while WAMR reports an otherwise recoverable loader error. */
static esp_err_t wasm_app_stop_on_control_thread(void)
{
    if (!s_current_module) return ESP_OK;
    esp_err_t err = wendy_wasm_stop(s_current_module);
    if (err != ESP_OK) return err;
    if (!wait_for_wasm_inactive(5000)) return ESP_ERR_TIMEOUT;
    reset_guest_resources();
    wendy_wasm_unload(s_current_module);
    mark_current_module_unloaded();
    return ESP_OK;
}

static esp_err_t wasm_app_stop_for_flash_on_control_thread(void)
{
    if (!s_current_module || !s_wasm_active) {
        s_wasm_flash_busy = false;
        return ESP_OK;
    }

    ESP_LOGI(TAG, "stopping flash-backed WASM before flash write...");
    esp_err_t err = wendy_wasm_stop(s_current_module);
    if (err != ESP_OK) return err;
    return wait_for_wasm_inactive(5000) ? ESP_OK : ESP_ERR_TIMEOUT;
}

static esp_err_t wasm_app_start_on_control_thread(uint8_t slot)
{
    static bool initialized;

    esp_err_t err = wasm_app_stop_on_control_thread();
    if (err != ESP_OK) return err;

    ESP_LOGI(TAG, "loading WASM from flash slot %d...", slot);

    if (initialized) {
        err = wendy_wasm_reinit();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "WASM runtime reinit failed");
            return err;
        }
    } else {
        /* Initialize the WASM runtime — must be in pthread context */
        wendy_wasm_config_t wasm_cfg = WENDY_WASM_CONFIG_DEFAULT();
        wasm_cfg.output_cb  = wasm_output_cb;
        wasm_cfg.output_ctx = NULL;

        err = wendy_wasm_init(&wasm_cfg);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "WASM runtime init failed");
            return err;
        }

        initialized = true;
    }

    /* Register HAL native functions with WAMR */
    err = wendy_hal_export_init();
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

static void wasm_control_request_release(wasm_control_request_t *request)
{
    if (atomic_fetch_sub(&request->ref_count, 1) == 1) {
        free(request);
    }
}

static void *wasm_control_thread_entry(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "WAMR lifecycle control thread ready");

    while (true) {
        wasm_control_request_t *request = NULL;
        if (xQueueReceive(s_wasm_control_queue, &request, portMAX_DELAY) != pdTRUE
            || !request) {
            continue;
        }

        switch (request->command) {
        case WASM_CONTROL_START:
            request->result = wasm_app_start_on_control_thread(request->slot);
            break;
        case WASM_CONTROL_STOP:
            request->result = wasm_app_stop_on_control_thread();
            break;
        case WASM_CONTROL_STOP_FOR_FLASH:
            request->result = wasm_app_stop_for_flash_on_control_thread();
            break;
        default:
            request->result = ESP_ERR_INVALID_ARG;
            break;
        }
        xSemaphoreGive(request->done);
        wasm_control_request_release(request);
    }

    return NULL;
}

static esp_err_t wasm_control_call(wasm_control_command_t command, uint8_t slot)
{
    if (!s_wasm_control_queue) return ESP_ERR_INVALID_STATE;

    wasm_control_request_t *request = calloc(1, sizeof(*request));
    if (!request) return ESP_ERR_NO_MEM;
    request->command = command;
    request->slot = slot;
    request->result = ESP_FAIL;
    atomic_init(&request->ref_count, 2); /* caller + control thread */
    request->done = xSemaphoreCreateBinaryStatic(&request->done_storage);
    if (!request->done) {
        free(request);
        return ESP_ERR_NO_MEM;
    }

    if (xQueueSend(s_wasm_control_queue, &request,
                   pdMS_TO_TICKS(WENDY_WASM_CONTROL_QUEUE_TIMEOUT_MS)) != pdTRUE) {
        ESP_LOGE(TAG, "timed out queueing WAMR control command %d", command);
        free(request);
        return ESP_ERR_TIMEOUT;
    }

    if (xSemaphoreTake(request->done,
                       pdMS_TO_TICKS(WENDY_WASM_CONTROL_RESPONSE_TIMEOUT_MS)) != pdTRUE) {
        ESP_LOGE(TAG, "timed out waiting for WAMR control command %d", command);
        wasm_control_request_release(request);
        return ESP_ERR_TIMEOUT;
    }

    esp_err_t result = request->result;
    wasm_control_request_release(request);
    return result;
}

static esp_err_t start_wasm_control_thread(void)
{
    s_wasm_control_queue = xQueueCreate(WENDY_WASM_CONTROL_QUEUE_LEN,
                                       sizeof(wasm_control_request_t *));
    if (!s_wasm_control_queue) return ESP_ERR_NO_MEM;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, WENDY_WASM_THREAD_STACK_SIZE);
    int ret = pthread_create(&s_wasm_control_thread, &attr,
                             wasm_control_thread_entry, NULL);
    pthread_attr_destroy(&attr);
    if (ret != 0) {
        vQueueDelete(s_wasm_control_queue);
        s_wasm_control_queue = NULL;
        ESP_LOGE(TAG, "failed to create WAMR lifecycle control thread");
        return ESP_FAIL;
    }
    /* This thread intentionally lives until the firmware is reset. */
    pthread_detach(s_wasm_control_thread);
    return ESP_OK;
}

#endif /* CONFIG_WENDY_WASM */

static void apply_app_auto_start(struct wcom_operation *op)
{
    if (s_app_auto_start_enabled) {
        s_app_auto_start_enabled = false;
#if CONFIG_WENDY_WASM
        esp_err_t err = wasm_control_call(WASM_CONTROL_START, 0);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "auto-start WASM app failed: %s", esp_err_to_name(err));
        }
#endif
    }
}

static void cancel_app_auto_start(void)
{
    s_app_auto_start_enabled = false;
    xEventGroupSetBits(s_events, EVT_APP_START_REQUEST);
}

/* ── Native app push (firmware OTA) ────────────────────────────────────
 *
 * A native push writes the incoming image to the next OTA app partition
 * and switches the boot partition on completion; the new firmware runs
 * after the next reboot.
 */

static bool s_native_push = false;
static const esp_partition_t *s_ota_partition = NULL;
static esp_ota_handle_t s_ota_handle = 0;

static WendyComResult native_push_begin(size_t size)
{
    s_ota_partition = esp_ota_get_next_update_partition(NULL);
    if (s_ota_partition == NULL) {
        ESP_LOGW(TAG, "no OTA update partition available");
        return WendyComResult_WENDY_COM_RESULT_BAD_APP_TYPE;
    }
    if (size > s_ota_partition->size) {
        ESP_LOGW(TAG, "app size %zu exceeds OTA partition size %" PRIu32, size, s_ota_partition->size);
        s_ota_partition = NULL;
        return WendyComResult_WENDY_COM_RESULT_BAD_APP_SIZE;
    }
    esp_err_t err = esp_ota_begin(s_ota_partition, size, &s_ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
        s_ota_partition = NULL;
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }
    s_native_push = true;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

static WendyComResult native_push_data(const uint8_t *data, size_t size)
{
    esp_err_t err = esp_ota_write(s_ota_handle, data, size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(err));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }
    return WendyComResult_WENDY_COM_RESULT_OK;
}

static WendyComResult native_push_end(void)
{
    s_native_push = false;
    esp_err_t err = esp_ota_end(s_ota_handle);
    s_ota_handle = 0;
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(err));
        s_ota_partition = NULL;
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }
    err = esp_ota_set_boot_partition(s_ota_partition);
    s_ota_partition = NULL;
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s", esp_err_to_name(err));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }
    return WendyComResult_WENDY_COM_RESULT_OK;
}

static void native_push_abort(void)
{
    s_native_push = false;
    esp_ota_abort(s_ota_handle);
    s_ota_handle = 0;
    s_ota_partition = NULL;
}

/* ── App delegate (wendy_com protocol callbacks) ───────────────────── */

static WendyComResult com_push_begin(size_t size, WendyComAppType app_type)
{
    if (app_type == WendyComAppType_WENDY_COM_APP_TYPE_NATIVE)
        return native_push_begin(size);
    cancel_app_auto_start();
    esp_err_t e = wasm_persist_begin(0, (uint32_t)size);
    if (e == ESP_ERR_NOT_SUPPORTED)
        return WendyComResult_WENDY_COM_RESULT_BAD_APP_TYPE;
    if (e == ESP_ERR_NOT_FOUND)
        return WendyComResult_WENDY_COM_RESULT_BAD_APP_TYPE;
    if (e == ESP_ERR_INVALID_SIZE)
        return WendyComResult_WENDY_COM_RESULT_BAD_APP_SIZE;
    return e == ESP_OK ? WendyComResult_WENDY_COM_RESULT_OK
                       : WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
}

static WendyComResult com_push_data(size_t offset, const uint8_t *data, size_t size)
{
    if (s_native_push)
        return native_push_data(data, size);
    cancel_app_auto_start();
    esp_err_t e = wasm_persist_chunk((uint32_t)offset, data, (uint32_t)size);
    return e == ESP_OK ? WendyComResult_WENDY_COM_RESULT_OK
                       : WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
}

static WendyComResult com_push_end(void)
{
    if (s_native_push)
        return native_push_end();
    cancel_app_auto_start();
    esp_err_t e = wasm_persist_end(0);
    return e == ESP_OK ? WendyComResult_WENDY_COM_RESULT_OK
                       : WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
}

static void com_push_abort(void)
{
    if (s_native_push) {
        native_push_abort();
        return;
    }
    wasm_persist_abort(0);
}

/* ── Conf push (wendy_conf partition) ──────────────────────────────────
 *
 * The conf is small, so the incoming blob is buffered in RAM and written
 * to the wendy_conf partition in one go on completion.  The new
 * configuration takes effect after reboot.
 */

static uint8_t *s_conf_push_buf = NULL;
static size_t s_conf_push_size = 0;
static enum wendy_conf_write_mode s_conf_push_mode;

static WendyComResult com_conf_push_begin(size_t size, WendyComConfPushMode mode)
{
    if (size == 0 || size > wendy_conf_get_max_size()) {
        ESP_LOGW(TAG, "conf size %zu exceeds max %zu", size, wendy_conf_get_max_size());
        return WendyComResult_WENDY_COM_RESULT_BAD_CONF_SIZE;
    }
    free(s_conf_push_buf);
    s_conf_push_buf = malloc(size);
    if (!s_conf_push_buf) {
        ESP_LOGE(TAG, "no memory for %zu bytes conf", size);
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }
    s_conf_push_size = size;
    s_conf_push_mode = mode == WendyComConfPushMode_WENDY_COM_CONF_PUSH_MODE_UPDATE
                     ? WENDY_CONF_WRITE_MODE_UPDATE : WENDY_CONF_WRITE_MODE_REPLACE;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

static WendyComResult com_conf_push_data(size_t offset, const uint8_t *data, size_t size)
{
    if (!s_conf_push_buf)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    if (offset > s_conf_push_size || size > s_conf_push_size - offset) {
        ESP_LOGW(TAG, "conf chunk offset=%zu size=%zu beyond announced size %zu",
                 offset, size, s_conf_push_size);
        return WendyComResult_WENDY_COM_RESULT_BAD_CONF_SIZE;
    }
    memcpy(s_conf_push_buf + offset, data, size);
    return WendyComResult_WENDY_COM_RESULT_OK;
}

static void com_conf_push_abort(void)
{
    free(s_conf_push_buf);
    s_conf_push_buf = NULL;
    s_conf_push_size = 0;
}

static WendyComResult com_conf_push_end(void)
{
    if (!s_conf_push_buf)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    esp_err_t e = wendy_conf_write(s_conf_push_buf, s_conf_push_size, s_conf_push_mode);
    com_conf_push_abort();
    if (e == ESP_ERR_INVALID_SIZE)
        return WendyComResult_WENDY_COM_RESULT_BAD_CONF_SIZE;
    return e == ESP_OK ? WendyComResult_WENDY_COM_RESULT_OK
                       : WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
}

static WendyComResult com_app_start(void)
{
    cancel_app_auto_start();
#if defined CONFIG_WENDY_WASM
    uint8_t slot = 0;
    if (s_persist_load_pending) {
        slot = s_persist_load_slot;
        s_persist_load_pending = false;
    }
    esp_err_t e = wasm_control_call(WASM_CONTROL_START, slot);
    return e == ESP_OK ? WendyComResult_WENDY_COM_RESULT_OK
                       : WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
#else
    return WendyComResult_WENDY_COM_RESULT_OK;
#endif
}

static WendyComResult com_app_stop(void)
{
    cancel_app_auto_start();
    #if defined CONFIG_WENDY_WASM
    esp_err_t e = wasm_control_call(WASM_CONTROL_STOP, 0);
    return e == ESP_OK ? WendyComResult_WENDY_COM_RESULT_OK
                       : WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    #else
    return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    #endif
}

static WendyComResult com_reboot(bool app_auto_start, uint32_t app_auto_start_delay_ms)
{
    cancel_app_auto_start();
    #if defined CONFIG_WENDY_WASM
    esp_err_t stop_err = wasm_control_call(WASM_CONTROL_STOP, 0);
    if (stop_err != ESP_OK) {
        ESP_LOGW(TAG, "failed to stop WASM before reboot: %s",
                 esp_err_to_name(stop_err));
    }
    #endif
    uint32_t delay = app_auto_start_delay_ms;
    if (delay > 120000)
        delay = 120000;
    s_reboot_params.app_auto_start          = app_auto_start;
    s_reboot_params.app_auto_start_delay_ms = delay;
    s_reboot_params.magic                   = REBOOT_PARAMS_MAGIC;
    esp_restart();
    return WendyComResult_WENDY_COM_RESULT_OK;
}

static void com_get_device_identity(const char **id, const char **name, const char **display_name)
{
    *id = s_device_name;
    *name = s_device_name;
    *display_name = s_device_name;
}

#define _STRINGIFY(x) #x
#define _TOSTRING(x) _STRINGIFY(x)

// WENDY_CORE_COMPONENT_VERSION is defined by CMakeLists.txt from the COMPONENT_VERSION property.
#ifndef WENDY_CORE_COMPONENT_VERSION
#define WENDY_CORE_COMPONENT_VERSION ""
#endif

static const char *get_version(void)
{
#if CONFIG_WENDY_FIRMWARE_VERSION_MAJOR == 0 && CONFIG_WENDY_FIRMWARE_VERSION_MINOR == 0 && CONFIG_WENDY_FIRMWARE_VERSION_PATCH == 0
    if (WENDY_CORE_COMPONENT_VERSION[0] == 0) {
        return "dev";
    } else {
        // CONFIG_WENDY_FIRMWARE_VERSION_* only carries a real version on a
        // release build of this repo (injected from the git tag by
        // .github/workflows/build.yml), so it stays at 0.0.0 when the
        // component is embedded in someone else's IDF project. There, report
        // the version the IDF Component Manager resolved for wendy_core
        // instead: the released version, or the commit for a git dependency.
        return WENDY_CORE_COMPONENT_VERSION;
    }
#else
    return _TOSTRING(CONFIG_WENDY_FIRMWARE_VERSION_MAJOR) "."
            _TOSTRING(CONFIG_WENDY_FIRMWARE_VERSION_MINOR) "."
            _TOSTRING(CONFIG_WENDY_FIRMWARE_VERSION_PATCH);
#endif
}

static void com_get_device_info(const char **os, const char **os_version,
                                const char **cpu_architecture, const char **board,
                                bool *wasm_app_support, bool *native_app_support)
{
    *os = "wendy-lite";
    *os_version = get_version();
    *cpu_architecture = CONFIG_IDF_TARGET_ARCH;
    /* "esp32c6" means "generic esp32c6 board", not the SoC name */
    *board = CONFIG_IDF_TARGET;
#if CONFIG_WENDY_WASM
    /* WASM support also needs the slot-0 app partition in the partition table */
    *wasm_app_support = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x80,
                                                 partition_label_for(0)) != NULL;
#else
    *wasm_app_support = false;
#endif
    /* native push is compiled in unconditionally but only works if the
       partition table has an OTA update partition */
    *native_app_support = esp_ota_get_next_update_partition(NULL) != NULL;
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

esp_err_t wendy_core_init(void)
{
    capture_boot_params();

    esp_err_t stdio_err = wendy_stdio_init();
    if (stdio_err != ESP_OK)
        ESP_LOGW(TAG, "wendy_stdio_init: %s (continuing)", esp_err_to_name(stdio_err));

#if CONFIG_WENDY_USJ
    wendy_usj_init();
    vTaskDelay(pdMS_TO_TICKS(1000));
#endif

    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "  Wendy MCU Firmware v%d.%d.%d",
             CONFIG_WENDY_FIRMWARE_VERSION_MAJOR,
             CONFIG_WENDY_FIRMWARE_VERSION_MINOR,
             CONFIG_WENDY_FIRMWARE_VERSION_PATCH);
    ESP_LOGI(TAG, "  WASM Runtime: WAMR (C)");
    ESP_LOGI(TAG, "  Target: %s", CONFIG_IDF_TARGET);
    ESP_LOGI(TAG, "========================================");

    esp_vfs_eventfd_config_t cfg = ESP_VFS_EVENTD_CONFIG_DEFAULT();
    esp_err_t err = esp_vfs_eventfd_register(&cfg);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_vfs_eventfd_register: %s (continuing)",
                    esp_err_to_name(err));
    }

    /* NVS */
    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    s_events = xEventGroupCreate();

    /* Load configuration from the wendy-conf partition */
    wendy_conf_init();
    wendy_conf_copy_span(s_device_name, sizeof(s_device_name), wendy_conf_get_device_name());
    if (s_device_name[0]) {
        ESP_LOGI(TAG, "device name: %s", s_device_name);
    }

#if CONFIG_WENDY_WASM
    /* Pre-allocate the WAMR memory pool while RAM is still plentiful,
     * before WiFi and BLE claim large chunks. */
    err = wendy_wasm_prealloc_pool(CONFIG_WENDY_WASM_POOL_SIZE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WAMR pool pre-allocation failed");
    }

    err = start_wasm_control_thread();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WAMR lifecycle control thread init failed: %s",
                 esp_err_to_name(err));
        return err;
    }
#endif

    /* Initialize hardware */
    init_hal();

    if (!s_device_name[0]) {
        uint8_t mac[6];
        esp_efuse_mac_get_default(mac);
        snprintf(s_device_name, sizeof(s_device_name), "wendy-%02x%02x", mac[4], mac[5]);
        ESP_LOGI(TAG, "device name (fallback): %s", s_device_name);
    }

    /* Initialize main com infrastructure */
    static const struct wcom_app_delegate app_delegate = {
        .on_app_push_begin      = com_push_begin,
        .on_app_push_data       = com_push_data,
        .on_app_push_end        = com_push_end,
        .on_app_push_abort      = com_push_abort,
        .on_conf_push_begin     = com_conf_push_begin,
        .on_conf_push_data      = com_conf_push_data,
        .on_conf_push_end       = com_conf_push_end,
        .on_conf_push_abort     = com_conf_push_abort,
        .on_app_start           = com_app_start,
        .on_app_stop            = com_app_stop,
        .on_reboot              = com_reboot,
        .on_get_device_identity = com_get_device_identity,
        .on_get_device_info     = com_get_device_info,
    };
    wcom_set_app_delegate(&app_delegate);
    wcom_start();

    /* Initialize WiFi transport (if enabled) */
#if CONFIG_WENDY_WIFI_ENABLED
    err = wendy_wifi_init(s_device_name);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "WiFi connected");
    } else if (err == WENDY_WIFI_ERR_NO_CREDS) {
        ESP_LOGW(TAG, "no WiFi credentials configured, continuing without WiFi");
    } else {
        ESP_LOGW(TAG, "WiFi init failed (running without WiFi)");
    }
#endif /* CONFIG_WENDY_WIFI_ENABLED */

    /* ── App start gate: honor the reboot params ─────────────────────── */

    if (s_boot_app_auto_start && s_boot_app_auto_start_delay_ms > 0) {
        /* /portTICK_PERIOD_MS instead of pdMS_TO_TICKS: the latter overflows
         * 32 bits for large ms values at a 1000 Hz tick. */
        TickType_t ticks = s_boot_app_auto_start_delay_ms / portTICK_PERIOD_MS;
        if (ticks >= portMAX_DELAY)
            ticks = portMAX_DELAY - 1;
        ESP_LOGI(TAG, "delaying app auto start by %" PRIu32 "ms",
                 s_boot_app_auto_start_delay_ms);
        xEventGroupWaitBits(s_events, EVT_APP_START_REQUEST, pdTRUE, pdFALSE, ticks);
    }

    if (s_boot_app_auto_start) {
        // Queue auto-start through wcom so it remains ordered with commands.
        // The operation then synchronously delegates all WAMR lifecycle work
        // to its dedicated pthread-owned control path.
        static struct wcom_operation op = {
            .func = apply_app_auto_start,
        };
        wcom_exec(&op);
    }

    return ESP_OK;
}
