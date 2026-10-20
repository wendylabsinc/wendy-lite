#include "wendy_sys.h"

#include <stdio.h>
#include <string.h>
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_log.h"
#include "wendy_conf.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wasm_export.h"

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#endif

static const char *TAG = "wendy_sys";

/* yield, permitting lower-priority tasks to run unlike taskYIELD() */
static void wendy_sys_yield_to_freertos(void)
{
    vTaskDelay(1);
}

/* sys_uptime_ms() -> i64 */
static int64_t sys_uptime_ms_wrapper(wasm_exec_env_t exec_env)
{
    return (int64_t)(esp_timer_get_time() / 1000);
}

/* sys_reboot() */
static void sys_reboot_wrapper(wasm_exec_env_t exec_env)
{
    ESP_LOGW(TAG, "WASM app requested reboot");
    esp_restart();
}

/* sys_firmware_version(buf_ptr, buf_len) -> i32 (bytes written) */
static int sys_firmware_version_wrapper(wasm_exec_env_t exec_env,
                                         char *buf, int len)
{
    if (!buf || len <= 0) {
        return -1;
    }
    int written = snprintf(buf, len, "%d.%d.%d",
                           CONFIG_WENDY_FIRMWARE_VERSION_MAJOR,
                           CONFIG_WENDY_FIRMWARE_VERSION_MINOR,
                           CONFIG_WENDY_FIRMWARE_VERSION_PATCH);
    return (written < len) ? written : len - 1;
}

/* Copy a NUL-terminated id whole or not at all: an id is never truncated. */
static int copy_id(char *buf, int len, int min_len, const char *id)
{
    int n = (int)strlen(id);
    if (!buf || len < min_len || len <= n) {
        return -1;
    }
    memcpy(buf, id, n + 1);
    return n;
}

/* sys_device_id(buf_ptr, buf_len) -> i32 (bytes written, -1 if buf_len < 37)
 * The device's one id: the canonical UUID it was enrolled with, also its cloud
 * asset id. Empty (0 bytes) while the board is unenrolled. */
static int sys_device_id_wrapper(wasm_exec_env_t exec_env,
                                  char *buf, int len)
{
    char tenant[37], device[65];
    wendy_conf_get_enrolled_ids(tenant, device);
    return copy_id(buf, len, 37, device);
}

/* sys_serial_number(buf_ptr, buf_len) -> i32 (bytes written, -1 if buf_len < 13)
 * The hardware id (factory MAC as 12 hex digits), stable across enrollments. */
static int sys_serial_number_wrapper(wasm_exec_env_t exec_env,
                                     char *buf, int len)
{
    return copy_id(buf, len, 13, wendy_conf_get_device_id());
}

/* sys_sleep_ms(ms) */
static void sys_sleep_ms_wrapper(wasm_exec_env_t exec_env, int ms)
{
    if (ms > 0) {
        TickType_t ticks = pdMS_TO_TICKS(ms);
        if (ticks == 0) {
            ticks = 1;
        }
        vTaskDelay(ticks);
    }
}

/* sys_yield() — drain callback queue */
static void sys_yield_wrapper(wasm_exec_env_t exec_env)
{
#if CONFIG_WENDY_CALLBACK
    wasm_module_inst_t module_inst = exec_env ? wasm_runtime_get_module_inst(exec_env) : NULL;
    if (exec_env && module_inst) {
        wendy_callback_dispatch(exec_env, module_inst);
    }
#endif
    wendy_sys_yield_to_freertos();
}

/* sys_wait_for_event(timeout_ms) -> dispatched callback count */
static int sys_wait_for_event_wrapper(wasm_exec_env_t exec_env, int timeout_ms)
{
#if CONFIG_WENDY_CALLBACK
    wasm_module_inst_t module_inst = exec_env ? wasm_runtime_get_module_inst(exec_env) : NULL;
    if (exec_env && module_inst) {
        uint32_t wait_ms = timeout_ms > 0 ? (uint32_t)timeout_ms : 0;
        int dispatched = wendy_callback_wait_and_dispatch(exec_env, module_inst,
                                                          wait_ms);
        wendy_sys_yield_to_freertos();
        return dispatched;
    }
#endif

    if (timeout_ms > 0) {
        TickType_t ticks = pdMS_TO_TICKS(timeout_ms);
        if (ticks == 0) {
            ticks = 1;
        }
        vTaskDelay(ticks);
    } else {
        wendy_sys_yield_to_freertos();
    }
    return 0;
}

static NativeSymbol s_sys_symbols[] = {
    { "sys_uptime_ms",        (void *)sys_uptime_ms_wrapper,        "()I",    NULL },
    { "sys_reboot",           (void *)sys_reboot_wrapper,           "()",     NULL },
    { "sys_firmware_version", (void *)sys_firmware_version_wrapper, "(*~)i",  NULL },
    { "sys_device_id",        (void *)sys_device_id_wrapper,        "(*~)i",  NULL },
    { "sys_serial_number",    (void *)sys_serial_number_wrapper,    "(*~)i",  NULL },
    { "sys_sleep_ms",         (void *)sys_sleep_ms_wrapper,         "(i)",    NULL },
    { "sys_yield",            (void *)sys_yield_wrapper,            "()",     NULL },
    { "sys_wait_for_event",   (void *)sys_wait_for_event_wrapper,   "(i)i",   NULL },
};

int wendy_sys_export_init(void)
{
    if (!wasm_runtime_register_natives("wendy",
                                       s_sys_symbols,
                                       sizeof(s_sys_symbols) / sizeof(s_sys_symbols[0]))) {
        ESP_LOGE(TAG, "failed to register sys natives");
        return -1;
    }
    ESP_LOGI(TAG, "sys exports registered");
    return 0;
}
