#include "wendy_sys.h"

#include <stdio.h>
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

/* sys_device_id(buf_ptr, buf_len) -> i32 (bytes written) */
static int sys_device_id_wrapper(wasm_exec_env_t exec_env,
                                  char *buf, int len)
{
    if (!buf || len < 12) {
        return -1;
    }
    int written = snprintf(buf, len, "%s", wendy_conf_get_device_id());
    return (written < len) ? written : len - 1;
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
