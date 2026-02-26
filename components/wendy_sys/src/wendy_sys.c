#include "wendy_sys.h"

#include <stdio.h>
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wasm_export.h"

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#include "wendy_wasm.h"
#endif

static const char *TAG = "wendy_sys";

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
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    int written = snprintf(buf, len, "%02x%02x%02x%02x%02x%02x",
                           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (written < len) ? written : len - 1;
}

/* sys_sleep_ms(ms) */
static void sys_sleep_ms_wrapper(wasm_exec_env_t exec_env, int ms)
{
    if (ms > 0) {
        vTaskDelay(pdMS_TO_TICKS(ms));
    }
}

/* sys_yield() — drain callback queue */
static void sys_yield_wrapper(wasm_exec_env_t exec_env)
{
#if CONFIG_WENDY_CALLBACK
    void *ee = wendy_wasm_get_current_exec_env();
    void *mi = wendy_wasm_get_current_module_inst();
    if (ee && mi) {
        wendy_callback_dispatch(ee, mi);
    }
#endif
    taskYIELD();
}

static NativeSymbol s_sys_symbols[] = {
    { "sys_uptime_ms",        (void *)sys_uptime_ms_wrapper,        "()I",    NULL },
    { "sys_reboot",           (void *)sys_reboot_wrapper,           "()",     NULL },
    { "sys_firmware_version", (void *)sys_firmware_version_wrapper, "(*~)i",  NULL },
    { "sys_device_id",        (void *)sys_device_id_wrapper,        "(*~)i",  NULL },
    { "sys_sleep_ms",         (void *)sys_sleep_ms_wrapper,         "(i)",    NULL },
    { "sys_yield",            (void *)sys_yield_wrapper,            "()",     NULL },
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
