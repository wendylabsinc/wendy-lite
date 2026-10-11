#include "wendy_cloud.h"
#if CONFIG_WENDY_CLOUD
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "wendy_conf.h"
#include "wendy_pki.h"
#include "wendy_server.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

static const char *TAG = "wendy_cloud";
static _Atomic wendy_cloud_state_t s_state = WENDY_CLOUD_STATE_IDLE;
static atomic_bool s_stop;
static TaskHandle_t s_task;
static SemaphoreHandle_t s_stopped, s_wake;

static void cloud_task(void *unused)
{
    (void)unused;
    while (!s_stop) {
        s_state = WENDY_CLOUD_STATE_CONNECTING;
        wendy_pki_connection *outer = NULL;
        struct wendy_lite_trust *trust = calloc(1, sizeof *trust);
        int fd = -1;
        if (trust && wendy_pki_connect(&outer) == ESP_OK) {
            s_state = WENDY_CLOUD_STATE_CONNECTED;
            fd = wendy_pki_relay_upgrade(outer, trust);
        }
        wendy_pki_close(outer);
        if (fd >= 0) {
            if (s_stop) close(fd);
            else wendy_server_accept_operator(fd, trust);
        }
        free(trust);
        s_state = WENDY_CLOUD_STATE_DISCONNECTED;
        // The handed-off stream belongs to the server. Open its replacement
        // immediately; shared broker caps prevent claiming it a second time.
        if (fd < 0 && !s_stop) xSemaphoreTake(s_wake, pdMS_TO_TICKS(CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS));
    }
    s_state = WENDY_CLOUD_STATE_IDLE;
    s_task = NULL;
    xSemaphoreGive(s_stopped);
    vTaskDelete(NULL);
}

esp_err_t wendy_cloud_start(void)
{
    if (s_task) return ESP_OK;
    if (!wendy_conf_has_enrollment()) return ESP_ERR_INVALID_STATE;
    if (!s_stopped) s_stopped = xSemaphoreCreateBinary();
    if (!s_wake) s_wake = xSemaphoreCreateBinary();
    if (!s_stopped || !s_wake) return ESP_ERR_NO_MEM;
    xSemaphoreTake(s_stopped, 0);
    xSemaphoreTake(s_wake, 0);
    s_stop = false;
    if (xTaskCreatePinnedToCore(cloud_task, "wendy_cloud", CONFIG_WENDY_CLOUD_TASK_STACK_SIZE,
        NULL, CONFIG_WENDY_CLOUD_TASK_PRIORITY, &s_task, CONFIG_WENDY_CLOUD_TASK_CORE_AFFINITY) != pdPASS) {
        s_task = NULL;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
void wendy_cloud_stop(void)
{
    if (!s_task) return;
    s_stop = true;
    xSemaphoreGive(s_wake);
    if (xSemaphoreTake(s_stopped, pdMS_TO_TICKS(35000)) != pdTRUE)
        ESP_LOGE(TAG, "cloud stop timed out");
}
wendy_cloud_state_t wendy_cloud_get_state(void) { return s_state; }
bool wendy_cloud_is_connected(void) { return s_state == WENDY_CLOUD_STATE_CONNECTED; }
#endif
