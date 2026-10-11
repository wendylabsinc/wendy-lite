#include "wendy_cloud.h"

#if CONFIG_WENDY_CLOUD

#include "wendy_pki.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "wendy_conf.h"
#include "wendy_server.h"
#include "esp_timer.h"
#include <unistd.h>

#include <stdatomic.h>

static const char *TAG = "wendy_cloud";

static _Atomic wendy_cloud_state_t s_state = WENDY_CLOUD_STATE_IDLE;
// Touched only by the start/stop callers (which must not run concurrently)
// and cleared by the cloud task on exit, ordered via s_stopped.
static TaskHandle_t                s_task  = NULL;
static SemaphoreHandle_t           s_stopped;
// Wakes the cloud task from its reconnect delay when stop is requested.
static SemaphoreHandle_t           s_wake;
static atomic_bool                 s_stop;

// Owned exclusively by the cloud task until the authenticated socket handoff.
static wendy_pki_connection *s_tls;

static esp_err_t cloud_connect(void)
{
    return wendy_pki_connect(&s_tls);
}

// The broker control protocol is separate from WendyCom. It exists only inside
// the initial device-to-broker mTLS session: WR, version 1, opcode.
static esp_err_t wait_for_upgrade(void)
{
    unsigned char record[4];
    size_t received = 0;
    int64_t deadline = esp_timer_get_time() + 30000000;
    int64_t refresh = esp_timer_get_time() + 240000000;
    while (!s_stop) {
        if (esp_timer_get_time() >= deadline || esp_timer_get_time() >= refresh)
            return ESP_ERR_TIMEOUT;
        int ret = wendy_pki_read(s_tls, record + received, sizeof(record) - received);
        if (ret == -2 || ret == -3) {
            if (esp_timer_get_time() >= deadline) return ESP_ERR_TIMEOUT;
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        if (ret <= 0) return ESP_FAIL;
        received += ret;
        if (received != sizeof(record)) continue;
        if (record[0] != 'W' || record[1] != 'R' || record[2] != 1) return ESP_FAIL;
        if (record[3] == 3) return ESP_OK;
        if (record[3] != 1) return ESP_FAIL;
        record[3] = 2;
        size_t sent = 0;
        while (sent < sizeof(record) && !s_stop) {
            if (esp_timer_get_time() >= deadline) return ESP_ERR_TIMEOUT;
            ret = wendy_pki_write(s_tls, record + sent, sizeof(record) - sent);
            if (ret == -2 || ret == -3) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            if (ret <= 0) return ESP_FAIL;
            sent += ret;
        }
        received = 0;
        deadline = esp_timer_get_time() + 30000000;
    }
    return ESP_FAIL;
}

static int detach_socket(void)
{
    int fd = wendy_pki_detach(s_tls);
    if (fd >= 0)
        s_tls = NULL;
    return fd;
}

static void cloud_task(void *arg)
{
    ESP_LOGI(TAG, "task started");

    for (;;) {
        if (s_stop)
            break;
        s_state = WENDY_CLOUD_STATE_CONNECTING;

        if (cloud_connect() != ESP_OK) {
            s_state = WENDY_CLOUD_STATE_ERROR;
            if (s_stop)
                break;
            ESP_LOGI(TAG, "retrying in %d ms", CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS);
            xSemaphoreTake(s_wake, pdMS_TO_TICKS(CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS));
            continue;
        }

        if (s_stop) {
            // stopped during connect: not yet handed off, safe to destroy here
            wendy_pki_close(s_tls);
            s_tls = NULL;
            break;
        }

        s_state = WENDY_CLOUD_STATE_CONNECTED;
        ESP_LOGI(TAG, "mTLS connected");

        if (wait_for_upgrade() == ESP_OK && !s_stop) {
            int fd = detach_socket();
            if (fd >= 0) {
                if (s_stop) {
                    close(fd);
                    break;
                }
                // Starts a fresh TLS server session and requires a same-tenant operator.
                // The server owns the descriptor on both success and failure.
                wendy_server_accept_operator(fd);
                // Keep a control connection available while accepted CLI sessions run.
                continue;
            }
        }
        if (s_tls) {
            wendy_pki_close(s_tls);
            s_tls = NULL;
        }
        s_state = WENDY_CLOUD_STATE_DISCONNECTED;
        if (s_stop) break;

        ESP_LOGI(TAG, "reconnecting in %d ms", CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS);
        xSemaphoreTake(s_wake, pdMS_TO_TICKS(CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS));
    }

    s_state = WENDY_CLOUD_STATE_IDLE;
    s_task = NULL;
    xSemaphoreGive(s_stopped);
    vTaskDelete(NULL);
}

esp_err_t wendy_cloud_start(void)
{
    if (s_task != NULL) {
        ESP_LOGW(TAG, "already running");
        return ESP_OK;
    }

    if (!wendy_conf_has_enrollment()) {
        ESP_LOGE(TAG, "pki-core enrollment configuration is missing");
        return ESP_ERR_INVALID_STATE;
    }

    if (!s_stopped)
        s_stopped = xSemaphoreCreateBinary();
    if (!s_wake)
        s_wake = xSemaphoreCreateBinary();
    if (!s_stopped || !s_wake)
        return ESP_ERR_NO_MEM;
    xSemaphoreTake(s_stopped, 0);
    xSemaphoreTake(s_wake, 0); // drain a stale wake left over from a previous run
    s_stop = false;

    BaseType_t ret = xTaskCreatePinnedToCore(
        cloud_task,
        "wendy_cloud",
        CONFIG_WENDY_CLOUD_TASK_STACK_SIZE,
        NULL,
        CONFIG_WENDY_CLOUD_TASK_PRIORITY,
        &s_task,
        CONFIG_WENDY_CLOUD_TASK_CORE_AFFINITY);

    if (ret != pdPASS) {
        ESP_LOGE(TAG, "task create failed");
        s_task = NULL;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "started (stack=%d, pri=%d)",
             CONFIG_WENDY_CLOUD_TASK_STACK_SIZE, CONFIG_WENDY_CLOUD_TASK_PRIORITY);
    return ESP_OK;
}

void wendy_cloud_stop(void)
{
    if (!s_task)
        return;

    s_stop = true;
    xSemaphoreGive(s_wake); // wake the task from any wait

    if (xSemaphoreTake(s_stopped, pdMS_TO_TICKS(15000)) != pdTRUE)
        ESP_LOGE(TAG, "stop timed out");
}

wendy_cloud_state_t wendy_cloud_get_state(void)
{
    return s_state;
}

bool wendy_cloud_is_connected(void)
{
    return (s_state == WENDY_CLOUD_STATE_CONNECTED);
}

#endif // CONFIG_WENDY_CLOUD
