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
#include <pthread.h>
#include <sys/socket.h>

static const char *TAG = "wendy_cloud";
static _Atomic wendy_cloud_state_t s_state = WENDY_CLOUD_STATE_IDLE;
static atomic_bool s_stop;
static atomic_uint s_failures;
static pthread_mutex_t s_start_lock = PTHREAD_MUTEX_INITIALIZER;
unsigned wendy_cloud_connect_failures(void) { return atomic_load(&s_failures); }
void wendy_cloud_reset_failures(void) { atomic_store(&s_failures, 0); }
static TaskHandle_t s_task;
static SemaphoreHandle_t s_stopped, s_wake;
static pthread_mutex_t s_connection_lock = PTHREAD_MUTEX_INITIALIZER;
static int s_outer_fd = -1;
void wendy_cloud_network_changed(void)
{
    pthread_mutex_lock(&s_connection_lock);
    if (s_outer_fd >= 0) shutdown(s_outer_fd, SHUT_RDWR);
    pthread_mutex_unlock(&s_connection_lock);
    if (s_wake) xSemaphoreGive(s_wake);
}

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
            atomic_store(&s_failures, 0);
            pthread_mutex_lock(&s_connection_lock);
            s_outer_fd = wendy_pki_fd(outer);
            pthread_mutex_unlock(&s_connection_lock);
            fd = wendy_pki_relay_upgrade(outer, trust);
            pthread_mutex_lock(&s_connection_lock);
            s_outer_fd = -1;
            pthread_mutex_unlock(&s_connection_lock);
        }
        if (!outer && !s_stop && atomic_load(&s_failures) < 3)
            atomic_fetch_add(&s_failures, 1);
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

static esp_err_t cloud_start_locked(void)
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
esp_err_t wendy_cloud_start(void)
{
    pthread_mutex_lock(&s_start_lock);
    esp_err_t result = cloud_start_locked();
    pthread_mutex_unlock(&s_start_lock);
    return result;
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
