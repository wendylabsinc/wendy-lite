#include "wendy_cloud.h"

#if CONFIG_WENDY_CLOUD

#include "wendy_pki.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "wendy_conf.h"
#include "wendy_com_link.h"

#include <stdatomic.h>
#include <string.h>


static const char *TAG = "wendy_cloud";

static _Atomic wendy_cloud_state_t s_state = WENDY_CLOUD_STATE_IDLE;
// Touched only by the start/stop callers (which must not run concurrently)
// and cleared by the cloud task on exit, ordered via s_stopped.
static TaskHandle_t                s_task  = NULL;
static SemaphoreHandle_t           s_stopped;
// Wakes the cloud task on link death or stop. Module-owned so the com task
// never has to touch a task handle that may already be dead.
static SemaphoreHandle_t           s_wake;
static atomic_bool                 s_stop;

// The TLS handle is owned by this module, but once handed off to the com
// core it may only be touched (read/written/destroyed) on the com task,
// after wcom_remove_link. Cross-task visibility comes from the wcom op
// queue (release/acquire) on handoff and from s_wake on hand-back.
// s_link_id is written on the com task only.
static wendy_pki_connection     *s_tls = NULL;
static atomic_int     s_link_id;
static atomic_bool    s_add_pending;

struct _add_link_op {
    struct wcom_operation base;
    wendy_pki_connection *tls;
};

// One connection at a time: the cloud task blocks until the previous link is
// fully torn down, so a single static op instance is enough.
static struct _add_link_op s_add_op;

struct _close_link_op {
    struct wcom_operation base;
    int link_id;
};


static const struct wcom_stream_ops cloud_ops = {
    .read = wendy_pki_read, .write = wendy_pki_write,
    .wakeup_fd = wendy_pki_fd,
};

static esp_err_t cloud_connect(void)
{
    return wendy_pki_connect(&s_tls);
}

// Com task. Tears down the cloud link.
static void _on_link_interruption(int link_id, enum wcom_interruption_reason reason)
{
    ESP_LOGI(TAG, "link %d down (reason %d)", link_id, (int)reason);
    wendy_pki_connection *tls = s_tls;
    s_tls = NULL;
    // State before s_link_id: once s_link_id is 0 a stopping cloud task may
    // exit and set IDLE, which DISCONNECTED must not overwrite.
    s_state = WENDY_CLOUD_STATE_DISCONNECTED;
    s_link_id = 0;
    wcom_remove_link(link_id);
    wendy_pki_close(tls); // client-mode destroy also closes the fd
    xSemaphoreGive(s_wake);
}

// Com task. Hands the established TLS connection to the com core; from here
// on all socket I/O happens on the com task and the device behaves exactly
// as if a local client had connected.
static void _add_link_exec(struct wcom_operation *op)
{
    struct _add_link_op *aop = (struct _add_link_op *)op;
    if (s_stop) {
        wendy_pki_close(aop->tls);
        s_tls = NULL;
        s_add_pending = false;
        xSemaphoreGive(s_wake);
        return;
    }
    int link_id = wcom_add_socket_link(&cloud_ops, aop->tls, _on_link_interruption);
    if (link_id < 0) {
        ESP_LOGE(TAG, "no free com link, dropping cloud connection");
        wendy_pki_close(aop->tls);
        s_tls = NULL;
        s_state = WENDY_CLOUD_STATE_ERROR;
        s_add_pending = false;
        xSemaphoreGive(s_wake);
        return;
    }
    s_link_id = link_id;
    ESP_LOGI(TAG, "link %d added", link_id);
    // Stop may have arrived while the link's state handlers ran.
    if (s_stop)
        wcom_close(link_id);
    s_add_pending = false;
}

// Com task. Queued by wendy_cloud_stop after s_add_op, so it always runs
// after a pending handoff and funnels teardown through the interruption handler.
static void _close_link_exec(struct wcom_operation *op)
{
    struct _close_link_op *close = (struct _close_link_op *)op;
    if (close->link_id != 0)
        wcom_close(close->link_id);
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

        s_add_op.base.func = _add_link_exec;
        s_add_op.tls = s_tls;
        s_add_pending = true;
        wcom_core_exec(&s_add_op.base);

        // sleep until the link dies (interruption handler) or stop is requested
        if (xSemaphoreTake(s_wake, pdMS_TO_TICKS(240000)) != pdTRUE) {
            // Refresh signed time and renew before the current identity expires.
            // Close through the com task so the next connection never shares TLS state.
            static struct _close_link_op refresh_op = { .base.func = _close_link_exec };
            refresh_op.link_id = s_link_id;
            wcom_core_exec(&refresh_op.base);
            xSemaphoreTake(s_wake, portMAX_DELAY);
        }
        if (s_stop)
            break;

        ESP_LOGI(TAG, "reconnecting in %d ms", CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS);
        xSemaphoreTake(s_wake, pdMS_TO_TICKS(CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS));
    }

    // wait for the com task to finish tearing down any live link
    while (s_add_pending || s_link_id != 0)
        vTaskDelay(pdMS_TO_TICKS(20));

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

    if (atomic_exchange(&s_stop, true))
        return;
    // close a live link on the com task; teardown funnels through the state
    // handler (this op is queued after any pending handoff)
    static struct _close_link_op close_op = {
        .base.func = _close_link_exec,
    };
    close_op.link_id = s_link_id;
    if (close_op.link_id)
        wcom_core_exec(&close_op.base);
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
