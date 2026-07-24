#include "wendy_cloud.h"

#if CONFIG_WENDY_CLOUD

#include "esp_tls.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "wendy_conf.h"
#include "wendy_com_link.h"

#include <stdatomic.h>
#include <string.h>

#define _CONNECT_TIMEOUT_MS 10000
#define _DEFAULT_PORT 5055

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
static esp_tls_t     *s_tls = NULL;
static atomic_int     s_link_id;

struct _add_link_op {
    struct wcom_operation base;
    esp_tls_t *tls;
};

// One connection at a time: the cloud task blocks until the previous link is
// fully torn down, so a single static op instance is enough.
static struct _add_link_op s_add_op;


static esp_err_t cloud_connect(void)
{
    s_tls = esp_tls_init();
    if (!s_tls) {
        ESP_LOGE(TAG, "esp_tls_init failed");
        return ESP_ERR_NO_MEM;
    }

    struct wendy_conf_span host = wendy_conf_get_cloud_host();

    int port = _DEFAULT_PORT;
    if (host.size > 0) {
        const char *p = host.data + host.size - 1;
        while (p > (const char *)host.data && *p >= '0' && *p <= '9')
            p--;
        if (*p == ':') {
            host.size = p - (const char *)host.data;
            port = (int)strtol(p + 1, NULL, 10);
        }
    }

    ESP_LOGI(TAG, "Connecting to %.*s:%d with mTLS", (int)host.size, host.data, port);

    struct wendy_conf_span key = wendy_conf_get_private_key();
    struct wendy_conf_span cert = wendy_conf_get_certificate();

    esp_tls_cfg_t cfg = {
        .clientcert_buf   = cert.data,
        .clientcert_bytes = cert.size,
        .clientkey_buf    = key.data,
        .clientkey_bytes  = key.size,
        .timeout_ms       = _CONNECT_TIMEOUT_MS,
    };

#if !CONFIG_WENDY_CLOUD_SKIP_SERVER_VERIFICATION
    struct wendy_conf_span chain = wendy_conf_get_chain_of_trust();
    cfg.cacert_buf   = chain.data;
    cfg.cacert_bytes = chain.size;
#endif
    // With WENDY_CLOUD_SKIP_SERVER_VERIFICATION no CA source is configured at all,
    // which makes esp-tls fall back to MBEDTLS_SSL_VERIFY_NONE — this needs
    // ESP_TLS_INSECURE + ESP_TLS_SKIP_SERVER_CERT_VERIFY (selected by the
    // Kconfig option). The client cert/key above are independent of server
    // verification and are still presented.

    int ret = esp_tls_conn_new_sync(
        host.data,
        host.size,
        port,
        &cfg,
        s_tls);

    if (ret != 1) {
        int mbedtls_err = 0, flags = 0;
        esp_tls_error_handle_t eh;
        if (esp_tls_get_error_handle(s_tls, &eh) == ESP_OK) {
            esp_tls_get_and_clear_last_error(eh, &mbedtls_err, &flags);
        }
        ESP_LOGE(TAG, "TLS connect failed ret=%d mbedtls=0x%x flags=0x%x",
                 ret, mbedtls_err, flags);
        esp_tls_conn_destroy(s_tls);
        s_tls = NULL;
        return ESP_FAIL;
    }

    return ESP_OK;
}

// Com task. Tears down the cloud link. Bookkeeping is cleared before
// wcom_remove_link because removal re-fires this handler (UNDEFINED).
static void _on_link_state_changed(
    struct wcom_state_change_handler *handler,
    int link_id,
    enum wcom_link_state state)
{
    if (state == WCOM_LINK_STATE_CONNECTED)
        return;
    int cur_link_id = s_link_id;
    if (cur_link_id == 0 || link_id != cur_link_id)
        return;

    ESP_LOGI(TAG, "link %d down (state %d)", link_id, (int)state);
    esp_tls_t *tls = s_tls;
    s_tls = NULL;
    // State before s_link_id: once s_link_id is 0 a stopping cloud task may
    // exit and set IDLE, which DISCONNECTED must not overwrite.
    s_state = WENDY_CLOUD_STATE_DISCONNECTED;
    s_link_id = 0;
    wcom_remove_link(link_id);
    esp_tls_conn_destroy(tls); // client-mode destroy also closes the fd
    xSemaphoreGive(s_wake);
}

static struct wcom_state_change_handler s_state_handler = {
    .func = _on_link_state_changed,
};

// Com task. Hands the established TLS connection to the com core; from here
// on all socket I/O happens on the com task and the device behaves exactly
// as if a local client had connected.
static void _add_link_exec(struct wcom_operation *op)
{
    static bool subscribed = false;
    if (!subscribed) {
        wcom_add_state_change_handler(&s_state_handler);
        subscribed = true;
    }

    struct _add_link_op *aop = (struct _add_link_op *)op;
    int link_id = wcom_add_tls_link(aop->tls);
    if (link_id < 0) {
        ESP_LOGE(TAG, "no free com link, dropping cloud connection");
        esp_tls_conn_destroy(aop->tls);
        s_tls = NULL;
        s_state = WENDY_CLOUD_STATE_ERROR;
        xSemaphoreGive(s_wake);
        return;
    }
    s_link_id = link_id;
    ESP_LOGI(TAG, "link %d added", link_id);
}

// Com task. Queued by wendy_cloud_stop after s_add_op, so it always runs
// after a pending handoff and funnels teardown through the state handler.
static void _close_link_exec(struct wcom_operation *op)
{
    int link_id = s_link_id;
    if (link_id != 0)
        wcom_close(link_id);
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
            esp_tls_conn_destroy(s_tls);
            s_tls = NULL;
            break;
        }

        s_state = WENDY_CLOUD_STATE_CONNECTED;
        ESP_LOGI(TAG, "mTLS connected");

        s_add_op.base.func = _add_link_exec;
        s_add_op.tls = s_tls;
        wcom_core_exec(&s_add_op.base);

        // sleep until the link dies (state handler) or stop is requested
        xSemaphoreTake(s_wake, portMAX_DELAY);
        if (s_stop)
            break;

        ESP_LOGI(TAG, "reconnecting in %d ms", CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS);
        xSemaphoreTake(s_wake, pdMS_TO_TICKS(CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS));
    }

    // wait for the com task to finish tearing down any live link
    while (s_link_id != 0)
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

    struct wendy_conf_span host = wendy_conf_get_cloud_host();
    struct wendy_conf_span key = wendy_conf_get_private_key();
    struct wendy_conf_span cert = wendy_conf_get_certificate();
    if (host.size == 0 || key.size == 0 || cert.size == 0) {
        ESP_LOGE(TAG, "cloud provisioning not found in wendy_conf");
        return ESP_FAIL;
    }
#if !CONFIG_WENDY_CLOUD_SKIP_SERVER_VERIFICATION
    struct wendy_conf_span chain = wendy_conf_get_chain_of_trust();
    if (chain.size == 0) {
        ESP_LOGE(TAG, "cloud chain of trust not found in wendy_conf");
        return ESP_FAIL;
    }
#endif

    if (!s_stopped)
        s_stopped = xSemaphoreCreateBinary();
    if (!s_wake)
        s_wake = xSemaphoreCreateBinary();
    xSemaphoreTake(s_wake, 0); // drain a stale wake left over from a previous run
    s_stop = false;

    BaseType_t ret = xTaskCreatePinnedToCore(
        cloud_task,
        "wendy_cloud",
        CONFIG_WENDY_CLOUD_TASK_STACK_SIZE,
        NULL,
        CONFIG_WENDY_CLOUD_TASK_PRIORITY,
        &s_task,
        tskNO_AFFINITY);

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
    // close a live link on the com task; teardown funnels through the state
    // handler (this op is queued after any pending handoff)
    static struct wcom_operation close_op = {
        .func = _close_link_exec,
    };
    wcom_core_exec(&close_op);
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
