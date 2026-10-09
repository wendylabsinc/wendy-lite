#include "wendy_cloud.h"

#if CONFIG_WENDY_CLOUD

#include "esp_tls.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "wendy_conf.h"
#include "wendy_server.h"
#include "mbedtls/ssl.h"
#include "esp_timer.h"
#include <unistd.h>

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

// Owned exclusively by the cloud task until the authenticated socket handoff.
static esp_tls_t *s_tls;

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
    struct wendy_conf_span chain = wendy_conf_get_chain_of_trust();

    esp_tls_cfg_t cfg = {
        .clientcert_buf   = cert.data,
        .clientcert_bytes = cert.size,
        .clientkey_buf    = key.data,
        .clientkey_bytes  = key.size,
        .cacert_buf       = chain.data,
        .cacert_bytes     = chain.size,
        .timeout_ms       = _CONNECT_TIMEOUT_MS,
    };

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

// The broker control protocol is separate from WendyCom. It exists only inside
// the initial device-to-broker mTLS session: WR, version 1, opcode.
static esp_err_t wait_for_upgrade(void)
{
    unsigned char record[4];
    size_t received = 0;
    int64_t deadline = esp_timer_get_time() + 30000000;
    while (!s_stop) {
        int ret = esp_tls_conn_read(s_tls, record + received, sizeof(record) - received);
        if (ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_WANT_WRITE ||
            ret == MBEDTLS_ERR_SSL_TIMEOUT) {
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
            ret = esp_tls_conn_write(s_tls, record + sent, sizeof(record) - sent);
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
    mbedtls_ssl_context *ssl = esp_tls_get_ssl_context(s_tls);
    unsigned char byte;
    int ret;
    int64_t deadline = esp_timer_get_time() + 10000000;
    // The broker sends close_notify after its upgrade. No more control data is legal.
    do {
        ret = mbedtls_ssl_read(ssl, &byte, 1);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        break;
    } while (!s_stop && esp_timer_get_time() < deadline);
    if (ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return -1;
    do {
        ret = mbedtls_ssl_close_notify(ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            vTaskDelay(pdMS_TO_TICKS(10));
        else break;
    } while (!s_stop && esp_timer_get_time() < deadline);
    if (ret != 0 || s_stop) return -1;
    int fd = -1;
    if (esp_tls_get_conn_sockfd(s_tls, &fd) != ESP_OK) return -1;
    // ESP-IDF's session-delete frees the TLS context without closing the socket.
    // conn_destroy would close TCP and must not be used at this boundary.
    esp_tls_server_session_delete(s_tls);
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
            esp_tls_conn_destroy(s_tls);
            s_tls = NULL;
            break;
        }

        s_state = WENDY_CLOUD_STATE_CONNECTED;
        ESP_LOGI(TAG, "mTLS connected");

        if (wait_for_upgrade() == ESP_OK && !s_stop) {
            int fd = detach_socket();
            if (fd >= 0) {
                // Starts a fresh TLS server session and requires a same-tenant operator.
                // The server owns the descriptor on both success and failure.
                wendy_server_accept_operator(fd);
                // Keep a control connection available while accepted CLI sessions run.
                continue;
            }
        }
        if (s_tls) {
            esp_tls_conn_destroy(s_tls);
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

    struct wendy_conf_span host = wendy_conf_get_cloud_host();
    struct wendy_conf_span key = wendy_conf_get_private_key();
    struct wendy_conf_span cert = wendy_conf_get_certificate();
    struct wendy_conf_span chain = wendy_conf_get_chain_of_trust();
    if (host.size == 0 || key.size == 0 || cert.size == 0 || chain.size == 0) {
        ESP_LOGE(TAG, "cloud provisioning not found in wendy_conf");
        return ESP_FAIL;
    }

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
