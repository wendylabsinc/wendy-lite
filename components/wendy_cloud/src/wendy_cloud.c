#include "wendy_cloud.h"

#if CONFIG_WENDY_CLOUD_ENABLED

#include "esp_tls.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wendy_conf.h"

#include <string.h>
#include <errno.h>

static const char *TAG = "wendy_cloud";

static volatile wendy_cloud_state_t s_state = WENDY_CLOUD_STATE_IDLE;
static TaskHandle_t                 s_task  = NULL;
static esp_tls_t                    *s_tls  = NULL;


static esp_err_t cloud_connect(void)
{
    s_tls = esp_tls_init();
    if (!s_tls) {
        ESP_LOGE(TAG, "esp_tls_init failed");
        return ESP_ERR_NO_MEM;
    }

    struct wendy_conf_span host = wendy_conf_get_cloud_host();

    int port = 5054;
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
        .cacert_buf       = chain.data,
        .cacert_bytes     = chain.size,
        .clientcert_buf   = cert.data,
        .clientcert_bytes = cert.size,
        .clientkey_buf    = key.data,
        .clientkey_bytes  = key.size,
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

static void cloud_task(void *arg)
{
    ESP_LOGI(TAG, "task started");

    for (;;) {
        s_state = WENDY_CLOUD_STATE_CONNECTING;

        if (cloud_connect() != ESP_OK) {
            s_state = WENDY_CLOUD_STATE_ERROR;
            ESP_LOGI(TAG, "retrying in %d ms", CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS);
            vTaskDelay(pdMS_TO_TICKS(CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS));
            continue;
        }

        s_state = WENDY_CLOUD_STATE_CONNECTED;
        ESP_LOGI(TAG, "mTLS connected");

        uint8_t rx_buf[256];
        for (;;) {
            ssize_t n = esp_tls_conn_read(s_tls, rx_buf, sizeof(rx_buf));
            if (n > 0) {
                ESP_LOGI(TAG, "rx %d bytes", (int)n);
                ESP_LOG_BUFFER_CHAR(TAG, rx_buf, n);
            } else if (n == 0) {
                ESP_LOGW(TAG, "server closed connection");
                break;
            } else {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    ESP_LOGE(TAG, "read error %d (errno %d)", (int)n, errno);
                    break;
                }
            }
        }

        s_state = WENDY_CLOUD_STATE_DISCONNECTED;
        esp_tls_conn_destroy(s_tls);
        s_tls = NULL;
        ESP_LOGI(TAG, "reconnecting in %d ms", CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS);
        vTaskDelay(pdMS_TO_TICKS(CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS));
    }
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
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "started (stack=%d, pri=%d)",
             CONFIG_WENDY_CLOUD_TASK_STACK_SIZE, CONFIG_WENDY_CLOUD_TASK_PRIORITY);
    return ESP_OK;
}

void wendy_cloud_stop(void)
{
    // TODO: is this safe?
    if (s_tls) {
        esp_tls_conn_destroy(s_tls);
        s_tls = NULL;
    }
    if (s_task) {
        vTaskDelete(s_task);
        s_task = NULL;
    }
    s_state = WENDY_CLOUD_STATE_IDLE;
}

wendy_cloud_state_t wendy_cloud_get_state(void)
{
    return s_state;
}

bool wendy_cloud_is_connected(void)
{
    return (s_state == WENDY_CLOUD_STATE_CONNECTED);
}

#endif /* CONFIG_WENDY_CLOUD_ENABLED */
