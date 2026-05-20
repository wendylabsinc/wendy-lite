#include "wendy_cloud.h"

#if CONFIG_WENDY_CLOUD_ENABLED

#include "esp_tls.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "u2_json.h"

#include <string.h>
#include <errno.h>

static const char *TAG = "wendy_cloud";

/* TEMP: provisioning JSON file embedded at build time via EMBED_TXTFILES — null-terminated */
extern const uint8_t s_provisioning_json_start[] asm("_binary_provisioning_json_start");
extern const uint8_t s_provisioning_json_end[]   asm("_binary_provisioning_json_end");

static volatile wendy_cloud_state_t s_state = WENDY_CLOUD_STATE_IDLE;
static TaskHandle_t                 s_task  = NULL;
static esp_tls_t                    *s_tls  = NULL;

static char *_ca_pem;
static char *_device_cert_pem;
static char *_device_key_pem;
static char *_host_name;
static int _host_port;


static esp_err_t _decode_provisioning(void)
{
    free(_ca_pem);
    free(_device_cert_pem);
    free(_device_key_pem);
    free(_host_name);

    _ca_pem = NULL;
    _device_cert_pem = NULL;
    _device_key_pem = NULL;
    _host_name = NULL;
    _host_port = 5555;

    // parse JSON

    U2_JSON json;
    u2_json_init_with_buf(&json, s_provisioning_json_start, s_provisioning_json_end - s_provisioning_json_start);

    if (u2_json_next(&json) != U2_JSON_ELEM_OBJ)
        return ESP_ERR_INVALID_ARG;
    while (u2_json_next(&json) != U2_JSON_ELEM_OBJ_END) {
        if (u2_json_element(&json) != U2_JSON_ELEM_KEY)
            return ESP_ERR_INVALID_ARG;
        if (u2_json_equal_str(&json, "chainPem")) {
            if (u2_json_next(&json) != U2_JSON_ELEM_STR)
                return ESP_ERR_INVALID_ARG;
            _ca_pem = u2_json_str(&json);
        } else if (u2_json_equal_str(&json, "certPem")) {
            if (u2_json_next(&json) != U2_JSON_ELEM_STR)
                return ESP_ERR_INVALID_ARG;
            _device_cert_pem = u2_json_str(&json);
        } else if (u2_json_equal_str(&json, "keyPem")) {
            if (u2_json_next(&json) != U2_JSON_ELEM_STR)
                return ESP_ERR_INVALID_ARG;
            _device_key_pem = u2_json_str(&json);
        } else if (u2_json_equal_str(&json, "cloudHost")) {
            if (u2_json_next(&json) != U2_JSON_ELEM_STR)
                return ESP_ERR_INVALID_ARG;
            _host_name = u2_json_str(&json);
        } else {
            u2_json_next(&json);
            u2_json_skip(&json);
        }
    }

    // extract port number

    if (_host_name && *_host_name != 0) {
        char *p = _host_name + strlen(_host_name) - 1;
        while (*p >= '0' && *p <= '9' && p > _host_name)
            p--;
        if (*p == ':') {
            *p = '\0';
            _host_port = (int)strtol(p + 1, NULL, 10);
        }
    }

    return ESP_OK;
}

static esp_err_t cloud_connect(void)
{
    s_tls = esp_tls_init();
    if (!s_tls) {
        ESP_LOGE(TAG, "esp_tls_init failed");
        return ESP_ERR_NO_MEM;
    }

    esp_tls_cfg_t cfg = {
        .cacert_buf       = (uint8_t *)_ca_pem,
        .cacert_bytes     = strlen(_ca_pem) + 1,
        .clientcert_buf   = (uint8_t *)_device_cert_pem,
        .clientcert_bytes = strlen(_device_cert_pem) + 1,
        .clientkey_buf    = (uint8_t *)_device_key_pem,
        .clientkey_bytes  = strlen(_device_key_pem) + 1,
        /*
         * We do not check the CN in the certificate.
         * The CA chain is still fully verified.
         */
        .skip_common_name = true,
    };

    int ret = esp_tls_conn_new_sync(
        _host_name,
        strlen(_host_name),
        _host_port,
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
        ESP_LOGI(TAG, "Connecting to %s:%d with mTLS", _host_name, _host_port);

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

    esp_err_t err = _decode_provisioning();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "provisioning decode failed");
        return err;
    }

    if (!_ca_pem || !_device_cert_pem || !_device_key_pem || !_host_name) {
        ESP_LOGE(TAG, "no cloud provisioning");
        return ESP_ERR_INVALID_ARG;
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
