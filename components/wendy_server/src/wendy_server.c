#include "wendy_server.h"
#include "wendy_conf.h"
#include "wendy_com_link.h"
#include "esp_tls.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#include "esp_log.h"
#include "mdns.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


//--- literals ---//

#define WENDY_SERVER_DUMP_CERT    0

#define TAG                       "wendy_server"
#define WENDY_SERVER_PORT         5054
#define WENDY_SERVER_BACKLOG      4
#define WENDY_SERVER_TASK_STACK   8192
#define WENDY_SERVER_MAX_LINKS    4


//--- types ---//

struct _add_link_op {
    struct wcom_operation base;
    esp_tls_t *tls;
};

struct wendy_server_link {
    esp_tls_t *tls;
    int link_id;
};


//--- globals ---//

extern const uint8_t default_cert_der_start[] asm("_binary_default_cert_der_start");
extern const uint8_t default_cert_der_end[]   asm("_binary_default_cert_der_end");
extern const uint8_t default_key_der_start[]  asm("_binary_default_key_der_start");
extern const uint8_t default_key_der_end[]    asm("_binary_default_key_der_end");

static struct wendy_server_link _links[WENDY_SERVER_MAX_LINKS];
static char *_device_name;


//--- internal functions ---//

static int _tls_verify_cb(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
#if WENDY_SERVER_DUMP_CERT == 1
    char buf[256];
    mbedtls_x509_dn_gets(buf, sizeof(buf), &crt->subject);
    ESP_LOGI(TAG, "peer cert chain depth %d: %s", depth, buf);
#endif
    return 0;
}

static void _on_state_change(struct wcom_state_change_handler *handler, int link_id, enum wcom_link_state state)
{
    ESP_LOGI(TAG, "link %d state -> %d", link_id, (int)state);

    if (state == WCOM_LINK_STATE_CONNECTED)
        return;

    for (int i = 0; i < WENDY_SERVER_MAX_LINKS; i++) {
        if (_links[i].tls != NULL && _links[i].link_id == link_id) {
            ESP_LOGI(TAG, "remove link %d", link_id);
            esp_tls_t *tls = _links[i].tls;
            _links[i].tls = NULL;
            _links[i].link_id = 0;
            wcom_remove_link(link_id);
            int fd = -1;
            esp_tls_get_conn_sockfd(tls, &fd);
            if (fd >= 0)
                close(fd);
            esp_tls_server_session_delete(tls);
            return;
        }
    }
}

static struct wcom_state_change_handler _state_handler = {
    .func = _on_state_change,
};

static void _add_link_exec(struct wcom_operation *op)
{
    static bool subscribed = false;
    if (!subscribed) {
        wcom_add_state_change_handler(&_state_handler);
        subscribed = true;
    }
    struct _add_link_op *aop = (struct _add_link_op *)op;

    int slot = -1;
    for (int i = 0; i < WENDY_SERVER_MAX_LINKS; i++) {
        if (_links[i].tls == NULL) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        ESP_LOGE(TAG, "max local links reached, rejecting connection");
        int fd = -1;
        esp_tls_get_conn_sockfd(aop->tls, &fd);
        if (fd >= 0)
            close(fd);
        esp_tls_server_session_delete(aop->tls);
        free(aop);
        return;
    }

    int link_id = wcom_add_tls_link(aop->tls);
    if (link_id < 0) {
        ESP_LOGE(TAG, "max links reached, rejecting connection");
        int fd = -1;
        esp_tls_get_conn_sockfd(aop->tls, &fd);
        if (fd >= 0)
            close(fd);
        esp_tls_server_session_delete(aop->tls);
        free(aop);
        return;
    }

    ESP_LOGI(TAG, "add link %d", link_id);

    _links[slot].tls = aop->tls;
    _links[slot].link_id = link_id;
    free(aop);
}

static void _server_task(void *arg)
{
    struct wendy_conf_span key = wendy_conf_get_private_key();
    struct wendy_conf_span cert = wendy_conf_get_certificate();
    struct wendy_conf_span chain = wendy_conf_get_chain_of_trust();
    bool trusted = key.size > 0 && cert.size > 0 && chain.size > 0;

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        ESP_LOGE(TAG, "socket() failed: %d", errno);
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port        = htons(WENDY_SERVER_PORT),
    };

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "bind() failed: %d", errno);
        close(listen_fd);
        vTaskDelete(NULL);
        return;
    }

    if (listen(listen_fd, WENDY_SERVER_BACKLOG) < 0) {
        ESP_LOGE(TAG, "listen() failed: %d", errno);
        close(listen_fd);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "listening on port %d", WENDY_SERVER_PORT);
    if (trusted) {
        ESP_LOGI(TAG, "full mTLS enabled: only authenticated clients will be accepted");
    } else {
        ESP_LOGI(TAG, "mTLS disabled: any client will be accepted");
    }

    mdns_txt_item_t txt_items[] = {
        {
            .key = "name",
            .value = _device_name
        },
        {
            .key = "mtls",
            .value = trusted ? "true" : "false"
        }
    };

    esp_err_t mdns_err = mdns_service_add(_device_name, "_wendy-lite", "_tcp", WENDY_SERVER_PORT, txt_items, sizeof(txt_items) / sizeof(txt_items[0]));
    free(_device_name);
    _device_name = NULL;
    if (mdns_err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS service add failed: %s", esp_err_to_name(mdns_err));
    } else {
        ESP_LOGI(TAG, "registered mDNS service _wendy-lite._tcp on port %d", WENDY_SERVER_PORT);
    }

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            ESP_LOGE(TAG, "accept() failed: %d", errno);
            continue;
        }

        esp_tls_t *tls = esp_tls_init();
        if (!tls) {
            ESP_LOGE(TAG, "esp_tls_init() failed");
            close(client_fd);
            continue;
        }

        esp_tls_cfg_server_t cfg;
        if (trusted) {
            cfg = (esp_tls_cfg_server_t){
                .servercert_buf   = cert.data,
                .servercert_bytes = cert.size,
                .serverkey_buf    = key.data,
                .serverkey_bytes  = key.size,
                .cacert_buf       = chain.data,
                .cacert_bytes     = chain.size,
            };
        } else {
            cfg = (esp_tls_cfg_server_t){
                .servercert_buf   = default_cert_der_start,
                .servercert_bytes = default_cert_der_end - default_cert_der_start,
                .serverkey_buf    = default_key_der_start,
                .serverkey_bytes  = default_key_der_end - default_key_der_start,
                // no cacert_buf: peer identity checks disabled
            };
        }

#if WENDY_SERVER_DUMP_CERT == 1
        {
            mbedtls_x509_crt srv_crt;
            mbedtls_x509_crt_init(&srv_crt);
            if (mbedtls_x509_crt_parse_der(&srv_crt, cfg.servercert_buf, cfg.servercert_bytes) == 0) {
                char buf[256];
                mbedtls_x509_dn_gets(buf, sizeof(buf), &srv_crt.subject);
                ESP_LOGI(TAG, "server cert DN: %s", buf);
            }
            mbedtls_x509_crt_free(&srv_crt);
        }
#endif

        esp_err_t init_ret = esp_tls_server_session_init(&cfg, client_fd, tls);
        if (init_ret != ESP_OK) {
            ESP_LOGE(TAG, "TLS session init failed: 0x%x", init_ret);
            close(client_fd);
            esp_tls_server_session_delete(tls);
            continue;
        }

        // Register the verify callback before the handshake so it fires for every
        // certificate in the peer's chain (leaf at depth 0, intermediates at depth 1+).
        mbedtls_ssl_set_verify(esp_tls_get_ssl_context(tls), _tls_verify_cb, NULL);

        int ret;
        while ((ret = esp_tls_server_session_continue_async(tls)) != 0) {
            if (ret != ESP_TLS_ERR_SSL_WANT_READ && ret != ESP_TLS_ERR_SSL_WANT_WRITE)
                break;
        }
        if (ret != 0) {
            ESP_LOGE(TAG, "TLS handshake failed: 0x%x", -ret);
            close(client_fd);
            esp_tls_server_session_delete(tls);
            continue;
        }

        ESP_LOGI(TAG, "accepted TLS connection from %s", inet_ntoa(client_addr.sin_addr));

        struct _add_link_op *op = malloc(sizeof(*op));
        if (!op) {
            ESP_LOGE(TAG, "malloc failed");
            close(client_fd);
            esp_tls_server_session_delete(tls);
            continue;
        }
        op->base.func = _add_link_exec;
        op->tls = tls;
        wcom_core_exec(&op->base);
    }
}


//--- public functions ---//

void wendy_server_start(const char *device_name)
{
    _device_name = device_name ? strdup(device_name) : NULL;
    xTaskCreatePinnedToCore(_server_task, "wendy_server", WENDY_SERVER_TASK_STACK, NULL,
                             CONFIG_WENDY_SERVER_TASK_PRIORITY, NULL,
                             CONFIG_WENDY_SERVER_TASK_CORE_AFFINITY);
}
