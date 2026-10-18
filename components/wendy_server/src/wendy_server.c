#include "wendy_server.h"
#include "wendy_server_tls.h"
#include "wendy_conf.h"
#include "wendy_pki.h"
#include "wendy_com_link.h"
#include "esp_tls.h"
#include "mbedtls/x509_crt.h"
#include "esp_log.h"
#include "mdns.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


//--- literals ---//

#define WENDY_SERVER_DUMP_CERT    0

#define TAG                       "wendy_server"
#define WENDY_SERVER_PORT         5054
#define WENDY_SERVER_BACKLOG      4
#if CONFIG_WENDY_PKI
#define WENDY_SERVER_TASK_STACK   24576
#else
#define WENDY_SERVER_TASK_STACK   8192
#endif
#define WENDY_SERVER_MAX_LINKS    4


//--- types ---//

struct _add_link_op {
    struct wcom_operation base;
    esp_tls_t *tls;
    wendy_pki_connection *pki;
};

struct wendy_server_link {
    esp_tls_t *tls;
    wendy_pki_connection *pki;
    int link_id;
};


//--- globals ---//

static struct wendy_server_link _links[WENDY_SERVER_MAX_LINKS];
static struct wendy_server_caps _caps = { .sensor_link = false };
static bool _running = false;


//--- internal functions ---//

#if CONFIG_WENDY_PKI
static enum wcom_link_permission _peer_permission(enum wendy_peer_role role)
{
    switch (role) {
    case WENDY_PEER_ROLE_OPERATOR:
        return WCOM_LINK_PERMISSION_FULL;
    case WENDY_PEER_ROLE_DEVICE:
        return WCOM_LINK_PERMISSION_SENSOR_ONLY;
    default:
        return WCOM_LINK_PERMISSION_NONE;
    }
}

static const struct wcom_stream_ops pki_ops = {
    .read = wendy_pki_read, .write = wendy_pki_write, .wakeup_fd = wendy_pki_fd,
};
#endif

static void _on_interruption(int link_id, enum wcom_interruption_reason reason)
{
    for (int i = 0; i < WENDY_SERVER_MAX_LINKS; i++) {
        if ((_links[i].tls != NULL || _links[i].pki != NULL) && _links[i].link_id == link_id) {
            ESP_LOGI(TAG, "remove link %d (reason %d)", link_id, (int)reason);
#if CONFIG_WENDY_PKI
            if (_links[i].pki) {
                wcom_remove_link(link_id);
                wendy_pki_close(_links[i].pki);
                _links[i].pki = NULL;
                _links[i].link_id = 0;
                return;
            }
#endif
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

static void _add_link_exec(struct wcom_operation *op)
{
    struct _add_link_op *aop = (struct _add_link_op *)op;

#if CONFIG_WENDY_PKI
    if (aop->pki) {
        if (!wendy_conf_has_enrollment() || wendy_pki_reset_in_progress()) {
            wendy_pki_close(aop->pki);
            free(aop);
            return;
        }
        for (int i = 0; i < WENDY_SERVER_MAX_LINKS; i++) {
            if (_links[i].tls || _links[i].pki) continue;
            int id = wcom_add_socket_link_with_permission(&pki_ops, aop->pki,
                _on_interruption, _peer_permission(wendy_pki_get_peer_role(aop->pki)));
            if (id < 0) break;
            _links[i].pki = aop->pki;
            _links[i].link_id = id;
            free(aop);
            return;
        }
        wendy_pki_close(aop->pki);
        free(aop);
        return;
    }
#endif
    if (wendy_conf_has_enrollment() || wendy_pki_reset_in_progress()) {
        int fd = -1;
        esp_tls_get_conn_sockfd(aop->tls, &fd);
        if (fd >= 0) close(fd);
        esp_tls_server_session_delete(aop->tls);
        free(aop);
        return;
    }
    int slot = -1;
    for (int i = 0; i < WENDY_SERVER_MAX_LINKS; i++) {
        if (_links[i].tls == NULL && _links[i].pki == NULL) {
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

    int link_id = wendy_server_add_anonymous_tls_link(aop->tls, _on_interruption);
    if (link_id < 0) {
        ESP_LOGE(TAG, "LAN TLS link setup failed, rejecting connection");
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
    bool enrolled = wendy_conf_has_enrollment();

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
    if (enrolled)
        ESP_LOGI(TAG, "mTLS required: same-tenant operators or devices with SensorLink-only access");
    else
        ESP_LOGI(TAG, "device is unenrolled: anonymous TLS clients are allowed");

    // The full identity, so a browser can tell which board answers without
    // opening a connection first: the ID pins it down, the names label it.
    mdns_txt_item_t txt_items[5];
    size_t txt_count = 0;

    txt_items[txt_count++] = (mdns_txt_item_t){ .key = "id",          .value = wendy_conf_get_device_id() };
    txt_items[txt_count++] = (mdns_txt_item_t){ .key = "name",        .value = wendy_conf_get_resolved_device_name() };
    txt_items[txt_count++] = (mdns_txt_item_t){ .key = "displayname", .value = wendy_conf_get_resolved_device_display_name() };
    txt_items[txt_count++] = (mdns_txt_item_t){ .key = "mtls",        .value = enrolled ? "true" : "false" };

    if (_caps.sensor_link)
        txt_items[txt_count++] = (mdns_txt_item_t){ .key = "caps", .value = "sensors" };

    esp_err_t mdns_err = mdns_service_add(wendy_conf_get_resolved_device_display_name(),
                                          "_wendy-lite", "_tcp", WENDY_SERVER_PORT,
                                          txt_items, txt_count);
    if (mdns_err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS service add failed: %s", esp_err_to_name(mdns_err));
    } else {
        ESP_LOGI(TAG, "registered mDNS service _wendy-lite._tcp on port %d", WENDY_SERVER_PORT);
    }

    if (enrolled) {
        WendyConfEnrollment enrollment = WendyConfEnrollment_init_zero;
        struct wendy_conf_enrollment_data enrollment_data = {0};
        if (wendy_conf_copy_enrollment(&enrollment, &enrollment_data) == ESP_OK) {
            mdns_service_txt_item_set("_wendy-lite", "_tcp", "tenant", enrollment.tenant_id);
            char principal[160];
            snprintf(principal, sizeof principal, "spiffe://wendy.sh/tenant/%s/device/%s",
                     enrollment.tenant_id, enrollment.device_id);
            mdns_service_txt_item_set("_wendy-lite", "_tcp", "principal", principal);
        }
        free(enrollment_data.storage);
        memset(&enrollment, 0, sizeof enrollment);
    }


    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            ESP_LOGE(TAG, "accept() failed: %d", errno);
            continue;
        }

        // SensorLink sends small headers followed by payloads. Do not wait
        // for a delayed ACK before transmitting the next TLS record.
        int no_delay = 1;
        if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof no_delay) < 0) {
            ESP_LOGW(TAG, "setting TCP_NODELAY failed: %d", errno);
            close(client_fd);
            continue;
        }

        // Once enrollment is configured, never fall back to anonymous TLS.
        if (wendy_conf_has_enrollment()) {
#if CONFIG_WENDY_PKI
            struct _add_link_op *op = calloc(1, sizeof *op);
            if (!op) { close(client_fd); continue; }
            if (wendy_pki_accept_lan(client_fd, &op->pki) != ESP_OK) {
                ESP_LOGW(TAG, "PKI LAN authentication failed");
                free(op);
                continue;
            }
            op->base.func = _add_link_exec;
            wcom_core_exec(&op->base);
#else
            close(client_fd);
#endif
            continue;
        }
        // Anonymous TLS is only available before enrollment.
        struct wendy_conf_span key = wendy_conf_get_default_private_key();
        struct wendy_conf_span cert = wendy_conf_get_default_certificate();
        if (wendy_pki_reset_in_progress()) {
            ESP_LOGW(TAG, "LAN authentication unavailable during enrollment reset");
            close(client_fd);
            continue;
        }
        esp_tls_t *tls = esp_tls_init();
        if (!tls) {
            ESP_LOGE(TAG, "esp_tls_init() failed");
            close(client_fd);
            continue;
        }

        esp_tls_cfg_server_t cfg = {
            .servercert_buf   = cert.data,
            .servercert_bytes = cert.size,
            .serverkey_buf    = key.data,
            .serverkey_bytes  = key.size,
        };

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

        // Enrollment or reset during the handshake invalidates anonymous access.
        if (wendy_conf_has_enrollment() || wendy_pki_reset_in_progress()) {
            ESP_LOGW(TAG, "LAN client rejected: enrollment state changed during TLS handshake");
            close(client_fd);
            esp_tls_server_session_delete(tls);
            continue;
        }

        ESP_LOGI(TAG, "accepted TLS connection from %s", inet_ntoa(client_addr.sin_addr));

        struct _add_link_op *op = calloc(1, sizeof(*op));
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

void wendy_server_set_caps(const struct wendy_server_caps caps)
{
    assert(!_running);
    _caps = caps;
}

void wendy_server_start(void)
{
    _running = true;
    xTaskCreatePinnedToCore(_server_task, "wendy_server", WENDY_SERVER_TASK_STACK, NULL,
                             CONFIG_WENDY_SERVER_TASK_PRIORITY, NULL,
                             CONFIG_WENDY_SERVER_TASK_CORE_AFFINITY);
}

void wendy_server_accept_operator(int fd, const struct wendy_lite_trust *trust)
{
#if CONFIG_WENDY_PKI
    struct _add_link_op *op = calloc(1, sizeof *op);
    if (!op) { close(fd); return; }
    if (wendy_pki_accept_relay(fd, trust, &op->pki) != ESP_OK) {
        ESP_LOGW(TAG, "cloud operator session rejected");
        free(op);
        return;
    }
    op->base.func = _add_link_exec;
    wcom_core_exec(&op->base);
#else
    (void)trust;
    close(fd);
#endif
}
