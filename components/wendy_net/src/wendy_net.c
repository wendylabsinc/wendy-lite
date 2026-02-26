#include "wendy_net.h"

#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "wasm_export.h"
#include "wendy_safety.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#endif

static const char *TAG = "wendy_net";

/* ── WiFi station/AP control ──────────────────────────────────────────── */

/* wifi_connect(ssid_ptr, ssid_len, pass_ptr, pass_len) -> 0 ok */
static int wifi_connect_wrapper(wasm_exec_env_t exec_env,
                                 const char *ssid, int ssid_len,
                                 const char *pass, int pass_len)
{
    wifi_config_t wifi_cfg = { 0 };

    int s = (ssid_len < 31) ? ssid_len : 31;
    int p = (pass_len < 63) ? pass_len : 63;
    memcpy(wifi_cfg.sta.ssid, ssid, s);
    if (pass && pass_len > 0) {
        memcpy(wifi_cfg.sta.password, pass, p);
    }

    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) return -1;

    err = esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);
    if (err != ESP_OK) return -1;

    err = esp_wifi_connect();
    return (err == ESP_OK) ? 0 : -1;
}

/* wifi_disconnect() -> 0 ok */
static int wifi_disconnect_wrapper(wasm_exec_env_t exec_env)
{
    esp_err_t err = esp_wifi_disconnect();
    return (err == ESP_OK) ? 0 : -1;
}

/* wifi_status() -> 0=disconnected, 1=connected, -1=error */
static int wifi_status_wrapper(wasm_exec_env_t exec_env)
{
    wifi_ap_record_t ap_info;
    esp_err_t err = esp_wifi_sta_get_ap_info(&ap_info);
    if (err == ESP_OK) return 1;
    return 0;
}

/* wifi_get_ip(buf_ptr, buf_len) -> bytes written or -1 */
static int wifi_get_ip_wrapper(wasm_exec_env_t exec_env, char *buf, int len)
{
    if (!buf || len < 16) return -1;

    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!netif) return -1;

    esp_netif_ip_info_t ip_info;
    esp_err_t err = esp_netif_get_ip_info(netif, &ip_info);
    if (err != ESP_OK) return -1;

    int written = snprintf(buf, len, IPSTR, IP2STR(&ip_info.ip));
    return (written < len) ? written : len - 1;
}

/* wifi_rssi() -> RSSI in dBm or 0 */
static int wifi_rssi_wrapper(wasm_exec_env_t exec_env)
{
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        return ap_info.rssi;
    }
    return 0;
}

/* wifi_ap_start(ssid_ptr, ssid_len, pass_ptr, pass_len, channel) -> 0 */
static int wifi_ap_start_wrapper(wasm_exec_env_t exec_env,
                                  const char *ssid, int ssid_len,
                                  const char *pass, int pass_len,
                                  int channel)
{
    wifi_config_t wifi_cfg = {
        .ap = {
            .channel = channel,
            .max_connection = 4,
            .authmode = (pass_len > 0) ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN,
        },
    };
    int s = (ssid_len < 31) ? ssid_len : 31;
    int p = (pass_len < 63) ? pass_len : 63;
    memcpy(wifi_cfg.ap.ssid, ssid, s);
    wifi_cfg.ap.ssid_len = s;
    if (pass && pass_len > 0) {
        memcpy(wifi_cfg.ap.password, pass, p);
    }

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_err_t err = esp_wifi_set_config(WIFI_IF_AP, &wifi_cfg);
    return (err == ESP_OK) ? 0 : -1;
}

/* wifi_ap_stop() -> 0 */
static int wifi_ap_stop_wrapper(wasm_exec_env_t exec_env)
{
    esp_wifi_set_mode(WIFI_MODE_STA);
    return 0;
}

/* ── BSD Sockets ──────────────────────────────────────────────────────── */

/* net_socket(domain, type, protocol) -> fd or -1 */
static int net_socket_wrapper(wasm_exec_env_t exec_env,
                               int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

/* net_connect(fd, ip_ptr, ip_len, port) -> 0 or -1 */
static int net_connect_wrapper(wasm_exec_env_t exec_env,
                                int fd, const char *ip, int ip_len, int port)
{
    if (!ip || ip_len <= 0) return -1;

    char ip_buf[48];
    int l = (ip_len < 47) ? ip_len : 47;
    memcpy(ip_buf, ip, l);
    ip_buf[l] = '\0';

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    inet_pton(AF_INET, ip_buf, &addr.sin_addr);

    return connect(fd, (struct sockaddr *)&addr, sizeof(addr));
}

/* net_bind(fd, port) -> 0 or -1 */
static int net_bind_wrapper(wasm_exec_env_t exec_env, int fd, int port)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    return bind(fd, (struct sockaddr *)&addr, sizeof(addr));
}

/* net_listen(fd, backlog) -> 0 or -1 */
static int net_listen_wrapper(wasm_exec_env_t exec_env, int fd, int backlog)
{
    return listen(fd, backlog);
}

/* net_accept(fd) -> new_fd or -1 */
static int net_accept_wrapper(wasm_exec_env_t exec_env, int fd)
{
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    return accept(fd, (struct sockaddr *)&client_addr, &addr_len);
}

/* net_send(fd, data_ptr, data_len) -> bytes sent */
static int net_send_wrapper(wasm_exec_env_t exec_env,
                             int fd, const char *data, int len)
{
    if (!data || len <= 0) return -1;
    return send(fd, data, len, 0);
}

/* net_recv(fd, buf_ptr, buf_len) -> bytes received */
static int net_recv_wrapper(wasm_exec_env_t exec_env,
                             int fd, char *buf, int len)
{
    if (!buf || len <= 0) return -1;
    return recv(fd, buf, len, 0);
}

/* net_close(fd) -> 0 */
static int net_close_wrapper(wasm_exec_env_t exec_env, int fd)
{
    return close(fd);
}

/* ── DNS ──────────────────────────────────────────────────────────────── */

/* dns_resolve(hostname_ptr, hostname_len, result_buf_ptr, result_buf_len) -> bytes written or -1 */
static int dns_resolve_wrapper(wasm_exec_env_t exec_env,
                                const char *hostname, int hostname_len,
                                char *result_buf, int result_len)
{
    if (!hostname || hostname_len <= 0 || !result_buf || result_len < 16) return -1;

    char host_buf[128];
    int l = (hostname_len < 127) ? hostname_len : 127;
    memcpy(host_buf, hostname, l);
    host_buf[l] = '\0';

    struct addrinfo hints = { .ai_family = AF_INET };
    struct addrinfo *res = NULL;

    int rc = getaddrinfo(host_buf, NULL, &hints, &res);
    if (rc != 0 || !res) return -1;

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    const char *ip = inet_ntoa(addr->sin_addr);
    int written = snprintf(result_buf, result_len, "%s", ip);
    freeaddrinfo(res);

    return (written < result_len) ? written : result_len - 1;
}

/* ── TLS (mbedTLS) ────────────────────────────────────────────────────── */

/* tls_connect(host_ptr, host_len, port) -> fd or -1 */
static int tls_connect_wrapper(wasm_exec_env_t exec_env,
                                const char *host, int host_len, int port)
{
    /* Simplified: use a regular socket for now.
     * Full mbedTLS integration would wrap the socket with TLS context. */
    ESP_LOGW(TAG, "tls_connect: mbedTLS not yet integrated, using plain socket");

    char host_buf[128];
    int l = (host_len < 127) ? host_len : 127;
    memcpy(host_buf, host, l);
    host_buf[l] = '\0';

    /* Resolve hostname */
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host_buf, NULL, &hints, &res) != 0 || !res) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    struct sockaddr_in addr;
    memcpy(&addr, res->ai_addr, sizeof(addr));
    addr.sin_port = htons(port);
    freeaddrinfo(res);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* tls_send / tls_recv / tls_close reuse net_send/recv/close for now */

static NativeSymbol s_net_symbols[] = {
    /* WiFi */
    { "wifi_connect",    (void *)wifi_connect_wrapper,    "(*~*~)i",    NULL },
    { "wifi_disconnect", (void *)wifi_disconnect_wrapper, "()i",        NULL },
    { "wifi_status",     (void *)wifi_status_wrapper,     "()i",        NULL },
    { "wifi_get_ip",     (void *)wifi_get_ip_wrapper,     "(*~)i",      NULL },
    { "wifi_rssi",       (void *)wifi_rssi_wrapper,       "()i",        NULL },
    { "wifi_ap_start",   (void *)wifi_ap_start_wrapper,   "(*~*~i)i",   NULL },
    { "wifi_ap_stop",    (void *)wifi_ap_stop_wrapper,    "()i",        NULL },
    /* Sockets */
    { "net_socket",      (void *)net_socket_wrapper,      "(iii)i",     NULL },
    { "net_connect",     (void *)net_connect_wrapper,     "(i*~i)i",    NULL },
    { "net_bind",        (void *)net_bind_wrapper,        "(ii)i",      NULL },
    { "net_listen",      (void *)net_listen_wrapper,      "(ii)i",      NULL },
    { "net_accept",      (void *)net_accept_wrapper,      "(i)i",       NULL },
    { "net_send",        (void *)net_send_wrapper,        "(i*~)i",     NULL },
    { "net_recv",        (void *)net_recv_wrapper,        "(i*~)i",     NULL },
    { "net_close",       (void *)net_close_wrapper,       "(i)i",       NULL },
    /* DNS */
    { "dns_resolve",     (void *)dns_resolve_wrapper,     "(*~*~)i",    NULL },
    /* TLS */
    { "tls_connect",     (void *)tls_connect_wrapper,     "(*~i)i",     NULL },
    { "tls_send",        (void *)net_send_wrapper,        "(i*~)i",     NULL },
    { "tls_recv",        (void *)net_recv_wrapper,        "(i*~)i",     NULL },
    { "tls_close",       (void *)net_close_wrapper,       "(i)i",       NULL },
};

int wendy_net_export_init(void)
{
    if (!wasm_runtime_register_natives("wendy",
                                       s_net_symbols,
                                       sizeof(s_net_symbols) / sizeof(s_net_symbols[0]))) {
        ESP_LOGE(TAG, "failed to register net natives");
        return -1;
    }
    ESP_LOGI(TAG, "networking exports registered (%d functions)",
             (int)(sizeof(s_net_symbols) / sizeof(s_net_symbols[0])));
    return 0;
}
