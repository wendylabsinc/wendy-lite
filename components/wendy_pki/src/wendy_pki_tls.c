#include "esp_timer.h"
#include "esp_log.h"
#include "http_parser.h"
#include "wendy_pki_internal.h"
#include "wendy_pki_verify.h"
#include <errno.h>
#include <psa/crypto.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int io_recv(void *context, unsigned char *buf, size_t size)
{
    int n = recv(*(int *)context, buf, size, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return MBEDTLS_ERR_SSL_WANT_READ;
    return n < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : n;
}
static int io_send(void *context, const unsigned char *buf, size_t size)
{
    int n = send(*(int *)context, buf, size, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    return n < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : n;
}
void wendy_pki_close(wendy_pki_connection *c)
{
    if (!c) return;
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->config);
    mbedtls_x509_crt_free(&c->roots);
    mbedtls_x509_crt_free(&c->certificate);
    mbedtls_pk_free(&c->key);
    if (c->fd >= 0) close(c->fd);
    free(c);
}
static int configure(wendy_pki_connection *c, int server, const uint8_t *key,
    size_t key_size, const char *cert, struct wendy_conf_span roots)
{
    mbedtls_ssl_init(&c->ssl); mbedtls_ssl_config_init(&c->config);
    mbedtls_x509_crt_init(&c->roots); mbedtls_x509_crt_init(&c->certificate);
    mbedtls_pk_init(&c->key);
    if (psa_crypto_init() != PSA_SUCCESS || !roots.data || !roots.size || roots.size > 16384 ||
        mbedtls_ssl_config_defaults(&c->config, server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) return -1;
    unsigned char *copy = calloc(1, roots.size + 1);
    if (!copy) return -1;
    memcpy(copy, roots.data, roots.size);
    int r = mbedtls_x509_crt_parse(&c->roots, copy, roots.size + 1);
    free(copy);
    if (r) return -1;
    mbedtls_ssl_conf_authmode(&c->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&c->config, wendy_pki_rng, NULL);
    mbedtls_ssl_conf_ca_chain(&c->config, &c->roots, NULL);
    mbedtls_ssl_conf_min_tls_version(&c->config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&c->config, MBEDTLS_SSL_VERSION_TLS1_3);
    if (key || cert) {
        if (!key || !cert ||
            mbedtls_x509_crt_parse(&c->certificate, (const unsigned char *)cert, strlen(cert)+1) ||
            mbedtls_pk_parse_key(&c->key, key, key_size, NULL, 0, wendy_pki_rng, NULL) ||
            mbedtls_pk_check_pair(&c->certificate.pk, &c->key, wendy_pki_rng, NULL) ||
            mbedtls_ssl_conf_own_cert(&c->config, &c->certificate, &c->key)) return -1;
    }
    if (mbedtls_ssl_setup(&c->ssl, &c->config)) return -1;
    mbedtls_ssl_set_bio(&c->ssl, &c->fd, io_send, io_recv, NULL);
    return 0;
}
static int wait_socket(wendy_pki_connection *c, int error, int64_t deadline)
{
    if (error != MBEDTLS_ERR_SSL_WANT_READ && error != MBEDTLS_ERR_SSL_WANT_WRITE)
        return -1;
    int64_t left = deadline - esp_timer_get_time();
    if (left <= 0)
        return -1;
    fd_set rd, wr;
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    if (error == MBEDTLS_ERR_SSL_WANT_READ)
        FD_SET(c->fd, &rd);
    else
        FD_SET(c->fd, &wr);
    struct timeval tv = {left / 1000000, left % 1000000};
    return select(c->fd + 1, &rd, &wr, NULL, &tv) > 0 ? 0 : -1;
}
static int detach_socket(wendy_pki_connection *c)
{
    int64_t deadline = esp_timer_get_time() + 10000000;
    unsigned char byte;
    for (;;) {
        int n = mbedtls_ssl_read(&c->ssl, &byte, 1);
        if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) break;
        // Reject TCP EOF and application data after the upgrade.
        if (n >= 0 || wait_socket(c, n, deadline)) return -1;
    }
    int n;
    while ((n = mbedtls_ssl_close_notify(&c->ssl)) != 0)
        if (wait_socket(c, n, deadline)) return -1;
    int fd = c->fd; c->fd = -1;
    return fd;
}
int wendy_pki_detach(wendy_pki_connection *c)
{
    int fd = detach_socket(c);
    if (fd >= 0)
        wendy_pki_close(c);
    return fd;
}
int pki_tls_connect(const char *host, unsigned port, const uint8_t *key, size_t key_size,
                    const char *cert, struct wendy_conf_span roots, wendy_pki_connection **out)
{
    if (!roots.data || !roots.size || !host || !host[0] || strlen(host) > 253 || !port || port > 65535)
        return -1;
    wendy_pki_connection *c = calloc(1, sizeof *c);
    if (!c)
        return -1;
    c->fd = -1;
    const char *stage = "DNS";
    int tls_error = 0;
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM}, *addresses = NULL;
    char service[6];
    snprintf(service, sizeof service, "%u", port);
    if ((tls_error = getaddrinfo(host, service, &hints, &addresses)) != 0)
        goto fail;
    int64_t deadline = esp_timer_get_time() + 15000000;
    stage = "TCP connect";
    for (struct addrinfo *a = addresses; a; a = a->ai_next)
    {
        c->fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (c->fd < 0)
            continue;
        if (c->fd >= FD_SETSIZE)
        {
            close(c->fd);
            c->fd = -1;
            continue;
        }
        fcntl(c->fd, F_SETFL, O_NONBLOCK);
        int r = connect(c->fd, a->ai_addr, a->ai_addrlen);
        if (r == 0)
            break;
        if (errno == EINPROGRESS && !wait_socket(c, MBEDTLS_ERR_SSL_WANT_WRITE, deadline))
        {
            int e = 0;
            socklen_t n = sizeof e;
            if (!getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &e, &n) && !e)
                break;
        }
        close(c->fd);
        c->fd = -1;
    }
    freeaddrinfo(addresses);
    addresses = NULL;
    if (c->fd < 0)
        goto fail;
    stage = "TLS setup";
    if (configure(c, 0, key, key_size, cert, roots) ||
        mbedtls_ssl_set_hostname(&c->ssl, host)) goto fail;
    stage = "TLS handshake";
    int r;
    while ((r = mbedtls_ssl_handshake(&c->ssl)) != 0) {
        tls_error = r;
        if (wait_socket(c, r, deadline)) goto fail;
    }
    stage = "certificate verification";
    tls_error = (int)mbedtls_ssl_get_verify_result(&c->ssl);
    if (tls_error) goto fail;
    *out = c;
    return 0;
fail:
    ESP_LOGW("wendy_pki", "TLS client failed at %s (%s:%u, tls=%d, errno=%d)",
             stage, host, port, tls_error, errno);
    if (addresses)
        freeaddrinfo(addresses);
    wendy_pki_close(c);
    return -1;
}
int wendy_pki_fd(void *v) { return ((wendy_pki_connection *)v)->fd; }
static ssize_t result(wendy_pki_connection *c, int n)
{
    if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
    if (n >= 0)
        return n;
    int e = n;
    return e == MBEDTLS_ERR_SSL_WANT_READ ? -2 : e == MBEDTLS_ERR_SSL_WANT_WRITE ? -3 : -1;
}
ssize_t wendy_pki_read(void *v, void *b, size_t n)
{
    wendy_pki_connection *c = v;
    if (wendy_pki_reset_in_progress() ||
        (c->relay_expires_us && esp_timer_get_time() >= c->relay_expires_us)) return -1;
    return result(c, mbedtls_ssl_read(&c->ssl, b, n));
}
ssize_t wendy_pki_write(void *v, const void *b, size_t n)
{
    wendy_pki_connection *c = v;
    if (wendy_pki_reset_in_progress() ||
        (c->relay_expires_us && esp_timer_get_time() >= c->relay_expires_us)) return -1;
    return result(c, mbedtls_ssl_write(&c->ssl, b, n));
}
#include "wendy_pki_http_response.h"
static int write_all(wendy_pki_connection *c, const void *b, size_t n, int64_t deadline)
{
    const uint8_t *p = b;
    while (n)
    {
        int r = mbedtls_ssl_write(&c->ssl, p, n);
        if (r > 0)
        {
            p += r;
            n -= r;
        }
        else if (wait_socket(c, r, deadline))
            return -1;
    }
    return 0;
}
int pki_http_post_enrollment(const char *url, const char *type, const char *token, const void *body,
                  size_t body_size, const uint8_t *key, size_t key_size, const char *cert,
                  struct wendy_conf_span roots, uint8_t **response, size_t *response_size,
                  char **lite_authority_header)
{
    if (lite_authority_header) *lite_authority_header = NULL;
    struct http_parser_url u;
    http_parser_url_init(&u);
    if (!url || strlen(url) > 279 || http_parser_parse_url(url, strlen(url), 0, &u))
        return -1;
    if (!(u.field_set & (1 << UF_SCHEMA)) || u.field_data[UF_SCHEMA].len != 5 ||
        memcmp(url + u.field_data[UF_SCHEMA].off, "https", 5) || !(u.field_set & (1 << UF_HOST)) ||
        u.field_set & ((1 << UF_USERINFO) | (1 << UF_FRAGMENT) | (1 << UF_QUERY)))
        return -1;
    char host[254], path[280];
    size_t hn = u.field_data[UF_HOST].len;
    if (hn == 0 || hn >= sizeof host)
        return -1;
    memcpy(host, url + u.field_data[UF_HOST].off, hn);
    host[hn] = 0;
    if (!(u.field_set & (1 << UF_PATH)))
        return -1;
    snprintf(path, sizeof path, "%.*s", u.field_data[UF_PATH].len, url + u.field_data[UF_PATH].off);
    if (strpbrk(host, "\r\n") || strpbrk(path, "\r\n") || (token && strpbrk(token, "\r\n")))
        return -1;
    wendy_pki_connection *c = NULL;
    if (pki_tls_connect(host, u.field_set & (1 << UF_PORT) ? u.port : 443, key, key_size, cert, roots, &c))
        return -1;
    char authority[264];
    unsigned port = u.field_set & (1 << UF_PORT) ? u.port : 443;
    snprintf(authority, sizeof authority, strchr(host, ':') ? "[%s]:%u" : "%s:%u", host, port);
    int answer = -1;
    char headers[1400];
    int n = snprintf(headers, sizeof headers,
                     "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: "
                     "%zu\r\nConnection: close\r\n%s%s%s\r\n",
                     path, authority, type, body_size, token ? "Authorization: Bearer " : "",
                     token ? token : "", token ? "\r\n" : "");
    struct response r = {.bytes = calloc(1, PKI_MAX_RESPONSE + 1),
                         .capture_lite_authority = lite_authority_header != NULL};
    if (!r.bytes || n < 0 || n >= sizeof headers)
        goto done;
    int64_t deadline = esp_timer_get_time() + 15000000;
    if (write_all(c, headers, n, deadline) || write_all(c, body, body_size, deadline))
        goto done;
    http_parser parser;
    http_parser_init(&parser, HTTP_RESPONSE);
    parser.data = &r;
    http_parser_settings settings = {.on_body = on_body, .on_message_complete = on_complete,
        .on_header_field = on_header_field, .on_header_value = on_header_value,
        .on_headers_complete = on_headers_complete};
    size_t total = 0;
    char buffer[2048];
    while (!r.complete)
    {
        int got = mbedtls_ssl_read(&c->ssl, (unsigned char *)buffer, sizeof buffer);
        if (got == 0) goto done; // TCP EOF without close_notify is a truncated TLS response.
        if (got == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) got = 0;
        if (got < 0)
        {
            if (wait_socket(c, got, deadline))
                goto done;
            continue;
        }
        total += got;
        if (total > PKI_MAX_RESPONSE + 8192)
            goto done;
        size_t used = http_parser_execute(&parser, &settings, buffer, got);
        if (used != (size_t)got || HTTP_PARSER_ERRNO(&parser) != HPE_OK || (!got && !r.complete))
            goto done;
    }
    if (parser.status_code != 200) {
        ESP_LOGE("wendy_pki", "PKI HTTP request returned status %u", parser.status_code);
        goto done;
    }
    *response = r.bytes;
    *response_size = r.size;
    r.bytes = NULL;
    if (lite_authority_header) {
        *lite_authority_header = r.lite_authority;
        r.lite_authority = NULL;
    }
    answer = 0;
done:
    free(r.lite_authority);
    free(r.bytes);
    wendy_pki_close(c);
    return answer;
}


int pki_http_post(const char *url, const char *type, const char *token, const void *body,
                  size_t body_size, const uint8_t *key, size_t key_size, const char *cert,
                  struct wendy_conf_span roots, uint8_t **response, size_t *response_size)
{
    return pki_http_post_enrollment(url, type, token, body, body_size, key, key_size,
        cert, roots, response, response_size, NULL);
}


/* TLS validates the chain, dates and clientAuth usage. LAN may additionally
 * accept a same-tenant device, with its role fixed for the TLS 1.3 session. */
static int accept_peer(int fd, const uint8_t *key, size_t key_size, const char *cert,
                       struct wendy_conf_span roots, const char *tenant,
                       wendy_pki_connection **out, int64_t deadline, bool allow_device, bool lite)
{
    wendy_pki_connection *c = calloc(1, sizeof *c);
    if (!c) { close(fd); return -1; }
    c->fd = fd;
    if (fd < 0 || fd >= FD_SETSIZE || fcntl(fd, F_SETFL, O_NONBLOCK) < 0) goto fail;
    if (configure(c, 1, key, key_size, cert, roots)) goto fail;
    int r;
    while ((r = mbedtls_ssl_handshake(&c->ssl)) != 0)
        if (wait_socket(c, r, deadline)) goto fail;
    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&c->ssl);
    if (!peer || mbedtls_ssl_get_verify_result(&c->ssl)) goto fail;
    enum wendy_peer_role role = wendy_pki_verify_peer(peer->raw.p, peer->raw.len, tenant);
    if (role == WENDY_PEER_ROLE_NONE || (!allow_device && role != WENDY_PEER_ROLE_OPERATOR) ||
        (lite && wendy_pki_verify_lite_operator(peer->raw.p, peer->raw.len, tenant)) ||
        wendy_lite_peer_hash(peer->raw.p, peer->raw.len, c->operator_hash) ||
        wendy_lite_peer_spki_hash(peer->raw.p, peer->raw.len, c->operator_spki_hash) ||
        wendy_lite_peer_expiry(peer->raw.p, peer->raw.len, &c->operator_expires)) goto fail;
    c->peer_role = role;
    *out = c;
    return 0;
fail:
    wendy_pki_close(c);
    return -1;
}

int pki_tls_accept(int fd, const uint8_t *key, size_t key_size, const char *cert,
                   struct wendy_conf_span roots, const char *tenant,
                   wendy_pki_connection **out, int64_t deadline)
{
    return accept_peer(fd, key, key_size, cert, roots, tenant, out, deadline, false, false);
}

int pki_tls_accept_lan(int fd, const uint8_t *key, size_t key_size, const char *cert,
                       struct wendy_conf_span roots, const char *tenant,
                       wendy_pki_connection **out, int64_t deadline)
{
    return accept_peer(fd, key, key_size, cert, roots, tenant, out, deadline, true, false);
}

int pki_tls_accept_lite(int fd, const uint8_t *key, size_t key_size, const char *cert,
                       struct wendy_conf_span roots, const char *tenant,
                       wendy_pki_connection **out, int64_t deadline)
{
    return accept_peer(fd, key, key_size, cert, roots, tenant, out, deadline, false, true);
}

enum wendy_peer_role wendy_pki_get_peer_role(const wendy_pki_connection *connection)
{
    return connection ? connection->peer_role : WENDY_PEER_ROLE_NONE;
}

static int read_all(wendy_pki_connection *c, uint8_t *out, size_t n, int64_t deadline)
{
    while (n) {
        if (esp_timer_get_time() >= deadline) return -1;
        int got = mbedtls_ssl_read(&c->ssl, out, n);
        if (got > 0) { out += got; n -= got; }
        else if (!got || wait_socket(c, got, deadline)) return -1;
    }
    return 0;
}

int wendy_pki_relay_upgrade(wendy_pki_connection *c, struct wendy_lite_trust *trust)
{
    memset(trust, 0, sizeof *trust);
    const char *stage = "grant key set";
    uint8_t header[4], count;
    int64_t deadline = esp_timer_get_time() + 10000000;
    if (read_all(c, header, 4, deadline) || memcmp(header, "WR\x03\x04", 4) ||
        read_all(c, &count, 1, deadline) || count < 1 || count > 2) goto fail;
    trust->count = count;
    for (unsigned i = 0; i < count; i++) {
        struct wendy_lite_key *key = &trust->keys[i];
        if (read_all(c, &key->id_size, 1, deadline) || key->id_size < 1 || key->id_size > 128 ||
            read_all(c, key->id, key->id_size, deadline) || wendy_lite_key_id(key->id, key->id_size) ||
            read_all(c, key->public_key, sizeof key->public_key, deadline)) goto fail;
        if (i && trust->keys[0].id_size == key->id_size &&
            !memcmp(trust->keys[0].id, key->id, key->id_size)) goto fail;
    }
    int64_t renew = esp_timer_get_time() + 240000000;
    bool first = true;
    for (;;) {
        stage = "heartbeat";
        deadline = esp_timer_get_time() + 30000000;
        if (deadline > renew) deadline = renew;
        if (read_all(c, header, 4, deadline) || memcmp(header, "WR\x03", 3)) {
            if (esp_timer_get_time() >= renew) {
                ESP_LOGI("wendy_pki", "refreshing broker control connection");
                return -1;
            }
            goto fail;
        }
        if (header[3] == 1) {
            if (write_all(c, "WR\x03\x02", 4, deadline)) goto fail;
            if (first) ESP_LOGI("wendy_pki", "broker control heartbeat received and answered");
            first = false;
        } else if (header[3] == 3) {
            stage = "relay handoff";
            deadline = esp_timer_get_time() + 10000000;
            if (read_all(c, trust->session, 16, deadline) ||
                read_all(c, trust->grant_hash, 32, deadline)) goto fail;
            int fd = detach_socket(c);
            if (fd < 0) goto fail;
            ESP_LOGI("wendy_pki", "broker control handed off to operator TLS");
            return fd;
        } else goto fail;
    }
fail:
    ESP_LOGW("wendy_pki", "broker control failed at %s", stage);
    return -1;
}

int pki_relay_grant(wendy_pki_connection *c, const struct wendy_lite_trust *trust, int64_t deadline)
{
    if (!c || c->peer_role != WENDY_PEER_ROLE_OPERATOR) return -1;
    uint8_t *record = malloc(WENDY_LITE_GRANT_MAX);
    if (!record) return -1;
    int result = -1;
    if (read_all(c, record, 5, deadline) || memcmp(record, "WLG2", 4) ||
        record[4] < 1 || record[4] > 128) goto done;
    size_t size = WENDY_LITE_GRANT_FIXED + record[4];
    uint64_t expires = 0;
    if (read_all(c, record + 5, size - 5, deadline) ||
        wendy_lite_verify_grant(record, size, trust, c->device_hash, c->operator_hash, c->operator_spki_hash, time(NULL), &expires)) goto done;
    // presentBy authorizes presentation only. Bound the session separately by
    // its signed issue time and both authenticated certificates.
    if (c->device_expires <= 0 || c->operator_expires <= 0) goto done;
    if (expires > (uint64_t)c->device_expires) expires = (uint64_t)c->device_expires;
    if (expires > (uint64_t)c->operator_expires) expires = (uint64_t)c->operator_expires;
    int64_t remaining = (int64_t)expires - (int64_t)time(NULL);
    if (remaining <= 0 || remaining > 1800) goto done;
    c->relay_expires_us = esp_timer_get_time() + remaining * 1000000;
    if (write_all(c, "WLA2", 4, deadline)) goto done;
    result = 0;
done:
    if (result) ESP_LOGW("wendy_pki", "operator relay grant rejected");
    free(record);
    return result;
}
