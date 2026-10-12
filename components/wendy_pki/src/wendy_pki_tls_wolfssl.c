#include "esp_timer.h"
#include "esp_log.h"
#include "http_parser.h"
#include "wendy_pki_internal.h"
#include "wendy_pki_verify.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/evp.h>

static pthread_once_t tls_once = PTHREAD_ONCE_INIT;
static int tls_ready;
static void init_tls(void) { tls_ready = wendy_pki_backend_init() == 0; }

/* Never override wolfSSL's trust, hostname, date, or signature failures. Apply
 * the same minimum algorithms as the default mbedTLS certificate profile. */
static int certificate_policy(int verified, WOLFSSL_X509_STORE_CTX *context)
{
    if (!verified || !context) return 0;
    WOLFSSL_X509 *cert = wolfSSL_X509_STORE_CTX_get_current_cert(context);
    if (!cert) return 0;
    bool anchor = false;
    if (wolfSSL_X509_get_isCA(cert) &&
        wolfSSL_X509_NAME_cmp(wolfSSL_X509_get_issuer_name(cert),
                             wolfSSL_X509_get_subject_name(cert)) == 0) {
        WOLFSSL_EVP_PKEY *key = wolfSSL_X509_get_pubkey(cert);
        anchor = key && wolfSSL_X509_verify(cert, key) == WOLFSSL_SUCCESS;
        wolfSSL_EVP_PKEY_free(key);
    }
    return wendy_pki_certificate_policy(cert, anchor) == 0;
}

static int io_recv(WOLFSSL *ssl, char *buf, int size, void *context)
{
    (void)ssl;
    int fd = *(int *)context;
    int n = recv(fd, buf, size, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return WOLFSSL_CBIO_ERR_WANT_READ;
    return n == 0 ? WOLFSSL_CBIO_ERR_CONN_CLOSE : n < 0 ? WOLFSSL_CBIO_ERR_GENERAL : n;
}
static int io_send(WOLFSSL *ssl, char *buf, int size, void *context)
{
    (void)ssl;
    int n = send(*(int *)context, buf, size, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return n < 0 ? WOLFSSL_CBIO_ERR_GENERAL : n;
}
void wendy_pki_close(wendy_pki_connection *c)
{
    if (!c)
        return;
    wolfSSL_free(c->ssl);
    wolfSSL_CTX_free(c->ctx);
    if (c->fd >= 0)
        close(c->fd);
    free(c);
}
static int wait_socket(wendy_pki_connection *c, int error, int64_t deadline)
{
    if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE)
        return -1;
    int64_t left = deadline - esp_timer_get_time();
    if (left <= 0)
        return -1;
    fd_set rd, wr;
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    if (error == WOLFSSL_ERROR_WANT_READ)
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
        int n = wolfSSL_read(c->ssl, &byte, 1);
        if (n > 0) // Application data is illegal after the upgrade record.
            return -1;
        int error = wolfSSL_get_error(c->ssl, n);
        if (error == WOLFSSL_ERROR_ZERO_RETURN)
            break;
        if (wait_socket(c, error, deadline))
            return -1;
    }
    // A TCP EOF is not sufficient: require the authenticated TLS notification.
    if (!(wolfSSL_get_shutdown(c->ssl) & WOLFSSL_RECEIVED_SHUTDOWN))
        return -1;
    int n;
    while ((n = wolfSSL_shutdown(c->ssl)) != WOLFSSL_SUCCESS)
        if (wait_socket(c, wolfSSL_get_error(c->ssl, n), deadline))
            return -1;
    int fd = c->fd;
    c->fd = -1;
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
    pthread_once(&tls_once, init_tls);
    if (!tls_ready || !roots.data || !roots.size || roots.size > 16384 ||
        !host || !host[0] || strlen(host) > 253 || !port || port > 65535 ||
        (key == NULL) != (cert == NULL) || key_size > INT_MAX)
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
        if (errno == EINPROGRESS && !wait_socket(c, WOLFSSL_ERROR_WANT_WRITE, deadline))
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
    c->ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!c->ctx)
        goto fail;
    wolfSSL_CTX_set_group_messages(c->ctx);
    wolfSSL_CTX_set_verify(c->ctx, WOLFSSL_VERIFY_PEER, certificate_policy);
    if (wolfSSL_CTX_load_verify_buffer(c->ctx, roots.data, roots.size,
                                       WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        goto fail;
    if (key && cert)
    {
        if (wolfSSL_CTX_use_certificate_chain_buffer_format(
                c->ctx, (uint8_t *)cert, strlen(cert), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
            wolfSSL_CTX_use_PrivateKey_buffer(c->ctx, key, key_size, WOLFSSL_FILETYPE_ASN1) !=
                WOLFSSL_SUCCESS ||
            wolfSSL_CTX_check_private_key(c->ctx) != WOLFSSL_SUCCESS)
            goto fail;
    }
    wolfSSL_CTX_SetIORecv(c->ctx, io_recv);
    wolfSSL_CTX_SetIOSend(c->ctx, io_send);
    c->ssl = wolfSSL_new(c->ctx);
    if (!c->ssl)
        goto fail;
    wolfSSL_SetIOReadCtx(c->ssl, &c->fd);
    wolfSSL_SetIOWriteCtx(c->ssl, &c->fd);
    if (wolfSSL_check_domain_name(c->ssl, host) != WOLFSSL_SUCCESS ||
        wolfSSL_UseSNI(c->ssl, WOLFSSL_SNI_HOST_NAME, host, strlen(host)) != WOLFSSL_SUCCESS)
        goto fail;
    stage = "TLS handshake";
    int r;
    while ((r = wolfSSL_connect(c->ssl)) != WOLFSSL_SUCCESS) {
        tls_error = wolfSSL_get_error(c->ssl, r);
        if (wait_socket(c, tls_error, deadline)) goto fail;
    }
    stage = "certificate verification";
    tls_error = (int)wolfSSL_get_verify_result(c->ssl);
    if (tls_error != 0) goto fail;
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
    if (n > 0)
        return n;
    int e = wolfSSL_get_error(c->ssl, n);
    if (e == WOLFSSL_ERROR_ZERO_RETURN &&
        (wolfSSL_get_shutdown(c->ssl) & WOLFSSL_RECEIVED_SHUTDOWN)) return 0;
    return e == WOLFSSL_ERROR_WANT_READ ? -2 : e == WOLFSSL_ERROR_WANT_WRITE ? -3 : -1;
}
ssize_t wendy_pki_read(void *v, void *b, size_t n)
{
    wendy_pki_connection *c = v;
    if (wendy_pki_reset_in_progress() || n > INT_MAX ||
        (c->relay_expires_us && esp_timer_get_time() >= c->relay_expires_us)) return -1;
    return result(c, wolfSSL_read(c->ssl, b, n));
}
ssize_t wendy_pki_write(void *v, const void *b, size_t n)
{
    wendy_pki_connection *c = v;
    if (wendy_pki_reset_in_progress() || n > INT_MAX ||
        (c->relay_expires_us && esp_timer_get_time() >= c->relay_expires_us)) return -1;
    return result(c, wolfSSL_write(c->ssl, b, n));
}
struct response
{
    uint8_t *bytes;
    size_t size;
    bool complete;
};
static int on_body(http_parser *p, const char *b, size_t n)
{
    struct response *r = p->data;
    if (n > PKI_MAX_RESPONSE - r->size)
        return -1;
    memcpy(r->bytes + r->size, b, n);
    r->size += n;
    return 0;
}
static int on_complete(http_parser *p)
{
    ((struct response *)p->data)->complete = true;
    return 0;
}
static int write_all(wendy_pki_connection *c, const void *b, size_t n, int64_t deadline)
{
    const uint8_t *p = b;
    while (n)
    {
        int r = wolfSSL_write(c->ssl, p, n);
        if (r > 0)
        {
            p += r;
            n -= r;
        }
        else if (wait_socket(c, wolfSSL_get_error(c->ssl, r), deadline))
            return -1;
    }
    return 0;
}
int pki_http_post(const char *url, const char *type, const char *token, const void *body,
                  size_t body_size, const uint8_t *key, size_t key_size, const char *cert,
                  struct wendy_conf_span roots, uint8_t **response, size_t *response_size)
{
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
    struct response r = {.bytes = calloc(1, PKI_MAX_RESPONSE + 1)};
    if (!r.bytes || n < 0 || n >= sizeof headers)
        goto done;
    int64_t deadline = esp_timer_get_time() + 15000000;
    if (write_all(c, headers, n, deadline) || write_all(c, body, body_size, deadline))
        goto done;
    http_parser parser;
    http_parser_init(&parser, HTTP_RESPONSE);
    parser.data = &r;
    http_parser_settings settings = {.on_body = on_body, .on_message_complete = on_complete};
    size_t total = 0;
    char buffer[2048];
    while (!r.complete)
    {
        int got = wolfSSL_read(c->ssl, buffer, sizeof buffer);
        if (got <= 0)
        {
            int error = wolfSSL_get_error(c->ssl, got);
            if (error == WOLFSSL_ERROR_ZERO_RETURN &&
                (wolfSSL_get_shutdown(c->ssl) & WOLFSSL_RECEIVED_SHUTDOWN)) {
                got = 0;
            } else {
                if (wait_socket(c, error, deadline))
                    goto done;
                continue;
            }
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
    answer = 0;
done:
    free(r.bytes);
    wendy_pki_close(c);
    return answer;
}


/* TLS validates the chain, dates and clientAuth usage. Also require exactly
 * one operator URI in this device's tenant, never another device's identity. */

int pki_tls_accept(int fd, const uint8_t *key, size_t key_size, const char *cert,
                   struct wendy_conf_span roots, const char *tenant, wendy_pki_connection **out, int64_t deadline)
{
    pthread_once(&tls_once, init_tls);
    if (!tls_ready || !key || !key_size || key_size > INT_MAX || !cert ||
        !roots.data || !roots.size || roots.size > 16384 || !tenant) {
        close(fd);
        return -1;
    }
    wendy_pki_connection *c = calloc(1, sizeof *c);
    if (!c) { close(fd); return -1; }
    c->fd = fd;
    if (fd < 0 || fd >= FD_SETSIZE || fcntl(fd, F_SETFL, O_NONBLOCK) < 0) goto fail;
    c->ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!c->ctx) goto fail;
    // Build the complete certificate flight before nonblocking socket writes.
    // Retrying wolfSSL 5.9.1 mid-certificate resets its chain-fragment cursor.
    wolfSSL_CTX_set_group_messages(c->ctx);
    wolfSSL_CTX_set_verify(c->ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, certificate_policy);
    if (wolfSSL_CTX_load_verify_buffer(c->ctx, roots.data, roots.size, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_certificate_chain_buffer_format(c->ctx, (const uint8_t *)cert, strlen(cert), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_buffer(c->ctx, key, key_size, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_check_private_key(c->ctx) != WOLFSSL_SUCCESS) goto fail;
    wolfSSL_CTX_SetIORecv(c->ctx, io_recv);
    wolfSSL_CTX_SetIOSend(c->ctx, io_send);
    c->ssl = wolfSSL_new(c->ctx);
    if (!c->ssl) goto fail;
    wolfSSL_SetIOReadCtx(c->ssl, &c->fd);
    wolfSSL_SetIOWriteCtx(c->ssl, &c->fd);
    int r;
    while ((r = wolfSSL_accept(c->ssl)) != WOLFSSL_SUCCESS)
        if (wait_socket(c, wolfSSL_get_error(c->ssl, r), deadline)) goto fail;
    WOLFSSL_X509 *peer = wolfSSL_get_peer_certificate(c->ssl);
    int peer_size = 0;
    const uint8_t *peer_der = peer ? wolfSSL_X509_get_der(peer, &peer_size) : NULL;
    int valid_operator = wendy_pki_verify_operator(peer_der, peer_size, tenant);
    if (!valid_operator) valid_operator = wendy_lite_peer_hash(peer_der, peer_size, c->operator_hash);
    if (!valid_operator) valid_operator = wendy_lite_peer_spki_hash(peer_der, peer_size, c->operator_spki_hash);
    if (!valid_operator) valid_operator = wendy_lite_peer_expiry(peer_der, peer_size, &c->operator_expires);
    wolfSSL_X509_free(peer);
    if (valid_operator) goto fail;
    if (wolfSSL_get_verify_result(c->ssl) != 0) goto fail;
    *out = c;
    return 0;
fail:
    wendy_pki_close(c);
    return -1;
}

static int read_all(wendy_pki_connection *c, uint8_t *out, size_t n, int64_t deadline)
{
    while (n) {
        if (esp_timer_get_time() >= deadline) return -1;
        int got = wolfSSL_read(c->ssl, out, n);
        if (got > 0) { out += got; n -= got; }
        else if (!got || wait_socket(c, wolfSSL_get_error(c->ssl, got), deadline)) return -1;
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
