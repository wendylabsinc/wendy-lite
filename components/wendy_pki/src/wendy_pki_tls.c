#include "esp_timer.h"
#include "esp_log.h"
#include "http_parser.h"
#include "wendy_pki_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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
int pki_tls_connect(const char *host, unsigned port, const uint8_t *key, size_t key_size,
                    const char *cert, struct wendy_conf_span roots, wendy_pki_connection **out)
{
    if (!roots.data || !roots.size || !host || !host[0] || strlen(host) > 253 || !port || port > 65535)
        return -1;
    wendy_pki_connection *c = calloc(1, sizeof *c);
    if (!c)
        return -1;
    c->fd = -1;
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM}, *addresses = NULL;
    char service[6];
    snprintf(service, sizeof service, "%u", port);
    if (getaddrinfo(host, service, &hints, &addresses))
        goto fail;
    int64_t deadline = esp_timer_get_time() + 15000000;
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
    c->ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!c->ctx)
        goto fail;
    wolfSSL_CTX_set_verify(c->ctx, WOLFSSL_VERIFY_PEER, NULL);
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
    int r;
    while ((r = wolfSSL_connect(c->ssl)) != WOLFSSL_SUCCESS)
        if (wait_socket(c, wolfSSL_get_error(c->ssl, r), deadline))
            goto fail;
    *out = c;
    return 0;
fail:
    if (addresses)
        freeaddrinfo(addresses);
    wendy_pki_close(c);
    return -1;
}
int wendy_pki_fd(void *v) { return ((wendy_pki_connection *)v)->fd; }
static ssize_t result(wendy_pki_connection *c, int n)
{
    if (n >= 0)
        return n;
    int e = wolfSSL_get_error(c->ssl, n);
    return e == WOLFSSL_ERROR_WANT_READ ? -2 : e == WOLFSSL_ERROR_WANT_WRITE ? -3 : -1;
}
ssize_t wendy_pki_read(void *v, void *b, size_t n)
{
    wendy_pki_connection *c = v;
    return result(c, wolfSSL_read(c->ssl, b, n));
}
ssize_t wendy_pki_write(void *v, const void *b, size_t n)
{
    wendy_pki_connection *c = v;
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
        if (got < 0)
        {
            if (wait_socket(c, wolfSSL_get_error(c->ssl, got), deadline))
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
    answer = 0;
done:
    free(r.bytes);
    wendy_pki_close(c);
    return answer;
}
