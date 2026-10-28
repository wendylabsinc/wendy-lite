#include "esp_timer.h"
#include "esp_log.h"
#include "http_parser.h"
#include "wendy_pki_internal.h"
#include "wendy_pki_dns.h"
#include <arpa/inet.h>
#include <psa/crypto.h>
#include "wendy_pki_verify.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_certificate_policy.h"
#include "wendy_peer_identity.h"
#include <mbedtls/base64.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#if ESP_PLATFORM
#include "sdkconfig.h"
#include "lwip/sockets.h"
#include <net/if.h>
#endif

static int io_recv(void *context, unsigned char *buf, size_t size)
{
    wendy_pki_connection *c = context;
    if (c->stream.read) {
        ssize_t n = c->stream.read(c->stream.context, buf, size);
        if (n == -2) return MBEDTLS_ERR_SSL_WANT_READ;
        if (n == -3) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return n < 0 || (size_t)n > size || n > INT_MAX ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : (int)n;
    }
    int n = recv(c->fd, buf, size, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return MBEDTLS_ERR_SSL_WANT_READ;
    return n < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : n;
}
static int io_send(void *context, const unsigned char *buf, size_t size)
{
    wendy_pki_connection *c = context;
    if (c->stream.write) {
        ssize_t n = c->stream.write(c->stream.context, buf, size);
        if (n == -2) return MBEDTLS_ERR_SSL_WANT_READ;
        if (n == -3) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return n <= 0 || (size_t)n > size || n > INT_MAX ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : (int)n;
    }
    int n = send(c->fd, buf, size, 0);
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
    free(c->mesh_roots);
    if (c->fd >= 0) close(c->fd);
    free(c);
}

/* Add Wendy's algorithm restrictions without overriding certificate-chain,
 * hostname, validity, or key-usage failures reported by mbedTLS. */
static int certificate_policy(void *context, mbedtls_x509_crt *cert, int depth,
                              uint32_t *flags)
{
    (void)depth;
    wendy_pki_connection *c = context;
    bool anchor = false;
    for (const mbedtls_x509_crt *root = &c->roots; root; root = root->next) {
        if (root->raw.len == cert->raw.len &&
            !memcmp(root->raw.p, cert->raw.p, root->raw.len)) {
            anchor = true;
            break;
        }
    }
    if (wendy_pki_certificate_policy(cert, anchor))
        *flags |= MBEDTLS_X509_BADCERT_OTHER;
    if (c->mesh_tenant[0]) {
        time_t expiry;
        if (wendy_lite_peer_expiry(cert->raw.p, cert->raw.len, &expiry))
            *flags |= MBEDTLS_X509_BADCERT_OTHER;
        else if (!c->operator_expires || expiry < c->operator_expires)
            c->operator_expires = expiry;
    }
    return 0;
}

static int configure_failed(const char *stage, int error)
{
    ESP_LOGE("wendy_pki", "TLS setup failed at %s (error=%d)", stage, error);
    (void)stage;
    (void)error;
    return -1;
}

static int configure(wendy_pki_connection *c, int server, const uint8_t *key,
    size_t key_size, const char *cert, struct wendy_conf_span roots)
{
    mbedtls_ssl_init(&c->ssl); mbedtls_ssl_config_init(&c->config);
    mbedtls_x509_crt_init(&c->roots); mbedtls_x509_crt_init(&c->certificate);
    mbedtls_pk_init(&c->key);
    int r = wendy_pki_crypto_init();
    if (r) return configure_failed("crypto initialization", r);
    if (!roots.data || !roots.size || roots.size > 16384)
        return configure_failed("CA bundle input", MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    r = mbedtls_ssl_config_defaults(&c->config,
        server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (r) return configure_failed("mbedtls_ssl_config_defaults", r);
    unsigned char *copy = calloc(1, roots.size + 1);
    if (!copy) return configure_failed("CA bundle allocation", MBEDTLS_ERR_SSL_ALLOC_FAILED);
    memcpy(copy, roots.data, roots.size);
    r = mbedtls_x509_crt_parse(&c->roots, copy, roots.size + 1);
    free(copy);
    if (r) return configure_failed("CA bundle parsing", r);
    mbedtls_ssl_conf_authmode(&c->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_cert_profile(&c->config, wendy_pki_certificate_profile());
    mbedtls_ssl_conf_verify(&c->config, certificate_policy, c);
    mbedtls_ssl_conf_ca_chain(&c->config, &c->roots, NULL);
    mbedtls_ssl_conf_min_tls_version(&c->config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&c->config, MBEDTLS_SSL_VERSION_TLS1_3);
    /* Each connection authenticates certificates. Do not negotiate unused
     * resumption PSKs or require callers to handle post-handshake tickets. */
    mbedtls_ssl_conf_tls13_key_exchange_modes(&c->config,
        MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
    if (key || cert) {
        if (!key || !cert)
            return configure_failed("identity input", MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
        r = mbedtls_x509_crt_parse(&c->certificate, (const unsigned char *)cert, strlen(cert)+1);
        if (r) return configure_failed("identity certificate parsing", r);
        r = mbedtls_pk_parse_key(&c->key, key, key_size, NULL, 0);
        if (r) return configure_failed("private key parsing", r);
        r = mbedtls_pk_check_pair(&c->certificate.pk, &c->key);
        if (r) return configure_failed("certificate/key match", r);
        r = mbedtls_ssl_conf_own_cert(&c->config, &c->certificate, &c->key);
        if (r) return configure_failed("mbedtls_ssl_conf_own_cert", r);
    }
    r = mbedtls_ssl_setup(&c->ssl, &c->config);
    if (r) return configure_failed("mbedtls_ssl_setup", r);
    mbedtls_ssl_set_bio(&c->ssl, c, io_send, io_recv, NULL);
    return 0;
}
static int wait_socket(wendy_pki_connection *c, int error, int64_t deadline)
{
    if (wendy_pki_reset_in_progress()) return -1;
    if (error != MBEDTLS_ERR_SSL_WANT_READ && error != MBEDTLS_ERR_SSL_WANT_WRITE)
        return -1;
    int64_t left = deadline - esp_timer_get_time();
    if (left <= 0)
        return -1;
    if (c->stream.wait) {
        if (wendy_pki_reset_in_progress()) return -1;
        return c->stream.wait(c->stream.context, error == MBEDTLS_ERR_SSL_WANT_WRITE, deadline);
    }
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
    if (!c || c->stream.read || c->fd < 0) return -1;
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
static int bind_interface(int fd, const char* interface)
{
    if (!interface) return 0;
#if ESP_PLATFORM
    struct ifreq request = { 0 };
    if (strlen(interface) >= sizeof request.ifr_name) return -1;
    snprintf(request.ifr_name, sizeof request.ifr_name, "%s", interface);
    return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &request, sizeof request);
#else
    (void)fd;
    return -1;
#endif
}
static int direct_resolve(const char* host, const char* resolver, const char* interface,
    char address[INET_ADDRSTRLEN])
{
    if (!resolver || !resolver[0] || !interface || !interface[0]) return -1;
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM,
        .ai_flags = AI_NUMERICHOST }, *server = NULL;
    if (getaddrinfo(resolver, "53", &hints, &server)) return -1;
    int fd = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
    uint8_t query[272], reply[1024], ip[4];
    /* The connected UDP socket also binds the response to the selected DNS
     * server and the socket's ephemeral source port. */
    uint16_t id;
    size_t size = psa_generate_random((uint8_t*)&id, sizeof id) == PSA_SUCCESS
        ? pki_dns_query(query, host, id) : 0;
    int result = -1;
    if (fd < 0 || fd >= FD_SETSIZE || !size || bind_interface(fd, interface)) goto done;
    struct timeval timeout = { .tv_sec = 5 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout)
        || setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout)
        || connect(fd, server->ai_addr, server->ai_addrlen)
        || send(fd, query, size, 0) != (ssize_t)size) goto done;
    ssize_t n = recv(fd, reply, sizeof reply, 0);
    if (n > 0 && !pki_dns_answer(query, size, reply, n, ip)
        && inet_ntop(AF_INET, ip, address, INET_ADDRSTRLEN)) result = 0;
done:
    if (fd >= 0) close(fd);
    freeaddrinfo(server);
    return result;
}
/* Only the opt-in borrower lengthens ordinary Cloud traffic. A probe bound to
 * a physical interface retains the direct-path budget. Neither budget slides. */
static int64_t network_budget_us(bool gateway, const char *interface)
{
#if CONFIG_WENDY_MESH_CLOUD_UPLINK
    if (!interface) return INT64_C(60000000);
#else
    (void)interface;
#endif
    return gateway ? INT64_C(60000000) : INT64_C(15000000);
}

static int open_tls(const char* host, unsigned port, const uint8_t* key, size_t key_size,
    const char* cert, struct wendy_conf_span roots, wendy_pki_connection** out, const char* tenant,
    const char* device, const char* router, const struct wendy_pki_stream* stream, bool server,
    bool gateway, const char* interface, const char* resolver)
{
    if (out)
        *out = NULL;
    bool mesh = tenant != NULL;
    if (!out || !roots.data || !roots.size
        || (stream ? (!mesh || !stream->read || !stream->write || !stream->wait)
                   : (!host || !host[0] || strlen(host) > 253 || !port || port > 65535)))
        return -1;
    bool discover_peer = mesh && stream && !server && !gateway && !router;
    if (mesh
        && (!device || (!router && !discover_peer) || !wendy_identity_uuid((const unsigned char*)tenant, strlen(tenant))
            || !wendy_identity_uuid((const unsigned char*)device, strlen(device))
            || (router && (!wendy_identity_uuid((const unsigned char*)router, strlen(router))
                || !strcmp(device, router)))))
        return -1;
    wendy_pki_connection* c = calloc(1, sizeof *c);
    if (!c)
        return -1;
    c->fd = -1;
    const char* stage = "TLS setup";
    int tls_error = 0;
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM },
                    *addresses = NULL;
    /* Parse local credentials before starting the broker's TCP deadline. */
    if (configure(c, server, key, key_size, cert, roots))
        goto fail;
    if (mesh)
    {
        static const char* const leaf_protocols[] = { WENDY_PKI_MESH_ALPN, NULL };
        static const char* const gateway_protocols[] = { "wendy-mesh-internet/1", NULL };
        if (mbedtls_ssl_conf_alpn_protocols(&c->config, gateway ? gateway_protocols : leaf_protocols))
            goto fail;
        /* Mesh identity is the exact SPIFFE principal, checked below after
         * mandatory CA verification. It is independent of the dial address. */
        if (mbedtls_ssl_set_hostname(&c->ssl, NULL))
            goto fail;
        memcpy(c->mesh_tenant, tenant, 37);
        memcpy(c->mesh_device, device, 37);
        c->mesh_roots = malloc(roots.size);
        if (!c->mesh_roots)
            goto fail;
        memcpy(c->mesh_roots, roots.data, roots.size);
        c->mesh_roots_size = roots.size;
    }
    else if (mbedtls_ssl_set_hostname(&c->ssl, host))
        goto fail;
    int64_t deadline = esp_timer_get_time() + 30000000;
    if (stream)
        c->stream = *stream;
    else
    {
        stage = "DNS";
        char service[6];
        snprintf(service, sizeof service, "%u", port);
        char direct_address[INET_ADDRSTRLEN];
        const char* dial_host = host;
        if (interface) {
            if (direct_resolve(host, resolver, interface, direct_address)) goto fail;
            dial_host = direct_address;
            hints.ai_flags = AI_NUMERICHOST;
        }
        if ((tls_error = getaddrinfo(dial_host, service, &hints, &addresses)) != 0)
            goto fail;
        /* A gateway handshake carries certificate chains over the mesh radio.
         * Keep a finite budget that includes BLE transmission and TCP retries. */
        deadline = esp_timer_get_time() + network_budget_us(gateway, interface);
        stage = "TCP connect";
        for (struct addrinfo* a = addresses; a; a = a->ai_next)
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
            if (bind_interface(c->fd, interface)) {
                close(c->fd); c->fd = -1; continue;
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
    }
    if (mesh && !gateway)
    {
        uint8_t preface[36] = { 'W', 'M', 'L', '3' };
        const char* uuids[] = { tenant, server ? router : device };
        for (unsigned u = 0; u < 2; u++)
        {
            unsigned offset = 4 + u * 16;
            for (unsigned i = 0; i < 36;)
            {
                if (uuids[u][i] == '-')
                {
                    i++;
                    continue;
                }
                unsigned value = 0;
                for (unsigned j = 0; j < 2; j++)
                {
                    char x = uuids[u][i++];
                    value = value * 16 + (x <= '9' ? x - '0' : x - 'a' + 10);
                }
                preface[offset++] = value;
            }
        }
        uint8_t received[36];
        size_t written = 0;
        while (written < sizeof preface)
        {
            int sent = server ? io_recv(c, received + written, sizeof received - written)
                              : io_send(c, preface + written, sizeof preface - written);
            if (sent > 0)
                written += sent;
            else if (wait_socket(c, sent, deadline))
                goto fail;
        }
        if (server && memcmp(received, preface, sizeof preface))
            goto fail;
    }
    stage = "TLS handshake";
    int r;
    while ((r = mbedtls_ssl_handshake(&c->ssl)) != 0)
    {
        tls_error = r;
        if (wait_socket(c, r, deadline))
            goto fail;
    }
    stage = "certificate verification";
    tls_error = (int)mbedtls_ssl_get_verify_result(&c->ssl);
    if (tls_error)
        goto fail;
    if (mesh)
    {
        const char* alpn = mbedtls_ssl_get_alpn_protocol(&c->ssl);
        const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(&c->ssl);
        char expected[106];
        snprintf(expected, sizeof expected, "spiffe://wendy.sh/tenant/%s/device/", tenant);
        if (!alpn || strcmp(alpn, gateway ? "wendy-mesh-internet/1" : WENDY_PKI_MESH_ALPN) || !peer
            || wendy_pki_verify_peer(peer->raw.p, peer->raw.len, tenant) != WENDY_PEER_ROLE_DEVICE)
            goto fail;
        unsigned count = 0;
        for (const mbedtls_x509_sequence* a = &peer->subject_alt_names; a && a->buf.p; a = a->next)
        {
            mbedtls_x509_subject_alternative_name san;
            if (mbedtls_x509_parse_subject_alt_name(&a->buf, &san)
                || san.type != MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER)
                continue;
            const unsigned char* uri = san.san.unstructured_name.p;
            if (san.san.unstructured_name.len != 105
                || memcmp(uri, expected, 69)
                || !wendy_identity_uuid(uri + 69, 36)
                || !memcmp(uri + 69, device, 36)
                || (router && memcmp(uri + 69, router, 36)))
                goto fail;
            memcpy(c->mesh_peer, uri + 69, 36);
            count++;
        }
        if (count != 1)
            goto fail;
        /* The TLS callback capped the peer's actual verified path. Verify
         * our own path independently; unrelated retired roots in the trust
         * bundle must not shorten either path's lifetime. */
        const uint8_t* der[8];
        size_t sizes[8], cert_count = 0;
        for (const mbedtls_x509_crt* cert = &c->certificate; cert && cert->raw.len;
            cert = cert->next)
        {
            if (cert_count == 8)
                goto fail;
            der[cert_count] = cert->raw.p;
            sizes[cert_count++] = cert->raw.len;
        }
        /* A peer has room for an ML-DSA-65 key; keep it off the caller's stack. */
        struct wendy_pki_mesh_peer* self = calloc(1, sizeof *self);
        time_t now = time(NULL);
        bool verified = self && c->operator_expires && c->operator_expires > now
            && !wendy_pki_mesh_chain(
                der, sizes, cert_count, roots.data, roots.size, tenant, now, self)
            && !strcmp(self->device, device);
        if (verified && self->expires < c->operator_expires)
            c->operator_expires = self->expires;
        free(self);
        if (!verified)
            goto fail;
        c->peer_role = WENDY_PEER_ROLE_DEVICE;
    }
    *out = c;
    return 0;
fail:
    ESP_LOGW("wendy_pki", "TLS peer failed at %s (%s:%u, tls=%d, errno=%d)", stage, host, port,
        tls_error, errno);
    if (addresses)
        freeaddrinfo(addresses);
    wendy_pki_close(c);
    return -1;
}
int pki_tls_connect(const char* host, unsigned port, const uint8_t* key, size_t key_size,
    const char* cert, struct wendy_conf_span roots, wendy_pki_connection** out)
{
    return open_tls(host, port, key, key_size, cert, roots, out, NULL, NULL, NULL, NULL, false, false, NULL, NULL);
}
int pki_tls_mesh_connect(const char* host, unsigned port, const char* tenant, const char* device,
    const char* router, const uint8_t* key, size_t key_size, const char* cert,
    struct wendy_conf_span roots, wendy_pki_connection** out)
{
    return open_tls(host, port, key, key_size, cert, roots, out, tenant, device, router, NULL, false, false, NULL, NULL);
}
int pki_tls_mesh_stream(const struct wendy_pki_stream* stream, bool server,
    const char* tenant, const char* device, const char* peer, const uint8_t* key,
    size_t key_size, const char* cert, struct wendy_conf_span roots, wendy_pki_connection** out)
{
    return open_tls("radio", 0, key, key_size, cert, roots, out,
        tenant, device, peer, stream, server, false, NULL, NULL);
}
int pki_tls_gateway_connect(const char* host, unsigned port, const char* tenant, const char* device,
    const char* router, const uint8_t* key, size_t key_size, const char* cert,
    struct wendy_conf_span roots, wendy_pki_connection** out)
{
    return open_tls(host, port, key, key_size, cert, roots, out,
        tenant, device, router, NULL, false, true, NULL, NULL);
}
int pki_tls_bound_connect(const char* host, unsigned port, const char* interface, const char* resolver,
    const uint8_t* key, size_t key_size, const char* cert,
    struct wendy_conf_span roots, wendy_pki_connection** out)
{
    if (!interface || !interface[0]) return -1;
    return open_tls(host, port, key, key_size, cert, roots, out,
        NULL, NULL, NULL, NULL, false, false, interface, resolver);
}
/* Readiness is only a hint. Stream callbacks may wake spuriously. */
int wendy_pki_wait(wendy_pki_connection* c, bool writing, int64_t deadline)
{
    if (!c || wendy_pki_reset_in_progress()) return -1;
    if (!writing && wendy_pki_pending(c)) return 1;
    int64_t left = deadline - esp_timer_get_time();
    if (left <= 0) return 0;
    if (c->stream.wait)
        return c->stream.wait(c->stream.context, writing, deadline) < 0 ? -1 : 1;
    if (c->fd < 0 || c->fd >= FD_SETSIZE) return -1;
    fd_set set;
    FD_ZERO(&set);
    FD_SET(c->fd, &set);
    struct timeval timeout = { left / 1000000, left % 1000000 };
    return select(c->fd + 1, writing ? NULL : &set, writing ? &set : NULL, NULL, &timeout);
}
int wendy_pki_mesh_sign(wendy_pki_connection* c, const char* principal, const void* body,
    size_t size, uint8_t signature[80], size_t* signature_size)
{
    if (!c || !principal || strlen(principal) != 105 || memcmp(principal + 25, c->mesh_tenant, 36)
        || strcmp(principal + 69, c->mesh_device) || !signature || !signature_size
        || !c->mesh_deadline_us || esp_timer_get_time() >= c->mesh_deadline_us
        || wendy_pki_reset_in_progress())
        return -1;
    uint8_t hash[32];
    return wendy_pki_mesh_digest(principal, body, size, hash)
            || mbedtls_pk_sign(
                &c->key, MBEDTLS_MD_SHA256, hash, sizeof hash, signature, 80, signature_size)
        ? -1
        : 0;
}
int wendy_pki_mesh_bundle(wendy_pki_connection* c, char* out, size_t capacity)
{
    if (!c || !out || capacity < 3 || !c->mesh_roots)
        return -1;
    size_t pos = 0, count = 0;
    out[pos++] = '[';
    for (const mbedtls_x509_crt* cert = &c->certificate; cert && cert->raw.len; cert = cert->next)
    {
        if (++count > 8 || capacity - pos < 4)
            return -1;
        if (count > 1)
            out[pos++] = ',';
        out[pos++] = '"';
        size_t encoded = 0;
        if (mbedtls_base64_encode((unsigned char*)out + pos, capacity - pos - 2, &encoded,
                cert->raw.p, cert->raw.len))
            return -1;
        pos += encoded;
        out[pos++] = '"';
    }
    if (!count || capacity - pos < 2)
        return -1;
    out[pos++] = ']';
    out[pos] = 0;
    return (int)pos;
}
int wendy_pki_mesh_verify_bundle(wendy_pki_connection* c, const uint8_t* const* der,
    const size_t* sizes, size_t count, time_t now, struct wendy_pki_mesh_peer* peer)
{
    return !c || !c->mesh_roots || !c->mesh_deadline_us
            || esp_timer_get_time() >= c->mesh_deadline_us || wendy_pki_reset_in_progress()
        ? -1
        : wendy_pki_mesh_chain(
              der, sizes, count, c->mesh_roots, c->mesh_roots_size, c->mesh_tenant, now, peer);
}
int wendy_pki_fd(void* v)
{
    return ((wendy_pki_connection*)v)->fd;
}
static ssize_t result(int n)
{
    if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        return 0;
    if (n >= 0)
        return n;
    int e = n;
    return e == MBEDTLS_ERR_SSL_WANT_READ ? -2 : e == MBEDTLS_ERR_SSL_WANT_WRITE ? -3 : -1;
}
ssize_t wendy_pki_read(void* v, void* b, size_t n)
{
    wendy_pki_connection* c = v;
    if (wendy_pki_reset_in_progress()
        || (c->relay_expires_us && esp_timer_get_time() >= c->relay_expires_us))
        return -1;
    return result(mbedtls_ssl_read(&c->ssl, b, n));
}
ssize_t wendy_pki_write(void *v, const void *b, size_t n)
{
    wendy_pki_connection *c = v;
    if (wendy_pki_reset_in_progress() ||
        (c->relay_expires_us && esp_timer_get_time() >= c->relay_expires_us)) return -1;
    return result(mbedtls_ssl_write(&c->ssl, b, n));
}
bool wendy_pki_pending(wendy_pki_connection *c)
{
    return c && !wendy_pki_reset_in_progress() &&
        (!c->relay_expires_us || esp_timer_get_time() < c->relay_expires_us) &&
        mbedtls_ssl_get_bytes_avail(&c->ssl) > 0;
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
    struct response r = {.capture_lite_authority = lite_authority_header != NULL};
    if (n < 0 || n >= sizeof headers)
        goto done;
    int64_t deadline = esp_timer_get_time() + network_budget_us(false, NULL);
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
    /* Free the TLS buffers before a chunked body is joined into one block. */
    wendy_pki_close(c);
    c = NULL;
    if (parser.status_code != 200) {
        ESP_LOGE("wendy_pki", "PKI HTTP request returned status %u", parser.status_code);
        goto done;
    }
    if (join_body(&r) || !r.bytes)
        goto done;
    *response = r.bytes;
    *response_size = r.size;
    r.bytes = NULL;
    if (lite_authority_header) {
        *lite_authority_header = r.lite_authority;
        r.lite_authority = NULL;
    }
    answer = 0;
done:
    if (r.alloc_failed)
        ESP_LOGE("wendy_pki", "PKI HTTP response allocation failed for %s%s (%zu bytes received)",
            host, path, r.size);
    free(r.lite_authority);
    free_body(&r);
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
                       wendy_pki_connection **out, int64_t deadline, bool allow_device, bool lite,
                       const struct wendy_pki_stream *stream)
{
    if (out) *out = NULL;
    if (!out || !key || !key_size || !cert || !tenant ||
        (stream && (!stream->read || !stream->write || !stream->wait))) {
        if (fd >= 0) close(fd);
        return -1;
    }
    wendy_pki_connection *c = calloc(1, sizeof *c);
    if (!c) { if (fd >= 0) close(fd); return -1; }
    c->fd = fd;
    if (stream) c->stream = *stream;
    else if (fd < 0 || fd >= FD_SETSIZE || fcntl(fd, F_SETFL, O_NONBLOCK) < 0) goto fail;
    if (configure(c, 1, key, key_size, cert, roots)) goto fail;
    int r;
    while ((r = mbedtls_ssl_handshake(&c->ssl)) != 0)
        if (wait_socket(c, r, deadline)) goto fail;
    if (stream && (wendy_pki_reset_in_progress() || esp_timer_get_time() >= deadline)) goto fail;
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
    return accept_peer(fd, key, key_size, cert, roots, tenant, out, deadline, false, false, NULL);
}

int pki_tls_accept_stream(const struct wendy_pki_stream *stream,
                          const uint8_t *key, size_t key_size, const char *cert,
                          struct wendy_conf_span roots, const char *tenant,
                          wendy_pki_connection **out, int64_t deadline)
{
    if (out) *out = NULL;
    if (!stream || wendy_pki_reset_in_progress() || esp_timer_get_time() >= deadline)
        return -1;
    return accept_peer(-1, key, key_size, cert, roots, tenant, out, deadline, false, false, stream);
}

int pki_tls_accept_lan(int fd, const uint8_t *key, size_t key_size, const char *cert,
                       struct wendy_conf_span roots, const char *tenant,
                       wendy_pki_connection **out, int64_t deadline)
{
    return accept_peer(fd, key, key_size, cert, roots, tenant, out, deadline, true, false, NULL);
}

int pki_tls_accept_lite(int fd, const uint8_t *key, size_t key_size, const char *cert,
                       struct wendy_conf_span roots, const char *tenant,
                       wendy_pki_connection **out, int64_t deadline)
{
    return accept_peer(fd, key, key_size, cert, roots, tenant, out, deadline, false, true, NULL);
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
                return WENDY_PKI_RELAY_RENEW;
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
    if (read_all(c, record, 5, deadline) || memcmp(record, "WLG3", 4) ||
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
