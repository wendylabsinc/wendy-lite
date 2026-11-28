/* Real Go/Lite TLS resumption fixture using the production native constructor. */
#include "wendy_pki_internal.h"
#include "wendy_pki_issuers.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_parsed_identity.h"
#include "wendy_cert_bundle.h"
#include <mbedtls/platform.h>
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
int64_t esp_timer_get_time(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
bool wendy_pki_reset_in_progress(void)
{
    return false;
}
ssize_t wendy_test_send(int fd, const void *data, size_t n, int flags)
{
    return send(fd, data, n, flags);
}
static uint8_t *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    assert(f);
    assert(!fseek(f, 0, SEEK_END));
    long size = ftell(f);
    assert(size > 0);
    *n = (size_t)size;
    rewind(f);
    uint8_t *p = calloc(1, *n + 1);
    assert(p && fread(p, 1, *n, f) == *n);
    fclose(f);
    return p;
}
static int read_der(void *context, unsigned index, uint8_t **data, size_t *n)
{
    const mbedtls_x509_crt *p = context;
    while (p && index--)
        p = p->next;
    *data = NULL;
    *n = 0;
    if (!p || !p->raw.len)
        return 0;
    *data = pki_owned_malloc(p->raw.len);
    assert(*data);
    *n = p->raw.len;
    memcpy(*data, p->raw.p, *n);
    return 1;
}
static ssize_t io_read(void *context, void *data, size_t n)
{
    ssize_t r = recv(*(int *)context, data, n, 0);
    return r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? -2 : r;
}
static ssize_t io_write(void *context, const void *data, size_t n)
{
    ssize_t r = send(*(int *)context, data, n, 0);
    return r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? -3 : r;
}
static int io_wait(void *context, bool write, int64_t deadline)
{
    int64_t remain = deadline - esp_timer_get_time();
    if (remain <= 0)
        return -1;
    struct pollfd p = {.fd = *(int *)context, .events = write ? POLLOUT : POLLIN};
    return poll(&p, 1, (int)(remain / 1000 + 1));
}

struct public_source {
    const mbedtls_x509_crt *chain;
    const uint8_t *roots;
    size_t roots_size;
};
static int public_read(void *context, unsigned i, uint8_t **data, size_t *size)
{
    struct public_source *p = context;
    return read_der((void *)p->chain, i, data, size);
}
static int public_roots(void *context, uint8_t **data, size_t *size)
{
    struct public_source *p = context;
    *data = malloc(p->roots_size + 1);
    if (!*data) return -1;
    memcpy(*data, p->roots, p->roots_size);
    (*data)[p->roots_size] = 0;
    *size = p->roots_size;
    return 0;
}
static void public_destroy(void *context) { pki_owned_free(context); }
int main(int argc, char **argv)
{
    assert(argc == 9 || argc == 11);
    bool leaf_server = !strcmp(argv[8], "leaf-server");
    assert(leaf_server == (argc == 11));
    bool server = leaf_server || !strcmp(argv[8], "server") || !strcmp(argv[8], "pair-server");
    signal(SIGPIPE, SIG_IGN);
    assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,
                                           wendy_net_memory_scoped_free));
    assert(!wendy_pki_crypto_init());
    size_t cert_size, root_size;
    uint8_t *cert = load(argv[2], &cert_size), *roots = load(argv[3], &root_size);
    mbedtls_x509_crt source;
    mbedtls_x509_crt_init(&source);
    assert(!pki_parse_certificate_bundle(&source, cert, cert_size, false));
    free(cert);
    wendy_net_memory_t memory = WENDY_NET_MEMORY_INITIALIZER;
    assert(wendy_net_memory_open(&memory, 1024 * 1024, true));
    wendy_net_memory_scope_t previous =
        wendy_net_memory_scope_enter(&memory, WENDY_NET_MEMORY_EXTERNAL);
    for (unsigned round = 0; round < 6u; round++) {
        if (round == 2) wendy_pki_net_forget_sessions();
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        assert(fd >= 0);
        struct sockaddr_in address = {.sin_family = AF_INET,
            .sin_port = htons((uint16_t)atoi(argv[4])),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        assert(!connect(fd, (struct sockaddr *)&address, sizeof address));
        assert(!fcntl(fd, F_SETFL, O_NONBLOCK));
        bool application = false;
        bool ble = true;
        struct wendy_pki_stream stream = {
            .context = &fd, .read = io_read, .write = io_write, .wait = io_wait, .ble_carrier = ble};
        size_t key_size;
        uint8_t *key = load(argv[1], &key_size);
        struct pki_public_chain *public = pki_owned_calloc(1, sizeof *public);
        struct public_source *context = pki_owned_calloc(1, sizeof *context);
        assert(public && context);
        context->chain = &source; context->roots = roots; context->roots_size = root_size;
        public->context = context; public->read = public_read;
        public->load_trust = public_roots; public->destroy = public_destroy;
        for (const mbedtls_x509_crt *p = &source; p && p->raw.len; p = p->next) {
            assert(public->count < 8);
            assert(!wendy_pki_sha256(p->raw.p, p->raw.len, public->hashes[public->count++]));
        }
        struct pki_tls_owned_identity owned = {.key = key, .key_size = key_size,
            .verify_at = time(NULL), .certificate_generation = !leaf_server && round >= 4 ? 2 : 1,
            .mesh_certificate_policy = true,
            .read_der = read_der, .der_context = &source,
            .public_chain = public};
        if (leaf_server)
            owned.lite_issuer_der = load(argv[round < 4 ? 9 : 10], &owned.lite_issuer_size);
        const char *expected = argv[7];
        wendy_pki_connection *c = NULL;
        assert(!pki_tls_net_begin(&stream, server, argv[5], argv[6], &owned,
                                  (struct wendy_conf_span){roots, root_size}, application, &c));
        assert(!!c->resumption == ble);
        int result = 1;
        int64_t deadline = esp_timer_get_time() + INT64_C(10000000);
        while (result && esp_timer_get_time() < deadline) {
            result = pki_tls_net_advance(c, application, expected);
            if (result == -2 || result == -3) {
                assert(io_wait(&fd, result == -3, deadline) > 0);
                result = 1;
            } else if (result < 0) {
                fprintf(stderr, "handshake failed round=%u state=%d\n",round,c->ssl.MBEDTLS_PRIVATE(state));
                abort();
            }
        }
        assert(!result);
        assert(!!c->ssl.MBEDTLS_PRIVATE(wendy_tls13_resumed) == (round % 2 == 1));
        assert(!strcmp(c->mesh_peer, argv[7]));
        if (!application) {
            struct wendy_pki_mesh_peer peer;
            assert(!wendy_pki_mesh_authenticated_peer(c, &peer));
            assert(!strcmp(peer.device, argv[7]) && peer.spki_size);
        }
        char message = 'x', reply = 0;
        int n;
        while ((n = wendy_pki_write(c, &message, 1)) < 0) {
            assert(n == -2 || n == -3);
            assert(io_wait(&fd, n == -3, deadline) > 0);
        }
        assert(n == 1);
        while ((n = wendy_pki_read(c, &reply, 1)) < 0) {
            assert(n == -2 || n == -3);
            assert(io_wait(&fd, n == -3, deadline) > 0);
        }
        assert(n == 1 && reply == message);
        fprintf(stderr, "round=%u resumed=%u peer=%s\n",round,
                c->ssl.MBEDTLS_PRIVATE(wendy_tls13_resumed),c->mesh_peer);
        wendy_pki_close(c);
        close(fd);
    }
    wendy_pki_net_forget_sessions();
    wendy_net_memory_scope_leave(previous);
    wendy_net_memory_close(&memory);
    assert(wendy_net_memory_drained(&memory));
    mbedtls_x509_crt_free(&source);
    free(roots);
    return 0;
}
