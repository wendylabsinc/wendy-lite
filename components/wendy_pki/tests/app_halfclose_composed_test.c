/* Production app actor and real TLS with generated device certificates.
 * NVS/configuration and an ordinary guest-owned service use host facades. The client
 * closes its TLS and TCP write halves before the backend produces a reply. */
#define main ordinary_tls_fixture_main
#include "tls_test.c"
#undef main
#include "../../wendy_net_peer/src/app.c"
#include "native_tls_fixture.h"
#include "wendy_net_alloc.h"
#include "wendy_operator_auth.h"
#include <psa/crypto_extra.h>
static struct pki_tls_owned_identity prepared;
static struct wendy_conf_span prepared_roots;
static int guest_fd = -1;
static bool replied;
static unsigned guest_connections;
enum { GUEST_PORT = 0xa811 };
struct wendy_pki_net_setup {
    wendy_pki_connection *connection;
    bool complete;
};
bool wendy_conf_is_current(void)
{
    return true;
}
bool wendy_conf_snapshot_current(uint64_t generation)
{
    return generation == 1;
}
void wendy_conf_get_enrolled_ids(char tenant[37], char device[65])
{
    strcpy(tenant, "2558fd76-afc7-466e-9613-6b715296a526");
    strcpy(device, "00000000-0000-4000-8000-000000000004");
}
void wnad_wake(void)
{
}
bool wnad_handshake_claim(void *owner)
{
    return wendy_pki_handshake_claim(owner);
}
void wnad_handshake_release(void *owner)
{
    wendy_pki_handshake_release(owner);
}
int wnad_no_wait(void *context, bool writing, int64_t deadline)
{
    assert(0);
    return -1;
}
/* This inbound guest test must never fall back to a native loopback backend. */
int wnad_connect(const char *host, unsigned port, bool *connecting)
{
    assert(!"unexpected native loopback backend");
    return -1;
}
int wendy_net_guest_service_begin(uint16_t port)
{
    /* Preserve the driver's WAS1 request bytes; this is now an ordinary guest
     * port, with no native timestamp backend or special-port dispatch. */
    assert(port == GUEST_PORT && guest_fd < 0);
    int pair[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
    assert(!fcntl(pair[0], F_SETFL, O_NONBLOCK));
    assert(!fcntl(pair[1], F_SETFL, O_NONBLOCK));
    guest_fd = pair[1];
    guest_connections++;
    return pair[0];
}
/* Unused guest modes fail closed. Only the ordinary inbound TCP service above
 * may create a backend in this half-close fixture. */
int wendy_net_guest_service_connect(uint16_t port) { return -1; }
int wendy_net_guest_datagram_connect(uint16_t port, int *owner) { return -1; }
int wendy_net_guest_datagram_owner(uint16_t port) { return -1; }
unsigned wendy_net_guest_datagram_capacity(void) { return 0; }
bool wendy_net_mesh_socket_live(int handle) { return false; }
int wendy_net_mesh_connected(int handle, int fd) { assert(0); return -1; }
int wendy_net_mesh_datagram_connected(int handle, unsigned maximum) { assert(0); return -1; }
int wendy_net_guest_datagram_deliver_owned(int owner, int *association, uint8_t **packet,
                                           size_t size, unsigned maximum,
                                           wendy_net_packet_release_fn release)
{ assert(0); return -1; }
int wendy_net_mesh_datagram_receive_owned(int handle, uint8_t **packet, size_t size,
                                          wendy_net_packet_release_fn release)
{ assert(0); return -1; }
int wendy_net_guest_datagram_take(int handle, uint8_t **packet, size_t *size)
{ assert(0); return -1; }
void wendy_net_guest_datagram_sent(int handle) { assert(0); }
void wendy_net_guest_datagram_closed(int handle) { assert(0); }
void wendy_net_mesh_discard_pending_datagrams(void) {}
void wendy_net_set_mesh_connector(wendy_net_mesh_begin_fn fn) {}
void wendy_net_set_mesh_resolver(wendy_net_mesh_resolve_fn fn) {}
void wendy_net_set_service_catalog(wendy_net_service_fn fn) {}
int wendy_net_peer_service_catalog(unsigned op, const void *in, size_t n, char *out, size_t cap)
{ return -1; }
esp_err_t wendy_net_peer_agent_endpoint_now(const char *peer, uint8_t address[16], uint16_t *port)
{ return ESP_ERR_NOT_FOUND; }
esp_err_t wendy_net_peer_app_endpoint_now(const char *peer, uint8_t address[16], uint16_t *port)
{ return ESP_ERR_NOT_FOUND; }
int wnad_connected(int fd)
{
    return 1;
}
esp_err_t wendy_pki_net_begin(const struct wendy_pki_stream *bio, bool server, const char *expected,
                              bool application, struct wendy_pki_net_setup **out)
{
    struct wendy_pki_net_setup *op = pki_owned_calloc(1, sizeof *op);
    assert(op);
    prepared.input_reserve = 26624;
    prepared.reserve_records_first = true;
    prepared.input_reservation = mbedtls_calloc(1, prepared.input_reserve);
    assert(prepared.input_reservation);
    int result = pki_tls_net_begin(bio, server, "2558fd76-afc7-466e-9613-6b715296a526",
                                   "00000000-0000-4000-8000-000000000004", &prepared,
                                   prepared_roots, application, &op->connection);
    if (result) {
        pki_owned_free(op);
        return ESP_FAIL;
    }
    op->connection->device_expires = time(NULL) + 3600;
    *out = op;
    return ESP_OK;
}
/* This fixture has no mesh issuer inventory; keep ordinary full-chain TLS. */
void wendy_net_peer_issuer_snapshot(struct wendy_pki_net_issuers *snapshot)
{
    memset(snapshot, 0, sizeof *snapshot);
}
void wendy_pki_net_add_issuers(struct wendy_pki_net_setup *op,
                               struct wendy_pki_net_issuers *snapshot)
{
    pki_tls_net_add_issuers(op->connection, snapshot);
}
int wendy_pki_net_step(struct wendy_pki_net_setup *op)
{
    int result = pki_tls_net_advance(op->connection, true, NULL);
    if (!result)
        op->complete = true;
    return result;
}
wendy_pki_connection *wendy_pki_net_take(struct wendy_pki_net_setup *op,
                                         struct wendy_pki_mesh_identity *info)
{
    assert(op->complete);
    wendy_pki_connection *connection = op->connection;
    *info = (struct wendy_pki_mesh_identity){.config_generation = 1};
    pki_owned_free(op);
    return connection;
}
void wendy_pki_net_dispose(struct wendy_pki_net_setup *op)
{
    if (op) {
        wendy_pki_close(op->connection);
        pki_owned_free(op);
    }
}
int wnad_channel_io(struct wna_channel *channel, int fd, const struct wendy_pki_stream *stream)
{
    assert(!stream);
    int progress = 0;
    if (channel->output.size) {
        size_t size = channel->output.size;
        if (size > 17)
            size = 17;
        ssize_t n = send(fd, channel->output.bytes + channel->output.offset, size, MSG_DONTWAIT);
        if (n > 0) {
            wna_buffer_consume(&channel->output, (size_t)n);
            progress = 1;
        } else
            assert(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
    }
    size_t room = wna_buffer_space(&channel->input);
    if (room > 31)
        room = 31;
    if (room && !channel->eof) {
        ssize_t n = recv(fd, channel->input.bytes + channel->input.size, room, MSG_DONTWAIT);
        if (n > 0) {
            channel->input.size += (size_t)n;
            progress = 1;
        } else if (!n) {
            channel->eof = true;
            progress = 1;
        } else
            assert(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
    }
    return progress;
}
int main(int argc, char **argv)
{
    assert(argc == 5);
    assert(wendy_net_runtime_memory_open());
    assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,
                                             wendy_net_memory_scoped_free));
    assert(mbedtls_psa_set_key_slot_table_allocator(wendy_pki_crypto_shared_calloc) == PSA_SUCCESS);
    assert(!wendy_pki_crypto_init()); /* permanent baseline PSA initialization */
    size_t key_size, cert_size, roots_size;
    uint8_t *key = load(argv[1], &key_size), *cert = load(argv[2], &cert_size),
            *roots = load(argv[3], &roots_size);
    size_t der_size = 0;
    assert(!wendy_cert_bundle_measure(roots, roots_size, &der_size));
    uint8_t *der_roots = calloc(1, der_size + 1);
    assert(der_roots);
    assert(!wendy_cert_bundle_import(roots, roots_size, der_roots, der_size, &der_size));
    free(roots);
    roots = der_roots;
    roots_size = der_size;
    struct der_source_test source = {0};
    mbedtls_x509_crt_init(&source.chain);
    assert(!pki_parse_certificate_bundle(&source.chain, cert, cert_size, false));
    free(cert);
    prepared = (struct pki_tls_owned_identity){.key = key,
                                               .key_size = key_size,
                                               .trust = roots,
                                               .trust_capacity = roots_size + 1,
                                               .verify_at = time(NULL),
                                               .read_der = read_der_test,
                                               .hash_der = hash_der_test,
                                               .read_der_range = read_der_range_test,
                                               .der_context = &source};
    prepared_roots = (struct wendy_conf_span){roots, roots_size};
    wendy_pki_work_enable();
    int listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener_fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(listener_fd, (struct sockaddr *)&address, sizeof address));
    socklen_t size = sizeof address;
    assert(!getsockname(listener_fd, (struct sockaddr *)&address, &size));
    assert(!listen(listener_fd, 1));
    printf("%u\n", (unsigned)ntohs(address.sin_port));
    fflush(stdout);
    int fd = accept(listener_fd, NULL, NULL);
    assert(fd >= 0);
    close(listener_fd);
    wendy_net_memory_scope_t previous = wendy_net_runtime_scope_enter();
    wendy_net_app_accept(fd);
    int64_t end = esp_timer_get_time() + 15000000;
    bool completed = false;
    while (esp_timer_get_time() < end) {
        (void)wendy_net_app_poll();
        (void)wendy_pki_work_poll();
        struct app_flow *f = datagram_flows ? &datagram_flows->flow : NULL;
        if (guest_fd >= 0 && f && f->buffers && f->buffers[0].eof && f->channel.eof && !replied) {
            char input[5];
            assert(recv(guest_fd, input, 5, 0) == 5 && !memcmp(input, "hello", 5));
            assert(send(guest_fd, "world", 5, 0) == 5);
            replied = true;
        }
        if (replied && (!f || f->disposing))
            break;
        if (replied && f && f->buffers[1].size == 5 && f->buffers[1].offset == 5 &&
            !f->channel.output.size) {
            completed = true;
            break;
        }
        usleep(100);
    }
    assert(guest_connections == 1 && replied && completed);
    while (!wendy_net_app_stop())
        (void)wendy_pki_work_poll();
    close(guest_fd);
    wendy_net_memory_snapshot_t memory;
    wendy_net_runtime_memory_snapshot(&memory);
    assert(!memory.current_bytes);
    wendy_net_memory_scope_leave(previous);
    wendy_net_runtime_memory_close();
    mbedtls_x509_crt_free(&source.chain);
    fprintf(stderr, "real app TLS clean close_notify+TCP FIN delayed reply PASS\n");
    return 0;
}
