/* Host adapter for the production TLS implementation. Go drives real TLS peers. */
#include "wendy_pki_internal.h"
#include "wendy_pki_crypto.h"
#include "wendy_cert_bundle.h"
#include "wendy_pki_parsed_identity.h"
#include <mbedtls/platform.h>
#include <psa/crypto_extra.h>
#include "wendy_pki_certificate_policy.h"
#include "esp_timer.h"
#include <mbedtls/net_sockets.h>
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static int64_t clock_advance;
int64_t esp_timer_get_time(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000 + clock_advance;
}
static unsigned char *load(const char *path, size_t *size) {
    FILE *f = fopen(path, "rb"); assert(f); fseek(f, 0, SEEK_END);
    *size = ftell(f); rewind(f); unsigned char *p = calloc(1, *size + 1);
    assert(p && fread(p, 1, *size, f) == *size); fclose(f); return p;
}
/* Fixtures cross the same one-time import boundary as enrolled storage. */
static void import_fixture(unsigned char **bytes,size_t *size)
{
    size_t der_size=0;
    assert(!wendy_cert_bundle_measure(*bytes,*size,&der_size));
    unsigned char *der=malloc(der_size+1);assert(der);
    assert(!wendy_cert_bundle_import(*bytes,*size,der,der_size,&der_size));
    der[der_size]=0;free(*bytes);*bytes=der;*size=der_size;
}
struct fixture_der {
    const uint8_t *part[8];size_t size[8];unsigned count,reads,ranges;
};
static int fixture_read(void *context,unsigned i,uint8_t **bytes,size_t *size)
{
    struct fixture_der *source=context;*bytes=NULL;*size=0;
    if(i>=source->count)return i==source->count ? 0:-1;
    *bytes=mbedtls_calloc(1,source->size[i]);if(!*bytes)return MBEDTLS_ERR_X509_ALLOC_FAILED;
    memcpy(*bytes,source->part[i],source->size[i]);*size=source->size[i];source->reads++;return 1;
}
static int fixture_range(void *context,unsigned i,size_t offset,uint8_t *out,size_t size,const uint8_t expected[32])
{
    struct fixture_der *source=context;uint8_t hash[32];
    if(i>=source->count || offset>source->size[i] || size>source->size[i]-offset ||
       wendy_pki_sha256(source->part[i],source->size[i],hash) || memcmp(hash,expected,32))return -1;
    memcpy(out,source->part[i]+offset,size);source->ranges++;return (int)size;
}
static wendy_net_memory_t owned_memory=WENDY_NET_MEMORY_INITIALIZER;
static void owned_drained(void)
{
    if(!getenv("WENDY_TLS_SCOPED_OWNER"))return;
    wendy_net_memory_snapshot_t state;wendy_net_memory_snapshot(&owned_memory,&state);
    fprintf(stderr,"owned ledger current=%zu allocations=%zu reservations=%zu peak=%zu\n",state.current_bytes,state.allocation_count,state.reservation_count,state.high_water_bytes);
    assert(state.high_water_bytes && !state.current_bytes && !state.allocation_count && !state.reservation_count);
    wendy_net_memory_close(&owned_memory);assert(wendy_net_memory_drained(&owned_memory));
    fprintf(stderr,"owned TLS allocation scope drained; peak=%zu\n",state.high_water_bytes);
}
static bool resetting;
bool wendy_pki_reset_in_progress(void) { return resetting; }

static bool short_writes;
static bool truncate_certificate, certificate_record;
static size_t record_remaining;
static unsigned send_calls, partial_sends, blocked_sends;
/* The production TLS source is compiled with send renamed to this adapter.
 * Alternate short writes with EAGAIN so each handshake flight must resume. */
ssize_t wendy_test_send(int fd, const void *buffer, size_t size, int flags) {
    if (short_writes) {
        if (truncate_certificate && certificate_record && !record_remaining) {
            /* End the transport after one intact encrypted Certificate record,
             * before the remainder of the handshake message can be sent. */
            assert(!shutdown(fd, SHUT_WR));
            errno = ECONNRESET;
            return -1;
        }
        if (!record_remaining) {
            const unsigned char *record = buffer;
            assert(size >= 5 && size == 5 + ((size_t)record[3] << 8) + record[4]);
            record_remaining = size;
            if (truncate_certificate && record[0] == MBEDTLS_SSL_MSG_APPLICATION_DATA)
                certificate_record = true;
        }
        if (++send_calls % 2 == 0) {
            blocked_sends++;
            errno = EAGAIN;
            return -1;
        }
        if (size > 512) {
            size = 512;
            partial_sends++;
        }
    }
    ssize_t n = send(fd, buffer, size, flags);
    if (short_writes && n > 0) {
        assert((size_t)n <= record_remaining);
        record_remaining -= (size_t)n;
    }
    return n;
}
static void wait_io(wendy_pki_connection *c, int result) {
    assert(result == -2 || result == -3);
    struct pollfd fd = {.fd = wendy_pki_fd(c), .events = result == -2 ? POLLIN : POLLOUT};
    assert(poll(&fd, 1, 3000) == 1);
}
static void outbound(unsigned port, const unsigned char *key, size_t kn,
                     const unsigned char *cert, size_t cn, const unsigned char *root, size_t rn,
                     bool truncate) {
    short_writes = true;
    truncate_certificate = truncate;
    wendy_pki_connection *c = NULL;
    int connected = pki_tls_connect("localhost", port, key, kn, (struct wendy_conf_span){cert,cn},
        (struct wendy_conf_span){root, rn}, &c);
    if (truncate) {
        assert(connected && !c && certificate_record && !record_remaining);
        assert(partial_sends && blocked_sends);
        return;
    }
    assert(!connected);
    assert(c && partial_sends && blocked_sends);
    size_t written = 0, received = 0;
    char response[5];
    while (written < 5) {
        int n = wendy_pki_write(c, &"hello"[written], 5 - written);
        if (n > 0) written += (size_t)n;
        else wait_io(c, n);
    }
    while (received < sizeof response) {
        int n = wendy_pki_read(c, response + received, sizeof response - received);
        if (n > 0) received += (size_t)n;
        else wait_io(c, n);
    }
    assert(!memcmp(response, "world", sizeof response));
    wendy_pki_close(c);
}

/* A second Mbed TLS endpoint negotiates 512-byte TLS records so the production
 * server receives a valid Certificate across records, within its fixed bound. */
static void fragmented_client(const char *port, const unsigned char *key_der, size_t kn,
                              const unsigned char *cert_pem, size_t cn,
                              const unsigned char *roots_pem, size_t rn) {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt cert, roots;
    mbedtls_pk_context key;
    mbedtls_net_context net;
    mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&config);
    mbedtls_x509_crt_init(&cert); mbedtls_x509_crt_init(&roots);
    mbedtls_pk_init(&key); mbedtls_net_init(&net);
    assert(!wendy_pki_crypto_init());
    assert(!pki_parse_certificate_bundle(&cert,cert_pem,cn,false));
    assert(!pki_parse_certificate_bundle(&roots,roots_pem,rn,false));
    assert(!mbedtls_pk_parse_key(&key, key_der, kn, NULL, 0));
    assert(!mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&config, &roots, NULL);
    mbedtls_ssl_conf_cert_profile(&config, wendy_pki_certificate_profile());
    mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_tls13_key_exchange_modes(&config,
        MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
    assert(!mbedtls_ssl_conf_max_frag_len(&config, MBEDTLS_SSL_MAX_FRAG_LEN_512));
    assert(!mbedtls_ssl_conf_own_cert(&config, &cert, &key));
    assert(!mbedtls_ssl_setup(&ssl, &config));
    assert(!mbedtls_ssl_set_hostname(&ssl, "localhost"));
    assert(!mbedtls_net_connect(&net, "127.0.0.1", port, MBEDTLS_NET_PROTO_TCP));
    struct timeval timeout = {.tv_sec = 3};
    assert(!setsockopt(net.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout));
    assert(!setsockopt(net.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout));
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);
    assert(!mbedtls_ssl_handshake(&ssl));
    assert(!mbedtls_ssl_get_verify_result(&ssl));
    assert(mbedtls_ssl_get_max_out_record_payload(&ssl) <= 512);
    assert(cert.raw.len > 512);
    assert(mbedtls_ssl_write(&ssl, (const unsigned char *)"hello", 5) == 5);
    unsigned char response[5];
    size_t received = 0;
    while (received < sizeof response) {
        int n = mbedtls_ssl_read(&ssl, response + received, sizeof response - received);
        assert(n > 0); received += (size_t)n;
    }
    assert(!memcmp(response, "world", sizeof response));
    mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&config);
    mbedtls_x509_crt_free(&cert); mbedtls_x509_crt_free(&roots);
    mbedtls_pk_free(&key); mbedtls_net_free(&net);
}

/* BLE supplies a byte stream rather than a socket. Keep the backing socket
 * outside the TLS connection and force fragmented reads, writes and retries. */
struct test_stream {
    int fd;
    unsigned reads, writes, partial_reads, partial_writes;
    unsigned blocked_reads, blocked_writes, read_waits, write_waits;
    unsigned opposite_reads, opposite_writes, injected_wait;
    bool fail_wait;
};
static ssize_t stream_read(void *context, void *buffer, size_t size) {
    struct test_stream *s = context;
    if (++s->reads == 1) {
        s->opposite_reads++;
        s->injected_wait = 2;
        return -3;
    }
    if (s->reads % 3 == 1) {
        s->blocked_reads++;
        return -2;
    }
    if (size > 73) { size = 73; s->partial_reads++; }
    ssize_t n = recv(s->fd, buffer, size, 0);
    return n < 0 && (errno == EAGAIN || errno == EINTR) ? -2 : n;
}
static ssize_t stream_write(void *context, const void *buffer, size_t size) {
    struct test_stream *s = context;
    if (++s->writes == 1) {
        s->opposite_writes++;
        s->injected_wait = 1;
        return -2;
    }
    if (s->writes % 3 == 1) {
        s->blocked_writes++;
        return -3;
    }
    if (size > 61) { size = 61; s->partial_writes++; }
    ssize_t n = send(s->fd, buffer, size, 0);
    return n < 0 && (errno == EAGAIN || errno == EINTR) ? -3 : n;
}
static int stream_wait(void *context, bool writing, int64_t deadline) {
    struct test_stream *s = context;
    if (writing) s->write_waits++; else s->read_waits++;
    if (s->fail_wait) return -1;
    if (s->injected_wait) {
        assert(writing == (s->injected_wait == 2));
        s->injected_wait = 0;
        return 0;
    }
    int64_t remaining = deadline - esp_timer_get_time();
    if (remaining <= 0) return -1;
    struct pollfd fd = {.fd = s->fd, .events = writing ? POLLOUT : POLLIN};
    return poll(&fd, 1, (int)((remaining + 999) / 1000)) == 1 ? 0 : -1;
}
static void stream_exchange(wendy_pki_connection *c, struct test_stream *s) {
    assert(wendy_pki_fd(c) == -1);
    /* A stream cannot be handed off as a TCP fd, and failure must retain it. */
    assert(wendy_pki_detach(c) == -1);
    char hello[5];
    size_t received = 0, written = 0;
    while (received < sizeof hello) {
        size_t size = received ? sizeof hello - received : 1;
        ssize_t n = wendy_pki_read(c, hello + received, size);
        if (n > 0) {
            received += (size_t)n;
            /* One-byte application reads must leave decrypted data visible
             * even when no additional transport packet arrives. */
            if (received == 1) assert(wendy_pki_pending(c));
        } else {
            assert(n == -2 || n == -3);
            assert(!stream_wait(s, n == -3, esp_timer_get_time() + 3000000));
        }
    }
    assert(!memcmp(hello, "hello", sizeof hello));
    assert(!wendy_pki_pending(c));
    while (written < 5) {
        ssize_t n = wendy_pki_write(c, &"world"[written], 5 - written);
        if (n > 0) written += (size_t)n;
        else {
            assert(n == -2 || n == -3);
            assert(!stream_wait(s, n == -3, esp_timer_get_time() + 3000000));
        }
    }
    assert(s->partial_reads && s->partial_writes &&
           s->blocked_reads && s->blocked_writes && s->read_waits && s->write_waits);
    assert(s->opposite_reads && s->opposite_writes && !s->injected_wait);
    resetting = true;
    assert(wendy_pki_read(c, hello, 1) == -1);
    assert(wendy_pki_write(c, "x", 1) == -1);
    resetting = false;
    wendy_pki_close(c);
    /* The BLE/L2CAP owner still owns its stream after TLS teardown. */
    assert(fcntl(s->fd, F_GETFD) >= 0);
    close(s->fd);
}

int main(int argc, char **argv) {
    /* Rejected peers can close before TLS sends its alert. Match lwIP's
     * error-return behavior instead of terminating the host adapter. */
    assert(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    /* Reset revokes existing sessions before the client requests reboot. */
    wendy_pki_connection old = {0};
    resetting = true;
    char byte;
    assert(wendy_pki_read(&old, &byte, 1) == -1);
    assert(wendy_pki_write(&old, "x", 1) == -1);
    resetting = false;
    assert(argc == 5 || argc == 6 || argc == 7 || argc == 8); size_t kn, cn, rn;
    unsigned char *key = load(argv[1], &kn), *cert = load(argv[2], &cn), *root = load(argv[3], &rn);
    import_fixture(&cert,&cn);import_fixture(&root,&rn);
    if (argc == 7) {
        assert(!strncmp(argv[4], "http-", 5));
        bool renew = !strcmp(argv[4], "http-renew");
        /* http-body-N expects an N-byte body of 'A's instead of "{}". */
        size_t expected_body = !strncmp(argv[4], "http-body-", 10) ? strtoul(argv[4] + 10, NULL, 10) : 0;
        uint8_t *body = NULL;
        size_t body_size = 0;
        char *authority = NULL;
        int result = pki_http_post_enrollment(argv[5], "application/json", renew ? NULL : "test-token",
            "{}", 2, renew ? key : NULL, renew ? kn : 0, (struct wendy_conf_span){renew ? cert:NULL,renew ? cn:0},
            (struct wendy_conf_span){root, rn}, &body, &body_size, &authority);
        if (!strcmp(argv[4], "http-reject")) {
            assert(result && !body && !authority);
        } else {
            if (expected_body) {
                assert(!result && body_size == expected_body && !body[body_size]);
                for (size_t i = 0; i < body_size; i++) assert(body[i] == 'A');
            } else
                assert(!result && body_size == 2 && !memcmp(body, "{}", 2));
            if (!strcmp(argv[6], "-")) assert(!authority);
            else {
                size_t expected_size;
                unsigned char *expected = load(argv[6], &expected_size);
                assert(authority && strlen(authority) == expected_size &&
                       !memcmp(authority, expected, expected_size));
                free(expected);
            }
        }
        free(authority); free(body); free(key); free(cert); free(root);
        return 0;
    }
    if (argc == 6) {
        if (!strcmp(argv[4], "fragment-client")) {
            fragmented_client(argv[5], key, kn, cert, cn, root, rn);
            free(key); free(cert); free(root);
            return 0;
        }
        bool truncate = !strcmp(argv[4], "connect-truncated");
        assert(truncate || !strcmp(argv[4], "connect"));
        outbound((unsigned)strtoul(argv[5], NULL, 10), key, kn, cert, cn, root, rn, truncate);
        free(key); free(cert); free(root);
        return 0;
    }
    int listener = socket(AF_INET, SOCK_STREAM, 0); assert(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(listener, (struct sockaddr *)&address, sizeof address));
    socklen_t size = sizeof address; assert(!getsockname(listener, (struct sockaddr *)&address, &size));
    assert(!listen(listener, 1)); printf("%d\n", ntohs(address.sin_port)); fflush(stdout);
    int fd = accept(listener, NULL, NULL); close(listener); assert(fd >= 0);
    wendy_pki_connection *c = NULL;
    const char *mode = argv[4];
    bool stream_mode = !strncmp(mode, "stream-", 7);
    if (stream_mode) mode += 7;
    bool lite = !strncmp(mode, "lite-", 5);
    if (lite) mode += 5;
    bool lan = !strncmp(mode, "lan-", 4);
    if (lan) mode += 4;
    struct test_stream transport = {.fd = fd, .fail_wait = !strcmp(mode, "timeout")};
    const struct wendy_pki_stream stream = {
        .context = &transport, .read = stream_read, .write = stream_write, .wait = stream_wait,
    };
    int rc;
    struct fixture_der source={0};
    if (stream_mode && getenv("WENDY_TLS_OWNED_STREAM")) {
        assert(!fcntl(fd,F_SETFL,O_NONBLOCK));
        size_t offset=0;const uint8_t *part;size_t bytes;
        while(wendy_cert_der_next(cert,cn,&offset,&part,&bytes)==1){
            assert(source.count<8);source.part[source.count]=part;source.size[source.count++]=bytes;
        }
        assert(offset==cn && source.count>1);
        struct pki_tls_owned_identity owned={.key=key,.key_size=kn,
            .read_der=fixture_read,.read_der_range=fixture_range,.der_context=&source,
            .verify_at=time(NULL)};
        wendy_net_memory_scope_t previous={0};
        if(getenv("WENDY_TLS_SCOPED_OWNER")){
            assert(wendy_net_memory_open(&owned_memory,2*1024*1024,false));
            assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,wendy_net_memory_scoped_free));
            assert(mbedtls_psa_set_key_slot_table_allocator(wendy_pki_crypto_shared_calloc)==PSA_SUCCESS);
            assert(!wendy_pki_crypto_init()); /* Firmware initializes PSA before task scopes. */
            previous=wendy_net_memory_scope_enter(&owned_memory,WENDY_NET_MEMORY_INTERNAL);
        }
        rc=pki_tls_accept_owned_stream(&stream,&owned,(struct wendy_conf_span){root,rn},
            "2558fd76-afc7-466e-9613-6b715296a526","00000000-0000-4000-8000-000000000004",
            &c,esp_timer_get_time()+10000000);
        if(getenv("WENDY_TLS_SCOPED_OWNER"))wendy_net_memory_scope_leave(previous);
        key=NULL;assert(!owned.key && !owned.certificate && !owned.input_reservation);
        if(!rc)assert(source.reads>=source.count && source.ranges && !c->certificate.raw.len && !c->roots.raw.len);
    } else if (stream_mode) {
        assert(!fcntl(fd, F_SETFL, O_NONBLOCK));
        rc = pki_tls_accept_stream(&stream, key, kn, (struct wendy_conf_span){cert,cn},
            (struct wendy_conf_span){root, rn}, "2558fd76-afc7-466e-9613-6b715296a526",
            &c, esp_timer_get_time() + 3000000);
    } else {
        rc = (lite ? pki_tls_accept_lite : lan ? pki_tls_accept_lan : pki_tls_accept)(fd, key, kn, (struct wendy_conf_span){cert,cn}, (struct wendy_conf_span){root, rn},
            "2558fd76-afc7-466e-9613-6b715296a526", &c, esp_timer_get_time() + 3000000);
    }
    free(key); free(cert); free(root);
    if (!strcmp(mode, "reject") || !strcmp(mode, "timeout")) {
        if (c) wendy_pki_close(c);
        if (stream_mode) {
            assert(fcntl(fd, F_GETFD) >= 0);
            if (transport.fail_wait) assert(transport.read_waits + transport.write_waits > 0);
            close(fd);
        }
        return rc ? 0 : 1;
    }
    if (rc) return 2;
    assert(wendy_pki_get_peer_role(c) == (!strcmp(mode, "valid-device") ? WENDY_PEER_ROLE_DEVICE : WENDY_PEER_ROLE_OPERATOR));
    if (stream_mode) { stream_exchange(c, &transport); owned_drained(); return 0; }
    if (!strcmp(mode, "valid-device"))
        assert(pki_relay_grant(c, NULL, esp_timer_get_time() + 3000000) == -1);
    if (argc == 8) {
        size_t tn;
        unsigned char *raw = load(argv[5], &tn);
        assert(tn == 145);
        struct wendy_lite_trust trust = {.count = 1};
        trust.keys[0].id_size = 4;
        memcpy(trust.keys[0].id, "test", 4);
        memcpy(trust.keys[0].public_key, raw, 65);
        memcpy(trust.session, raw + 65, 16);
        memcpy(trust.grant_hash, raw + 81, 32);
        memcpy(c->device_hash, raw + 113, 32);
        c->device_expires = (time_t)strtoll(argv[6], NULL, 10);
        free(raw);
        rc = pki_relay_grant(c, &trust, esp_timer_get_time() + 3000000);
        if (!strcmp(mode, "relay-reject")) {
            wendy_pki_close(c);
            return rc ? 0 : 6;
        }
        if (rc) { wendy_pki_close(c); return 7; }
        int64_t expected = strtoll(argv[7], NULL, 10);
        int64_t remaining = (c->relay_expires_us - esp_timer_get_time()) / 1000000;
        assert(llabs(remaining - (expected - time(NULL))) <= 1);
        // The session uses a monotonic cutoff even after the clock is corrected.
        clock_advance = c->relay_expires_us - esp_timer_get_time() + 1;
        assert(wendy_pki_read(c, &byte, 1) == -1);
        assert(wendy_pki_write(c, "x", 1) == -1);
        wendy_pki_close(c);
        return 0;
    }
    fd = wendy_pki_detach(c);
    if (!strcmp(mode, "truncate") || !strcmp(mode, "extra")) {
        if (fd < 0) { wendy_pki_close(c); return 0; } close(fd); return 3;
    }
    if (fd < 0) { wendy_pki_close(c); return 4; }
    // close_notify completed without consuming bytes from the next protocol.
    assert(fcntl(fd, F_SETFL, 0) == 0);
    char raw[3]; int ok = recv(fd, raw, sizeof raw, MSG_WAITALL) == 3 && !memcmp(raw, "raw", 3);
    close(fd); return ok ? 0 : 5;
}
