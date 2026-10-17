/* Host adapter for the production TLS implementation. Go drives real TLS peers. */
#include "wendy_pki_internal.h"
#include "esp_timer.h"
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
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
static bool resetting;
bool wendy_pki_reset_in_progress(void) { return resetting; }

static bool short_writes;
static unsigned send_calls, partial_sends, blocked_sends;
/* The production TLS source is compiled with send renamed to this adapter.
 * Alternate short writes with EAGAIN so each handshake flight must resume. */
ssize_t wendy_test_send(int fd, const void *buffer, size_t size, int flags) {
    if (short_writes) {
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
    return send(fd, buffer, size, flags);
}
static void wait_io(wendy_pki_connection *c, int result) {
    assert(result == -2 || result == -3);
    struct pollfd fd = {.fd = wendy_pki_fd(c), .events = result == -2 ? POLLIN : POLLOUT};
    assert(poll(&fd, 1, 3000) == 1);
}
static void outbound(unsigned port, const unsigned char *key, size_t kn,
                     const unsigned char *cert, const unsigned char *root, size_t rn) {
    short_writes = true;
    wendy_pki_connection *c = NULL;
    assert(pki_tls_connect("localhost", port, key, kn, (const char *)cert,
        (struct wendy_conf_span){root, rn}, &c) == 0);
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
    /* Reset revokes existing sessions before the client requests reboot. */
    wendy_pki_connection old = {0};
    resetting = true;
    char byte;
    assert(wendy_pki_read(&old, &byte, 1) == -1);
    assert(wendy_pki_write(&old, "x", 1) == -1);
    resetting = false;
    assert(argc == 5 || argc == 6 || argc == 7 || argc == 8); size_t kn, cn, rn;
    unsigned char *key = load(argv[1], &kn), *cert = load(argv[2], &cn), *root = load(argv[3], &rn);
    if (argc == 7) {
        assert(!strncmp(argv[4], "http-", 5));
        bool renew = !strcmp(argv[4], "http-renew");
        uint8_t *body = NULL;
        size_t body_size = 0;
        char *authority = NULL;
        int result = pki_http_post_enrollment(argv[5], "application/json", renew ? NULL : "test-token",
            "{}", 2, renew ? key : NULL, renew ? kn : 0, renew ? (char *)cert : NULL,
            (struct wendy_conf_span){root, rn}, &body, &body_size, &authority);
        if (!strcmp(argv[4], "http-reject")) {
            assert(result && !body && !authority);
        } else {
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
        assert(!strcmp(argv[4], "connect"));
        outbound((unsigned)strtoul(argv[5], NULL, 10), key, kn, cert, root, rn);
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
    if (stream_mode) {
        assert(!fcntl(fd, F_SETFL, O_NONBLOCK));
        rc = pki_tls_accept_stream(&stream, key, kn, (char *)cert,
            (struct wendy_conf_span){root, rn}, "2558fd76-afc7-466e-9613-6b715296a526",
            &c, esp_timer_get_time() + 3000000);
    } else {
        rc = (lite ? pki_tls_accept_lite : lan ? pki_tls_accept_lan : pki_tls_accept)(fd, key, kn, (char *)cert, (struct wendy_conf_span){root, rn},
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
    if (stream_mode) { stream_exchange(c, &transport); return 0; }
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
