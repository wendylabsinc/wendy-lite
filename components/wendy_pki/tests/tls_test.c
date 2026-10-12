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
        int n = wendy_pki_write(c, "hello" + written, 5 - written);
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

int main(int argc, char **argv) {
    /* Reset revokes existing sessions before the client requests reboot. */
    wendy_pki_connection old = {0};
    resetting = true;
    char byte;
    assert(wendy_pki_read(&old, &byte, 1) == -1);
    assert(wendy_pki_write(&old, "x", 1) == -1);
    resetting = false;
    assert(argc == 5 || argc == 6 || argc == 8); size_t kn, cn, rn;
    unsigned char *key = load(argv[1], &kn), *cert = load(argv[2], &cn), *root = load(argv[3], &rn);
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
    int rc = pki_tls_accept(fd, key, kn, (char *)cert, (struct wendy_conf_span){root, rn},
        "2558fd76-afc7-466e-9613-6b715296a526", &c, esp_timer_get_time() + 3000000);
    free(key); free(cert); free(root);
    if (!strcmp(argv[4], "reject")) { if (c) wendy_pki_close(c); return rc ? 0 : 1; }
    if (rc) return 2;
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
        if (!strcmp(argv[4], "relay-reject")) {
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
    if (!strcmp(argv[4], "truncate") || !strcmp(argv[4], "extra")) {
        if (fd < 0) { wendy_pki_close(c); return 0; } close(fd); return 3;
    }
    if (fd < 0) { wendy_pki_close(c); return 4; }
    // close_notify completed without consuming bytes from the next protocol.
    assert(fcntl(fd, F_SETFL, 0) == 0);
    char raw[3]; int ok = recv(fd, raw, sizeof raw, MSG_WAITALL) == 3 && !memcmp(raw, "raw", 3);
    close(fd); return ok ? 0 : 5;
}
