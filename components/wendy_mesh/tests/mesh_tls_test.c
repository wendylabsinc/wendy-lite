/* Production mbedTLS client exercised by independent Go TLS peers. */
#include "esp_timer.h"
#include "wendy_pki_internal.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

bool wendy_pki_reset_in_progress(void)
{
    return false;
}
int64_t esp_timer_get_time(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
ssize_t wendy_test_send(int fd, const void* buffer, size_t size, int flags)
{
    return send(fd, buffer, size, flags);
}
static void* load(const char* path, size_t* size)
{
    FILE* f = fopen(path, "rb");
    assert(f);
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    assert(n > 0 && n <= 65536);
    rewind(f);
    uint8_t* out = calloc(1, n + 1);
    assert(out && fread(out, 1, n, f) == (size_t)n);
    fclose(f);
    *size = n;
    return out;
}
static ssize_t stream_read(void* ctx, void* p, size_t n)
{
    if (n > 17)
        n = 17;
    ssize_t got = recv(*(int*)ctx, p, n, 0);
    return got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? -2 : got;
}
static ssize_t stream_write(void* ctx, const void* p, size_t n)
{
    if (n > 23)
        n = 23;
    ssize_t got = send(*(int*)ctx, p, n, 0);
    return got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? -3 : got;
}
static int stream_wait(void* ctx, bool writing, int64_t deadline)
{
    int fd = *(int*)ctx;
    int64_t left = deadline - esp_timer_get_time();
    if (left <= 0)
        return -1;
    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    struct timeval tv = { left / 1000000, left % 1000000 };
    return select(fd + 1, writing ? NULL : &set, writing ? &set : NULL, NULL, &tv) < 0 ? -1 : 0;
}
int main(int argc, char** argv)
{
    assert(argc == 9);
    /* Rejected peers may close while TLS writes its alert. */
    assert(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    size_t kn, cn, rn;
    uint8_t *key = load(argv[1], &kn), *cert = load(argv[2], &cn), *roots = load(argv[3], &rn);
    wendy_pki_connection* connection = NULL;
    /* Optional peer discovery must never relax TCP or gateway pinning. */
    assert(pki_tls_mesh_connect("127.0.0.1", 43024, argv[5], argv[6], NULL,
        key, kn, (char*)cert, (struct wendy_conf_span) { roots, rn }, &connection) != 0);
    assert(!connection);
    assert(pki_tls_gateway_connect("127.0.0.1", 43024, argv[5], argv[6], NULL,
        key, kn, (char*)cert, (struct wendy_conf_span) { roots, rn }, &connection) != 0);
    assert(!connection);
    int result, fd = -1;
    const char* mode = getenv("MESH_STREAM_MODE");
    if (mode && !strcmp(mode, "gateway")) {
        result = pki_tls_gateway_connect("127.0.0.1", (unsigned)strtoul(argv[4], NULL, 10),
            argv[5], argv[6], argv[7], key, kn, (char*)cert,
            (struct wendy_conf_span) { roots, rn }, &connection);
    } else if (mode && strcmp(mode, "tcp")) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address = { .sin_family = AF_INET,
            .sin_port = htons((unsigned)strtoul(argv[4], NULL, 10)),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
        assert(fd >= 0 && connect(fd, (struct sockaddr*)&address, sizeof address) == 0);
        assert(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
        struct wendy_pki_stream stream = { .context = &fd, .read = stream_read, .write = stream_write, .wait = stream_wait };
        result = pki_tls_mesh_stream(&stream, !strcmp(mode, "server"), argv[5], argv[6],
            !strcmp(mode, "same-tenant") ? NULL : argv[7],
            key, kn, (char*)cert, (struct wendy_conf_span) { roots, rn }, &connection);
    } else
        result = pki_tls_mesh_connect("127.0.0.1", (unsigned)strtoul(argv[4], NULL, 10),
            argv[5], argv[6], argv[7], key, kn, (char*)cert,
            (struct wendy_conf_span) { roots, rn }, &connection);
    bool expected = strcmp(argv[8], "accept") == 0;
    if ((result == 0) != expected) {
        fprintf(stderr, "unexpected TLS result %d\n", result);
        return 1;
    }
    if (connection) {
        assert(!strcmp(connection->mesh_peer, argv[7]));
        const char* expected_expiry = getenv("EXPECTED_MESH_EXPIRY");
        assert(expected_expiry
            && connection->operator_expires == (time_t)strtoll(expected_expiry, NULL, 10));
        wendy_pki_close(connection);
    }
    if (fd >= 0)
        close(fd);
    memset(key, 0, kn);
    free(key);
    free(cert);
    free(roots);
    return 0;
}
