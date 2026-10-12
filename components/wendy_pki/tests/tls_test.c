/* Host adapter for the production TLS implementation. Go drives real TLS peers. */
#include "wendy_pki_internal.h"
#include "esp_timer.h"
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
int64_t esp_timer_get_time(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
static unsigned char *load(const char *path, size_t *size) {
    FILE *f = fopen(path, "rb"); assert(f); fseek(f, 0, SEEK_END);
    *size = ftell(f); rewind(f); unsigned char *p = calloc(1, *size + 1);
    assert(p && fread(p, 1, *size, f) == *size); fclose(f); return p;
}
static bool resetting;
bool wendy_pki_reset_in_progress(void) { return resetting; }

int main(int argc, char **argv) {
    /* Reset revokes existing sessions before the client requests reboot. */
    wendy_pki_connection old = {0};
    resetting = true;
    char byte;
    assert(wendy_pki_read(&old, &byte, 1) == -1);
    assert(wendy_pki_write(&old, "x", 1) == -1);
    resetting = false;
    assert(argc == 5); size_t kn, cn, rn;
    unsigned char *key = load(argv[1], &kn), *cert = load(argv[2], &cn), *root = load(argv[3], &rn);
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
