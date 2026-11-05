/* Production outbound TLS with a test clock. CMake builds this target with its
 * own X.509 objects, without mbedTLS date checks, to match the firmware.
 * Usage: broker_dates_test dated|undated|http roots.pem port clock accept|reject */
#include "wendy_pki_internal.h"
#include "wendy_cert_bundle.h"
#include "esp_timer.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static time_t test_clock;
static time_t test_time(time_t *out)
{
    if (out) *out = test_clock;
    return test_clock;
}
#define time test_time
#include "../src/wendy_pki_tls.c"
#undef time

int64_t esp_timer_get_time(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
bool wendy_pki_reset_in_progress(void) { return false; }

static struct wendy_conf_span load_roots(const char *path)
{
    FILE *f = fopen(path, "rb");
    assert(f);
    fseek(f, 0, SEEK_END);
    size_t pem_size = (size_t)ftell(f), der_size = 0;
    rewind(f);
    unsigned char *pem = calloc(1, pem_size + 1);
    assert(pem && fread(pem, 1, pem_size, f) == pem_size);
    fclose(f);
    assert(!wendy_cert_bundle_measure(pem, pem_size, &der_size));
    unsigned char *der = calloc(1, der_size + 1);
    assert(der && !wendy_cert_bundle_import(pem, pem_size, der, der_size, &der_size));
    free(pem);
    return (struct wendy_conf_span){der, der_size};
}

int main(int argc, char **argv)
{
    assert(argc == 6);
    const char *mode = argv[1];
    struct wendy_conf_span roots = load_roots(argv[2]);
    unsigned port = (unsigned)strtoul(argv[3], NULL, 10);
    test_clock = (time_t)strtoll(argv[4], NULL, 10);
    bool expect_accept = !strcmp(argv[5], "accept");
    const struct wendy_conf_span no_cert = {0};
    wendy_pki_connection *c = NULL;
    int result;
    if (!strcmp(mode, "dated")) {
        result = pki_tls_connect_dated("localhost", port, NULL, 0, no_cert, roots, &c);
    } else if (!strcmp(mode, "undated")) {
        result = pki_tls_connect("localhost", port, NULL, 0, no_cert, roots, &c);
    } else {
        /* The time fetch: same call as refresh_time_source() in wendy_pki.c. */
        assert(!strcmp(mode, "http"));
        char url[64];
        snprintf(url, sizeof url, "https://localhost:%u/", port);
        uint8_t *response = NULL;
        size_t response_size = 0;
        result = pki_http_post(url, "application/timestamp-query", NULL, "q", 1, NULL, 0, no_cert,
                               roots, &response, &response_size);
        assert(result || (response_size == 2 && !memcmp(response, "ok", 2)));
        free(response);
    }
    assert(result ? !c : (strcmp(mode, "http") ? c != NULL : !c));
    if (c) wendy_pki_close(c);
    free((void *)roots.data);
    if ((result == 0) != expect_accept) {
        fprintf(stderr, "%s at clock %s: expected %s, connect returned %d\n", mode, argv[4], argv[5],
                result);
        return 1;
    }
    return 0;
}
