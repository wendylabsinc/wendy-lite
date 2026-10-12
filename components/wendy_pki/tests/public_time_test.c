#include "wendy_pki_verify.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Certificate validation must use authenticated time, never the boot clock. */
static time_t wall_clock;
time_t time(time_t *out)
{
    if (out) *out = wall_clock;
    return wall_clock;
}
static uint8_t *load(const char *dir, const char *name, size_t *size)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    assert(f);
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    rewind(f);
    uint8_t *data = malloc(*size);
    assert(data && fread(data, 1, *size, f) == *size);
    fclose(f);
    return data;
}
int main(int argc, char **argv)
{
    assert(argc == 2 || argc == 3);
    wall_clock = argc == 3 ? (time_t)strtoll(argv[2], NULL, 10) : 0;
    uint8_t nonce[32];
    for (size_t i = 0; i < sizeof nonce; i++) nonce[i] = i + 1;
    struct {
        const char *name, *root;
        int valid;
    } cases[] = {
        {"sigstore.der", "sigstore-root.pem", 1},
        {"issuer-present.der", "test-root.pem", 1},
        {"issuer-absent.der", "test-root.pem", 1},
        {"wrong-issuer.der", "test-root.pem", 0},
        {"wrong-serial.der", "test-root.pem", 0},
        {"extra-issuer.der", "test-root.pem", 0},
        {"unsupported-curve.der", "test-root.pem", 0},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        size_t size, root_size;
        uint8_t *data = load(argv[1], cases[i].name, &size);
        uint8_t *root = load(argv[1], cases[i].root, &root_size);
        time_t verified = 123;
        int result = wendy_pki_verify_time(data, size, nonce, root, root_size, 0, &verified);
        printf("%s: %d\n", cases[i].name, result);
        fflush(stdout);
        assert(cases[i].valid ? result == 0 : result != 0);
        if (cases[i].valid) {
            assert(verified > 1700000000);
            time_t saved = verified;
            nonce[0] ^= 1;
            assert(wendy_pki_verify_time(data, size, nonce, root, root_size, 0, &verified) != 0);
            nonce[0] ^= 1;
            assert(wendy_pki_verify_time(data, size, nonce, root, root_size, saved + 1, &verified) != 0);
            size_t other_size;
            uint8_t *other = load(argv[1], i == 0 ? "test-root.pem" : "sigstore-root.pem", &other_size);
            assert(wendy_pki_verify_time(data, size, nonce, other, other_size, 0, &verified) != 0);
            free(other);
            data[size - 1] ^= 1;
            assert(wendy_pki_verify_time(data, size, nonce, root, root_size, 0, &verified) != 0);
            assert(verified == saved);
        } else {
            assert(verified == 123);
        }
        free(root);
        free(data);
    }
    puts("public timestamp verification tests passed");
    return 0;
}
