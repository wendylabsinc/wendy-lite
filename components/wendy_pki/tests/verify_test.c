#include "wendy_pki_verify.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
/* Override only this test executable's wall clock, including wolfSSL calls. */
static time_t wall_clock;
time_t time(time_t *out)
{
    if (out)
        *out = wall_clock;
    return wall_clock;
}
static unsigned char *load(const char *dir, const char *name, size_t *n)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    assert(f);
    fseek(f, 0, SEEK_END);
    *n = ftell(f);
    rewind(f);
    unsigned char *p = malloc(*n);
    assert(p && fread(p, 1, *n, f) == *n);
    fclose(f);
    return p;
}
int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--request"))
    {
        uint8_t nonce[32], request[128];
        for (int i = 0; i < 32; i++)
            nonce[i] = i + 1;
        assert(wolfSSL_Init() == WOLFSSL_SUCCESS);
        size_t size = wendy_pki_time_request(request, nonce);
        FILE *f = fopen(argv[2], "wb");
        assert(f && fwrite(request, 1, size, f) == size);
        fclose(f);
        wolfSSL_Cleanup();
        return 0;
    }
    assert(argc == 2 || argc == 3);
    wall_clock = argc == 3 ? (time_t)strtoll(argv[2], NULL, 10) : 0;
    int init = wolfSSL_Init();
    printf("init=%d success=%d\n", init, WOLFSSL_SUCCESS);
    fflush(stdout);
    assert(init == WOLFSSL_SUCCESS);
    size_t root_n, nonce_n, n;
    unsigned char *root = load(argv[1], "root.pem", &root_n),
                  *nonce = load(argv[1], "nonce.bin", &nonce_n);
    assert(nonce_n == 32);
    const char *names[] = {"valid",         "wrong-eku",   "expired",
                           "wrong-imprint", "wrong-nonce", "valid-ecdsa"};
    time_t t = 0;
    for (int i = 0; i < 6; i++)
    {
        char name[64];
        snprintf(name, sizeof name, "%s.der", names[i]);
        unsigned char *p = load(argv[1], name, &n);
        int r = wendy_pki_verify_time(p, n, nonce, root, root_n, 0, &t);
        printf("%s: %d\n", names[i], r);
        fflush(stdout);
        assert(i == 0 || i == 5 ? r == 0 : r != 0);
        if (i == 0)
        {
            assert(t > 1700000000);
            time_t old = t;
            assert(wendy_pki_verify_time(p, n, nonce, root, root_n, t + 1, &t) != 0 && t == old);
            p[n - 1] ^= 1;
            assert(wendy_pki_verify_time(p, n, nonce, root, root_n, 0, &t) != 0);
            p[n - 1] ^= 1;
            for (size_t j = 0; j < n; j += 137)
                assert(wendy_pki_verify_time(p, j, nonce, root, root_n, 0, &t) != 0);
            assert(wendy_pki_verify_time(p, n, nonce, (const unsigned char *)"bad", 3, 0, &t) != 0);
        }
        free(p);
    }
    const char *principal =
        "spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/lite-test";
    size_t key_n;
    unsigned char *key = load(argv[1], "device-key.der", &key_n);
    const char *identities[] = {"identity", "identity-expired", "identity-wrong-eku",
                                "identity-wrong-uri", "identity-duplicate-uri"};
    for (int i = 0; i < 5; i++)
    {
        char name[64];
        snprintf(name, sizeof name, "%s.pem", identities[i]);
        unsigned char *p = load(argv[1], name, &n);
        time_t expires = 0;
        int r = wendy_pki_verify_identity(p, n, root, root_n, key, key_n, principal, t, &expires);
        printf("%s: %d\n", name, r);
        fflush(stdout);
        assert(i == 0 ? r == 0 : r != 0);
        if (i == 0)
        {
            size_t wrong_n;
            unsigned char *wrong = load(argv[1], "wrong-key.der", &wrong_n);
            assert(wendy_pki_verify_identity(p, n, root, root_n, wrong, wrong_n, principal, t,
                                             &expires) != 0);
            free(wrong);
            assert(wendy_pki_verify_identity(p, n, (const unsigned char *)"bad", 3, key, key_n,
                                             principal, t, &expires) != 0);
        }
        free(p);
    }
    free(key);
    free(root);
    free(nonce);
    wolfSSL_Cleanup();
    puts("signed-time verification tests passed");
}
