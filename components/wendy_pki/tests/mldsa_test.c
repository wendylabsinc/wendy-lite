#include "wendy_pki_verify.h"
#include "wendy_lite_grant.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static time_t wall_clock;
time_t time(time_t *out)
{
    if (out) *out = wall_clock;
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
    assert(argc == 2 || argc == 3);
    wall_clock = argc == 3 ? (time_t)strtoll(argv[2], NULL, 10) : 0;
    const time_t signed_time = 1791792000; /* 2026-10-12 08:00:00 UTC. */
    const char *principal = "spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/lite-test";
    size_t nonce_n, key_n, wrong_key_n, n;
    unsigned char *nonce = load(argv[1], "nonce.bin", &nonce_n);
    unsigned char *key = load(argv[1], "device-key.der", &key_n);
    unsigned char *wrong_key = load(argv[1], "wrong-key.der", &wrong_key_n);
    assert(nonce_n == 32);
    unsigned char *ed = load(argv[1], "ed25519-root.pem", &n);
    assert(wendy_pki_verify_roots(ed, n) != 0);
    free(ed);
    const char *levels[] = {"44", "65", "87"};
    for (int level = 0; level < 3; level++) {
        char name[128];
        size_t root_n;
        snprintf(name, sizeof name, "%s-root.pem", levels[level]);
        unsigned char *root = load(argv[1], name, &root_n);
        assert(wendy_pki_verify_roots(root, root_n) == 0);
        snprintf(name, sizeof name, "%s-identity-valid.der", levels[level]);
        unsigned char *peer = load(argv[1], name, &n);
        uint8_t peer_hash[32];
        assert(wendy_lite_peer_hash(peer, n, peer_hash) == 0);
        size_t expected_n;
        unsigned char *expected = load(argv[1], "peer-hash.bin", &expected_n);
        assert(expected_n == 32 && !memcmp(peer_hash, expected, 32));
        assert(wendy_lite_peer_hash(peer, n-1, peer_hash) != 0);
        free(peer); free(expected);
        snprintf(name, sizeof name, "%s-identity-duplicate-uri.der", levels[level]);
        peer = load(argv[1], name, &n);
        assert(wendy_lite_peer_hash(peer, n, peer_hash) != 0);
        free(peer);
        const char *times[] = {"valid", "expired-intermediate", "future-intermediate", "nonca-intermediate", "no-keysign", "pathlen-zero", "expired", "wrong-eku", "noncritical-eku"};
        for (size_t i = 0; i < sizeof times / sizeof *times; i++) {
            snprintf(name, sizeof name, "%s-time-%s.der", levels[level], times[i]);
            unsigned char *response = load(argv[1], name, &n);
            time_t verified = 123;
            int result = wendy_pki_verify_time(response, n, nonce, root, root_n, 0, &verified);
            printf("ML-DSA %s timestamp %s: %d\n", levels[level], times[i], result);
            fflush(stdout);
            assert(i == 0 ? result == 0 && verified == signed_time : result != 0 && verified == 123);
            if (i == 0) {
                assert(wendy_pki_verify_time(response, n, nonce, root, root_n, signed_time + 1, &verified) != 0);
                assert(verified == signed_time);
                uint8_t wrong_nonce[32];
                memcpy(wrong_nonce, nonce, 32); wrong_nonce[0] ^= 1;
                assert(wendy_pki_verify_time(response, n, wrong_nonce, root, root_n, 0, &verified) != 0);
                response[n-1] ^= 1;
                assert(wendy_pki_verify_time(response, n, nonce, root, root_n, 0, &verified) != 0);
                response[n-1] ^= 1;
                assert(wendy_pki_verify_time(response, n-1, nonce, root, root_n, 0, &verified) != 0);
                for (int expired = 0; expired < 2; expired++) {
                    size_t invalid_n;
                    snprintf(name, sizeof name, "%s-%s-root.pem", levels[level], expired ? "expired" : "future");
                    unsigned char *invalid = load(argv[1], name, &invalid_n);
                    assert(wendy_pki_verify_time(response, n, nonce, invalid, invalid_n, 0, &verified) != 0);
                    free(invalid);
                }
            }
            free(response);
        }
        const char *identities[] = {"valid", "expired-intermediate", "future-intermediate", "nonca-intermediate", "no-keysign", "pathlen-zero", "expired", "wrong-eku", "wrong-uri", "duplicate-uri"};
        for (size_t i = 0; i < sizeof identities / sizeof *identities; i++) {
            snprintf(name, sizeof name, "%s-identity-%s.pem", levels[level], identities[i]);
            unsigned char *identity = load(argv[1], name, &n);
            time_t expires = 123;
            int result = wendy_pki_verify_identity(identity, n, root, root_n, key, key_n, principal, signed_time, &expires);
            printf("ML-DSA %s P-256 identity %s: %d\n", levels[level], identities[i], result);
            fflush(stdout);
            assert(i == 0 ? result == 0 && expires == signed_time + 3600 : result != 0 && expires == 123);
            if (i == 0) {
                assert(wendy_pki_verify_identity(identity, n, root, root_n, wrong_key, wrong_key_n, principal, signed_time, &expires) != 0);
                assert(wendy_pki_verify_identity(identity, n, root, root_n, key, key_n, principal, signed_time + 3601, &expires) != 0);
            }
            free(identity);
        }
        free(root);
    }
    free(nonce); free(key); free(wrong_key);
    puts("ML-DSA mixed-chain verification tests passed");
    return 0;
}
