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

/* Replace one CA while retaining the complete authenticated device chain. */
static unsigned char *replace_pem_certificate(const unsigned char *chain,
    size_t chain_size, size_t index, const unsigned char *replacement,
    size_t replacement_size, size_t *size)
{
    const char end_marker[] = "-----END CERTIFICATE-----\n";
    const size_t marker_size = sizeof end_marker - 1;
    size_t begin = 0, end = 0;
    for (size_t i = 0; i <= index; i++) {
        begin = end;
        while (end + marker_size <= chain_size &&
               memcmp(chain + end, end_marker, marker_size)) end++;
        assert(end + marker_size <= chain_size);
        end += marker_size;
    }
    *size = chain_size - (end - begin) + replacement_size;
    unsigned char *result = malloc(*size);
    assert(result);
    memcpy(result, chain, begin);
    memcpy(result + begin, replacement, replacement_size);
    memcpy(result + begin + replacement_size, chain + end, chain_size - end);
    return result;
}

/* Locate SignerInfo.signatureAlgorithm independently of certificate OIDs. */
typedef struct { unsigned char *raw, *body; size_t size; } test_der;
static test_der next_der(unsigned char **cursor, const unsigned char *end, unsigned tag)
{
    unsigned char *raw = *cursor;
    assert(end - raw >= 2 && raw[0] == tag);
    size_t size = raw[1], header = 2;
    if (size & 128) {
        unsigned count = size & 127;
        assert(count && count <= 3 && end - raw >= 2 + count);
        size = 0;
        while (count--) size = size * 256 + raw[header++];
    }
    assert(size <= (size_t)(end - raw) - header);
    *cursor = raw + header + size;
    return (test_der){raw, raw + header, size};
}
static void reject_signature_algorithm_variants(unsigned char *response, size_t size,
    const unsigned char nonce[32], const unsigned char *root, size_t root_size)
{
    test_der parents[7];
    unsigned char *p = response;
    const unsigned char *end = response + size;
    parents[0] = next_der(&p, end, 0x30); p = parents[0].body;
    next_der(&p, end, 0x30); /* status */
    parents[1] = next_der(&p, end, 0x30); p = parents[1].body;
    next_der(&p, end, 6); /* signedData OID */
    parents[2] = next_der(&p, end, 0xa0); p = parents[2].body;
    parents[3] = next_der(&p, end, 0x30); p = parents[3].body;
    next_der(&p, end, 2); next_der(&p, end, 0x31);
    next_der(&p, end, 0x30); next_der(&p, end, 0xa0);
    parents[4] = next_der(&p, end, 0x31); p = parents[4].body;
    parents[5] = next_der(&p, end, 0x30); p = parents[5].body;
    next_der(&p, end, 2); next_der(&p, end, 0x30);
    next_der(&p, end, 0x30); next_der(&p, end, 0xa0);
    parents[6] = next_der(&p, end, 0x30);
    unsigned char *id_cursor = parents[6].body;
    test_der id = next_der(&id_cursor, end, 6);
    assert(id.size == 9 && id.body[8] == 18 && id_cursor == p);
    const unsigned unsupported[] = {17, 19, 33}; /* ML-DSA-44, ML-DSA-87, HashML-DSA-65. */
    for (size_t i = 0; i < sizeof unsupported / sizeof *unsupported; i++) {
        time_t verified = 123;
        id.body[8] = unsupported[i];
        assert(wendy_pki_verify_time(response, size, nonce, root, root_size, 0, &verified) != 0);
        assert(verified == 123);
    }
    id.body[8] = 18;

    /* NULL parameters are forbidden even though the signed attributes and
     * signature are unchanged. Update enclosing lengths without re-signing. */
    size_t insertion = p - response;
    unsigned char *with_null = malloc(size + 2);
    assert(with_null);
    memcpy(with_null, response, insertion);
    with_null[insertion] = 5; with_null[insertion + 1] = 0;
    memcpy(with_null + insertion + 2, response + insertion, size - insertion);
    for (size_t i = 0; i < sizeof parents / sizeof *parents; i++) {
        size_t length = parents[i].size + 2;
        unsigned char *raw = with_null + (parents[i].raw - response);
        size_t header = parents[i].body - parents[i].raw;
        if (header == 2) {
            assert(length < 128); raw[1] = length;
        } else {
            for (size_t j = header - 1; j >= 2; j--) { raw[j] = length; length >>= 8; }
            assert(!length);
        }
    }
    time_t verified = 123;
    assert(wendy_pki_verify_time(with_null, size + 2, nonce, root, root_size, 0, &verified) != 0);
    assert(verified == 123);
    free(with_null);
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
        const int supported_ca = strcmp(levels[level], "44") != 0;
        const int supported_signer = !strcmp(levels[level], "65");
        assert((wendy_pki_verify_roots(root, root_n) == 0) == supported_ca);
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
            assert(i == 0 && supported_signer ? result == 0 && verified == signed_time : result != 0 && verified == 123);
            if (i == 0 && supported_signer) {
                reject_signature_algorithm_variants(response, n, nonce, root, root_n);
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
                    /* CA renewals with the same key must be selected using
                     * authenticated time, independently of the wall clock. */
                    unsigned char *renewed = malloc(invalid_n + root_n);
                    assert(renewed);
                    memcpy(renewed, invalid, invalid_n);
                    memcpy(renewed + invalid_n, root, root_n);
                    assert(wendy_pki_verify_time(response, n, nonce, renewed,
                        invalid_n + root_n, 0, &verified) == 0 && verified == signed_time);
                    free(renewed);
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
            assert(i == 0 && supported_ca ? result == 0 && expires == signed_time + 3600 : result != 0 && expires == 123);
            if (i == 0 && supported_ca) {
                assert(wendy_pki_verify_identity(identity, n, root, root_n, wrong_key, wrong_key_n, principal, signed_time, &expires) != 0);
                assert(wendy_pki_verify_identity(identity, n, root, root_n, key, key_n, principal, signed_time + 3601, &expires) != 0);
            }
            free(identity);
        }
        free(root);
    }
    size_t root_n;
    unsigned char *root = load(argv[1], "mixed87-root.pem", &root_n);
    assert(wendy_pki_verify_roots(root, root_n) == 0);
    size_t valid_size;
    unsigned char *valid_chain = load(argv[1], "mixed87-identity-valid.pem", &valid_size);
    const char *mixed[] = {"valid", "tampered-intermediate", "tampered-issuer", "hash87-intermediate", "44-intermediate"};
    for (size_t i = 0; i < sizeof mixed / sizeof *mixed; i++) {
        unsigned char *chain = valid_chain;
        n = valid_size;
        if (i) {
            char name[128];
            snprintf(name, sizeof name, "mixed87-ca-%s.pem", mixed[i]);
            size_t ca_size;
            unsigned char *ca = load(argv[1], name, &ca_size);
            size_t index = !strcmp(mixed[i], "tampered-issuer") ? 2 : 3;
            chain = replace_pem_certificate(valid_chain, valid_size, index,
                ca, ca_size, &n);
            free(ca);
        }
        time_t expires = 123;
        int result = wendy_pki_verify_identity(chain, n, root, root_n,
            key, key_n, principal, signed_time, &expires);
        printf("Mixed ML-DSA-87 CA chain %s: %d\n", mixed[i], result);
        assert(i == 0 ? result == 0 && expires == signed_time + 3600 : result != 0 && expires == 123);
        if (i) free(chain);
    }
    free(valid_chain);
    free(root);
    for (size_t i = 0; i < sizeof levels / sizeof *levels; i++) {
        char name[128];
        snprintf(name, sizeof name, "mixed87-operator-%s.der", levels[i]);
        unsigned char *operator = load(argv[1], name, &n);
        int result = wendy_pki_verify_operator(operator, n,
            "2558fd76-afc7-466e-9613-6b715296a526");
        assert((result == 0) == !strcmp(levels[i], "65"));
        free(operator);
    }
    free(nonce); free(key); free(wrong_key);
    puts("ML-DSA-65 identities and ML-DSA-65/87 CA verification tests passed");
    return 0;
}
