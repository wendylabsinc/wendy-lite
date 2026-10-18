#include "wendy_lite_grant.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wendy_pki_crypto.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "check failed at %d\n", __LINE__); abort(); } } while (0)
static size_t load(const char *root, const char *name, uint8_t *out, size_t max)
{
    char path[1024]; snprintf(path, sizeof path, "%s/%s", root, name);
    FILE *f = fopen(path, "rb"); CHECK(f != NULL);
    size_t n = fread(out, 1, max, f); CHECK(!ferror(f) && fgetc(f) == EOF);
    fclose(f); return n;
}
static int verify(const uint8_t *r, size_t n, const struct wendy_lite_trust *trust,
    const uint8_t device[32], const uint8_t operator_id[32], const uint8_t spki[32], time_t now)
{
    uint64_t expires = 123;
    int result = wendy_lite_verify_grant(r, n, trust, device, operator_id, spki, now, &expires);
    if (result) CHECK(expires == 123);
    else CHECK(expires == 1700001800); /* Session lasts beyond present-by. */
    return result;
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    uint8_t record[WENDY_LITE_GRANT_MAX + 1], changed[WENDY_LITE_GRANT_MAX + 1];
    struct wendy_lite_trust trust = {.count = 1};
    const char *kid = "conformance-cloud-key";
    trust.keys[0].id_size = strlen(kid); memcpy(trust.keys[0].id, kid, strlen(kid));
    CHECK(load(argv[1], "cloud-key.bin", trust.keys[0].public_key, WENDY_LITE_KEY_BYTES) == WENDY_LITE_KEY_BYTES);
    size_t size = load(argv[1], "grant.bin", record, sizeof record);
    CHECK(size == WENDY_LITE_GRANT_FIXED + strlen(kid));
    trust.session[15] = 3;
    CHECK(wendy_pki_sha256(record, size, trust.grant_hash) == 0);
    uint8_t device[32], operator_id[32], spki[32];
    const char *device_uri = "spiffe://wendy.sh/tenant/00000000-0000-4000-8000-000000000001/device/lite-test";
    const char *operator_uri = "spiffe://wendy.sh/tenant/00000000-0000-4000-8000-000000000001/operator/00000000-0000-4000-8000-000000000002";
    CHECK(wendy_pki_sha256((const uint8_t *)device_uri, strlen(device_uri), device) == 0);
    CHECK(wendy_pki_sha256((const uint8_t *)operator_uri, strlen(operator_uri), operator_id) == 0);
    uint8_t certificate[2048], raw_spki[256], expected[32], peer_uri[32];
    size_t cert_n = load(argv[1], "operator.der", certificate, sizeof certificate);
    size_t spki_n = load(argv[1], "operator-spki.der", raw_spki, sizeof raw_spki);
    CHECK(wendy_pki_sha256(raw_spki, spki_n, expected) == 0);
    CHECK(wendy_lite_peer_spki_hash(certificate, cert_n, spki) == 0 && !memcmp(spki, expected, 32));
    CHECK(wendy_lite_peer_hash(certificate, cert_n, peer_uri) == 0 && !memcmp(peer_uri, operator_id, 32));
    time_t certificate_expiry = 123;
    CHECK(wendy_lite_peer_expiry(certificate, cert_n, &certificate_expiry) == 0 && certificate_expiry == 1700003600);
    certificate[cert_n] = 0;
    CHECK(wendy_lite_peer_spki_hash(certificate, cert_n + 1, expected) != 0);
    CHECK(wendy_lite_peer_spki_hash(certificate, cert_n - 1, expected) != 0);
    certificate_expiry = 123;
    CHECK(wendy_lite_peer_expiry(certificate, cert_n + 1, &certificate_expiry) != 0 && certificate_expiry == 123);
    CHECK(verify(record, size, &trust, device, operator_id, spki, 1700000000) == 0);
    CHECK(verify(record, size, &trust, device, operator_id, spki, 1700000059) == 0);
    CHECK(verify(record, size, &trust, device, operator_id, spki, 1699999999) != 0);
    CHECK(verify(record, size, &trust, device, operator_id, spki, 1700000060) != 0);
    /* Valid certificate and matching operator identity cannot substitute another key. */
    cert_n = load(argv[1], "operator-wrong-key.der", certificate, sizeof certificate);
    CHECK(wendy_lite_peer_hash(certificate, cert_n, peer_uri) == 0 && !memcmp(peer_uri, operator_id, 32));
    CHECK(wendy_lite_peer_spki_hash(certificate, cert_n, expected) == 0 && memcmp(expected, spki, 32));
    CHECK(verify(record, size, &trust, device, peer_uri, expected, 1700000000) != 0);
    for (size_t i = 0; i < size; i++) CHECK(verify(record, i, &trust, device, operator_id, spki, 1700000000) != 0);
    record[size] = 0;
    CHECK(verify(record, size + 1, &trust, device, operator_id, spki, 1700000000) != 0);
    device[0] ^= 1;
    CHECK(verify(record, size, &trust, device, operator_id, spki, 1700000000) != 0);
    device[0] ^= 1; operator_id[0] ^= 1;
    CHECK(verify(record, size, &trust, device, operator_id, spki, 1700000000) != 0);
    operator_id[0] ^= 1; trust.session[0] ^= 1;
    CHECK(verify(record, size, &trust, device, operator_id, spki, 1700000000) != 0);
    trust.session[0] ^= 1; trust.keys[0].id[0] ^= 1;
    CHECK(verify(record, size, &trust, device, operator_id, spki, 1700000000) != 0);
    trust.keys[0].id[0] ^= 1; trust.grant_hash[0] ^= 1;
    CHECK(verify(record, size, &trust, device, operator_id, spki, 1700000000) != 0);
    trust.grant_hash[0] ^= 1;
    /* Rotated previous key works; duplicate IDs remain ambiguous and fail. */
    trust.count = 2; trust.keys[1] = trust.keys[0]; trust.keys[0].id[0] ^= 1;
    CHECK(verify(record, size, &trust, device, operator_id, spki, 1700000000) == 0);
    trust.keys[0].id[0] ^= 1;
    CHECK(verify(record, size, &trust, device, operator_id, spki, 1700000000) != 0);
    trust.count = 1;
    memcpy(changed, record, size); changed[size - 20] ^= 1;
    CHECK(wendy_pki_sha256(changed, size, trust.grant_hash) == 0);
    CHECK(verify(changed, size, &trust, device, operator_id, spki, 1700000000) != 0);
    memcpy(changed, record, size); changed[4] = 255;
    CHECK(verify(changed, size, &trust, device, operator_id, spki, 1700000000) != 0);
    const char *invalid[] = {"legacy-grant.bin", "long-window.bin", "zero-window.bin", "reversed-window.bin", "zero-issued.bin", "overflow.bin"};
    for (size_t i = 0; i < sizeof invalid / sizeof *invalid; i++) {
        size_t n = load(argv[1], invalid[i], changed, sizeof changed);
        CHECK(wendy_pki_sha256(changed, n, trust.grant_hash) == 0);
        time_t now = i == 4 ? 1 : i == 5 ? (time_t)(INT64_MAX - 100) : 1700000000;
        CHECK(verify(changed, n, &trust, device, operator_id, spki, now) != 0);
    }
    size_t n = load(argv[1], "maximum-kid.bin", changed, sizeof changed);
    CHECK(n == WENDY_LITE_GRANT_MAX);
    trust.keys[0].id_size = 128; memset(trust.keys[0].id, 'k', 128);
    CHECK(wendy_pki_sha256(changed, n, trust.grant_hash) == 0);
    CHECK(verify(changed, n, &trust, device, operator_id, spki, 1700000000) == 0);
    changed[n] = 0;
    CHECK(verify(changed, n + 1, &trust, device, operator_id, spki, 1700000000) != 0);
    printf("%u Lite grant checks passed\n", checks);
    return 0;
}
