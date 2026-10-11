#include "wendy_lite_grant.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/sha256.h>
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "check failed at %d\n", __LINE__); abort(); } } while (0)
static size_t load(const char *root, const char *name, uint8_t *out, size_t max)
{
    char path[1024]; snprintf(path, sizeof path, "%s/%s", root, name);
    FILE *f = fopen(path, "rb"); CHECK(f != NULL);
    size_t n = fread(out, 1, max, f); CHECK(!ferror(f) && fgetc(f) == EOF);
    fclose(f); return n;
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    uint8_t record[WENDY_LITE_GRANT_MAX], changed[WENDY_LITE_GRANT_MAX];
    struct wendy_lite_trust trust = {.count = 1};
    const char *kid = "conformance-cloud-key";
    trust.keys[0].id_size = strlen(kid); memcpy(trust.keys[0].id, kid, strlen(kid));
    CHECK(load(argv[1], "cloud-key.bin", trust.keys[0].public_key, WENDY_LITE_KEY_BYTES) == WENDY_LITE_KEY_BYTES);
    size_t size = load(argv[1], "grant.bin", record, sizeof record);
    trust.session[15] = 3;
    CHECK(mbedtls_sha256(record, size, trust.grant_hash, 0) == 0);
    uint8_t device[32], operator_id[32];
    const char *device_uri = "spiffe://wendy.sh/tenant/00000000-0000-4000-8000-000000000001/device/lite-test";
    const char *operator_uri = "spiffe://wendy.sh/tenant/00000000-0000-4000-8000-000000000001/operator/00000000-0000-4000-8000-000000000002";
    CHECK(mbedtls_sha256((const uint8_t *)device_uri, strlen(device_uri), device, 0) == 0);
    CHECK(mbedtls_sha256((const uint8_t *)operator_uri, strlen(operator_uri), operator_id, 0) == 0);
    uint64_t expiry = 0;
    CHECK(wendy_lite_verify_grant(record, size, &trust, device, operator_id, 1700000000, &expiry) == 0);
    CHECK(expiry == 1700001800);
    // Every possible truncation is rejected before any out-of-bounds read.
    for (size_t i = 0; i < size; i++) CHECK(wendy_lite_verify_grant(record, i, &trust, device, operator_id, 1700000000, &expiry) != 0);
    CHECK(wendy_lite_verify_grant(record, size + 1, &trust, device, operator_id, 1700000000, &expiry) != 0);
    CHECK(wendy_lite_verify_grant(record, size, &trust, device, operator_id, 1699999999, &expiry) != 0);
    CHECK(wendy_lite_verify_grant(record, size, &trust, device, operator_id, 1700001800, &expiry) != 0);
    device[0] ^= 1;
    CHECK(wendy_lite_verify_grant(record, size, &trust, device, operator_id, 1700000000, &expiry) != 0);
    device[0] ^= 1; operator_id[0] ^= 1;
    CHECK(wendy_lite_verify_grant(record, size, &trust, device, operator_id, 1700000000, &expiry) != 0);
    operator_id[0] ^= 1; trust.session[0] ^= 1;
    CHECK(wendy_lite_verify_grant(record, size, &trust, device, operator_id, 1700000000, &expiry) != 0);
    trust.session[0] ^= 1; trust.keys[0].id[0] ^= 1;
    CHECK(wendy_lite_verify_grant(record, size, &trust, device, operator_id, 1700000000, &expiry) != 0);
    trust.keys[0].id[0] ^= 1;
    memcpy(changed, record, size); changed[size - 20] ^= 1;
    // Even a matching upgrade hash cannot make a forged signature valid.
    CHECK(mbedtls_sha256(changed, size, trust.grant_hash, 0) == 0);
    CHECK(wendy_lite_verify_grant(changed, size, &trust, device, operator_id, 1700000000, &expiry) != 0);
    memcpy(changed, record, size); changed[4] = 255;
    CHECK(wendy_lite_verify_grant(changed, size, &trust, device, operator_id, 1700000000, &expiry) != 0);
    printf("%u Lite grant checks passed\n", checks);
    return 0;
}
