#include "wendy_lite_grant.h"
#include <stdlib.h>
#include <string.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

int wendy_lite_key_id(const uint8_t *id, size_t n)
{
    if (!id || n < 1 || n > 128) return -1;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = id[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return -1;
    }
    return 0;
}
static uint64_t u64(const uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value = (value << 8) | p[i];
    return value;
}
int wendy_lite_verify_grant(const uint8_t *r, size_t n,
    const struct wendy_lite_trust *trust, const uint8_t device[32],
    const uint8_t operator_id[32], time_t now, uint64_t *expires)
{
    if (!r || !trust || !device || !operator_id || !expires || now < 0 || n < 5 ||
        memcmp(r, "WLG2", 4) || n != 213u + r[4] ||
        wendy_lite_key_id(r + 5, r[4]) || trust->count < 1 || trust->count > 2) return -1;
    const struct wendy_lite_key *selected = NULL;
    for (unsigned i = 0; i < trust->count; i++) {
        const struct wendy_lite_key *k = &trust->keys[i];
        if (k->id_size == r[4] && !memcmp(k->id, r + 5, r[4])) {
            if (selected) return -1;
            selected = k;
        }
    }
    if (!selected) return -1;
    const uint8_t *fields = r + 5 + r[4];
    uint64_t issued = u64(fields), expiry = u64(fields + 8);
    uint8_t hash[32];
    if (!issued || expiry <= issued || expiry - issued > 1800 || issued > (uint64_t)now ||
        expiry <= (uint64_t)now || mbedtls_sha256(r, n, hash, 0) ||
        memcmp(hash, trust->grant_hash, 32) || memcmp(fields + 16, trust->session, 16) ||
        memcmp(fields + 48, device, 32) || memcmp(fields + 80, operator_id, 32)) return -1;
    mbedtls_ecp_group group;
    mbedtls_ecp_point point;
    mbedtls_mpi sr, ss;
    mbedtls_ecp_group_init(&group); mbedtls_ecp_point_init(&point);
    mbedtls_mpi_init(&sr); mbedtls_mpi_init(&ss);
    int result = -1;
    if (!mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) &&
        !mbedtls_ecp_point_read_binary(&group, &point, selected->public_key, WENDY_LITE_KEY_BYTES) &&
        !mbedtls_ecp_check_pubkey(&group, &point) &&
        !mbedtls_mpi_read_binary(&sr, r+n-64, 32) &&
        !mbedtls_mpi_read_binary(&ss, r+n-32, 32) &&
        !mbedtls_sha256(r, n-64, hash, 0) &&
        !mbedtls_ecdsa_verify(&group, hash, 32, &point, &sr, &ss)) {
        *expires = expiry;
        result = 0;
    }
    mbedtls_mpi_free(&sr); mbedtls_mpi_free(&ss);
    mbedtls_ecp_point_free(&point); mbedtls_ecp_group_free(&group);
    return result;
}

int wendy_lite_peer_hash(const uint8_t *der, size_t n, uint8_t hash[32])
{
    if (!der || !n || n > 65536 || !hash) return -1;
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int result = -1, count = 0;
    if (!mbedtls_x509_crt_parse_der(&cert, der, n)) {
        for (const mbedtls_x509_sequence *a = &cert.subject_alt_names; a && a->buf.p; a = a->next) {
            mbedtls_x509_subject_alternative_name san;
            if (mbedtls_x509_parse_subject_alt_name(&a->buf, &san) ||
                san.type != MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) continue;
            count++;
            result = mbedtls_sha256(san.san.unstructured_name.p, san.san.unstructured_name.len, hash, 0);
        }
    }
    mbedtls_x509_crt_free(&cert);
    return count == 1 && result == 0 ? 0 : -1;
}
