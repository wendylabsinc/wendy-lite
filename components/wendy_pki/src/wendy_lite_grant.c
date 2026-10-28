#include "wendy_lite_grant.h"
#include "wendy_pki_parsed_identity.h"
#include <stdlib.h>
#include <string.h>
#include "wendy_pki_crypto.h"
#include <psa/crypto.h>
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
    const uint8_t operator_id[32], const uint8_t operator_spki[32],
    time_t now, uint64_t *session_expires)
{
    if (!r || !trust || !device || !operator_id || !operator_spki || !session_expires ||
        now < 0 || n < 5 || memcmp(r, "WLG3", 4) || n != WENDY_LITE_GRANT_FIXED + r[4] ||
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
    if (!issued || issued > INT64_MAX - 1800 || expiry <= issued ||
        expiry - issued > 60 || issued > (uint64_t)now ||
        expiry <= (uint64_t)now || wendy_pki_sha256(r, n, hash) ||
        memcmp(hash, trust->grant_hash, 32) || memcmp(fields + 16, trust->session, 16) ||
        memcmp(fields + 64, device, 32) || memcmp(fields + 96, operator_id, 32) ||
        memcmp(fields + 128, operator_spki, 32)) return -1;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    int result = -1;
    /* PSA validates the SEC1 point on import and takes the wire-format r||s
     * signature directly, without exposing curve or big-integer internals. */
    if (psa_import_key(&attributes, selected->public_key, WENDY_LITE_KEY_BYTES, &key) == PSA_SUCCESS &&
        !wendy_pki_sha256(r, n-64, hash) &&
        psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, sizeof hash,
                        r+n-64, 64) == PSA_SUCCESS) {
        *session_expires = issued + 1800;
        result = 0;
    }
    psa_destroy_key(key);
    psa_reset_key_attributes(&attributes);
    return result;
}

int pki_parsed_peer_expiry(const mbedtls_x509_crt *cert,time_t *expires)
{
    if (!cert || !expires || !cert->raw.len) return -1;
    int result=-1;
        const mbedtls_x509_time *t = &cert->valid_to;
        if (t->year >= 1970 && t->year <= 9999) {
            /* Gregorian civil date to UTC seconds, independent of process TZ. */
            int year = t->year - (t->mon <= 2);
            int era = year / 400, yy = year - era * 400;
            int doy = (153 * (t->mon + (t->mon > 2 ? -3 : 9)) + 2) / 5 + t->day - 1;
            int64_t seconds = ((int64_t)era * 146097 + yy * 365 + yy / 4 - yy / 100 +
                               doy - 719468) * 86400 + t->hour * 3600 + t->min * 60 + t->sec;
            time_t value = (time_t)seconds;
            if (seconds >= 0 && (int64_t)value == seconds) {
                *expires = value;
                result = 0;
            }
        }
    return result;
}
int wendy_lite_peer_expiry(const uint8_t *der,size_t n,time_t *expires)
{
    if (!der || !n || n>65536 || !expires || wendy_pki_crypto_init()) return -1;
    mbedtls_x509_crt cert;mbedtls_x509_crt_init(&cert);
    int result=mbedtls_x509_crt_parse_der(&cert,der,n) || cert.raw.len!=n ? -1 :
        pki_parsed_peer_expiry(&cert,expires);
    mbedtls_x509_crt_free(&cert);return result;
}

int wendy_lite_peer_spki_hash(const uint8_t *der, size_t n, uint8_t hash[32])
{
    if (!der || !n || n > 65536 || !hash || wendy_pki_crypto_init()) return -1;
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int result = -1;
    if (!mbedtls_x509_crt_parse_der(&cert, der, n) && cert.raw.len == n &&
        cert.pk_raw.p && cert.pk_raw.len)
        result = wendy_pki_sha256(cert.pk_raw.p, cert.pk_raw.len, hash);
    mbedtls_x509_crt_free(&cert);
    return result;
}

int wendy_lite_peer_hash(const uint8_t *der, size_t n, uint8_t hash[32])
{
    if (!der || !n || n > 65536 || !hash || wendy_pki_crypto_init()) return -1;
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int result = -1, count = 0;
    if (!mbedtls_x509_crt_parse_der(&cert, der, n)) {
        for (const mbedtls_x509_sequence *a = &cert.subject_alt_names; a && a->buf.p; a = a->next) {
            mbedtls_x509_subject_alternative_name san;
            if (mbedtls_x509_parse_subject_alt_name(&a->buf, &san) ||
                san.type != MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) continue;
            count++;
            result = wendy_pki_sha256(san.san.unstructured_name.p, san.san.unstructured_name.len, hash);
        }
    }
    mbedtls_x509_crt_free(&cert);
    return count == 1 && result == 0 ? 0 : -1;
}
