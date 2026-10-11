#include "wendy_lite_grant.h"
#include <stdlib.h>
#include <string.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hash.h>

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
        memcmp(r, "WLG1", 4) || n != 3458u + r[4] ||
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
        expiry <= (uint64_t)now || wc_Sha256Hash(r, n, hash) ||
        memcmp(hash, trust->grant_hash, 32) || memcmp(fields + 16, trust->session, 16) ||
        memcmp(fields + 48, device, 32) || memcmp(fields + 80, operator_id, 32)) return -1;
    dilithium_key *key = malloc(sizeof *key);
    if (!key) return -1;
    int result = -1, valid = 0;
    if (!wc_dilithium_init(key)) {
        if (!wc_dilithium_set_level(key, WC_ML_DSA_65) &&
            !wc_dilithium_import_public(selected->public_key, WENDY_LITE_KEY_BYTES, key) &&
            !wc_dilithium_verify_ctx_msg(r + n - 3309, 3309, NULL, 0, r, n - 3309, &valid, key) && valid) {
            *expires = expiry;
            result = 0;
        }
        wc_dilithium_free(key);
    }
    free(key);
    return result;
}
int wendy_lite_peer_hash(const uint8_t *der, size_t n, uint8_t hash[32])
{
    if (!der || !n || n > 65536 || !hash) return -1;
    DecodedCert *cert = malloc(sizeof *cert);
    if (!cert) return -1;
    wc_InitDecodedCert(cert, der, n, NULL);
    int result = -1, count = 0;
    if (!wc_ParseCert(cert, CERT_TYPE, NO_VERIFY, NULL)) {
        for (DNS_entry *a = cert->altNames; a; a = a->next) {
            if (a->type != ASN_URI_TYPE) continue;
            count++;
            result = a->len > 0 ? wc_Sha256Hash((uint8_t *)a->name, a->len, hash) : -1;
        }
    }
    wc_FreeDecodedCert(cert);
    free(cert);
    return count == 1 && result == 0 ? 0 : -1;
}
