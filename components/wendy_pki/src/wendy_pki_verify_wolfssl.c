#include "wendy_pki_verify.h"
#include "wendy_lite_grant.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/settings.h>

static int root_algorithm_allowed(WOLFSSL_X509 *cert);

int wendy_pki_verify_roots(const uint8_t *pem, size_t size)
{
    if (!pem || !size || size > 16384 || memchr(pem, 0, size))
        return -1;
    char *copy = calloc(1, size + 1);
    if (!copy)
        return -1;
    memcpy(copy, pem, size);
    char *p = copy;
    int count = 0, result = -1;
    while (*p)
    {
        while (*p && strchr(" \t\r\n", *p))
            p++;
        if (!*p)
            break;
        if (count == 8 || strncmp(p, "-----BEGIN CERTIFICATE-----", 27))
            goto done;
        char *end = strstr(p, "-----END CERTIFICATE-----");
        if (!end)
            goto done;
        end += 25;
        WOLFSSL_X509 *cert = wolfSSL_X509_load_certificate_buffer(
            (const uint8_t *)p, (int)(end - p), WOLFSSL_FILETYPE_PEM);
        if (!cert)
            goto done;
        int ca = wolfSSL_X509_get_isCA(cert) && root_algorithm_allowed(cert);
        wolfSSL_X509_free(cert);
        if (!ca)
            goto done;
        count++;
        p = end;
    }
    result = count ? 0 : -1;
done:
    free(copy);
    return result;
}

/* Bounded DER reader. Indefinite/nonminimal lengths, high tags, integer padding,
 * trailing bytes, duplicate security attributes and ambiguous signers fail. */
typedef struct
{
    const uint8_t *p, *raw;
    size_t n, raw_n;
    unsigned tag;
} der;
static int take(der *in, unsigned tag, der *out)
{
    if (in->n < 2 || in->p[0] != tag || (tag & 31) == 31)
        return -1;
    size_t h = 2, n = in->p[1];
    if (n & 128)
    {
        size_t count = n & 127;
        if (!count || count > 3 || in->n < 2 + count || !in->p[2])
            return -1;
        h += count;
        n = 0;
        for (size_t i = 0; i < count; ++i)
            n = n * 256 + in->p[2 + i];
        if (n < 128)
            return -1;
    }
    if (h > in->n || n > in->n - h)
        return -1;
    *out = (der){in->p + h, in->p, n, h + n, tag};
    in->p += h + n;
    in->n -= h + n;
    return 0;
}
static int equal(der a, der b) { return a.n == b.n && !memcmp(a.p, b.p, a.n); }
static int bytes(der a, const uint8_t *b, size_t n) { return a.n == n && !memcmp(a.p, b, n); }
static int integer(der *in, der *out)
{
    if (take(in, 2, out) || !out->n || (out->p[0] & 128))
        return -1;
    if (out->n > 1 && out->p[0] == 0 && !(out->p[1] & 128))
        return -1;
    return 0;
}
static int number(der *in, unsigned n)
{
    der d;
    return integer(in, &d) || d.n != 1 || d.p[0] != n ? -1 : 0;
}
static const uint8_t sha256oid[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1};
static const uint8_t signed_data_oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2};
static const uint8_t tst_oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 1, 4};
static const uint8_t ct_oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 3};
static const uint8_t md_oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 4};
static const uint8_t ess_oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 47};
static int oid(der *in, const uint8_t *value, size_t size)
{
    der d;
    return take(in, 6, &d) || !bytes(d, value, size) ? -1 : 0;
}
static int algorithm(der *in, der *id)
{
    der seq, nil;
    if (take(in, 0x30, &seq) || take(&seq, 6, id))
        return -1;
    if (seq.n && (take(&seq, 5, &nil) || nil.n))
        return -1;
    return seq.n ? -1 : 0;
}
static int sha256_algorithm(der *in)
{
    der id;
    return algorithm(in, &id) || !bytes(id, sha256oid, sizeof sha256oid) ? -1 : 0;
}
static int utc_time(der d, time_t *value)
{
    if (d.tag != 24 || d.n != 15 || d.p[14] != 'Z')
        return -1;
    int v[6] = {0}, widths[] = {4, 2, 2, 2, 2, 2}, pos = 0;
    for (int i = 0; i < 6; i++)
        for (int j = 0; j < widths[i]; j++)
        {
            unsigned c = d.p[pos++];
            if (c < '0' || c > '9')
                return -1;
            v[i] = v[i] * 10 + c - '0';
        }
    int y = v[0], m = v[1], day = v[2];
    static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    if (y < 1970 || y > 9999 || m < 1 || m > 12 || day < 1 ||
        day > days[m - 1] + (m == 2 && leap) || v[3] > 23 || v[4] > 59 || v[5] > 59)
        return -1;
    /* Gregorian civil date -> seconds since 1970, independent of local TZ. */
    y -= m <= 2;
    int era = y / 400, yy = y - era * 400;
    int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    int64_t seconds = ((int64_t)era * 146097 + yy * 365 + yy / 4 - yy / 100 + doy - 719468) * 86400;
    *value = (time_t)(seconds + v[3] * 3600 + v[4] * 60 + v[5]);
    return *value < 0 ? -1 : 0;
}
static int certificate_parts(der cert, der *serial, der *issuer, der *spki)
{
    der seq, tbs, version, tmp;
    if (take(&cert, 0x30, &seq) || cert.n || take(&seq, 0x30, &tbs))
        return -1;
    if (tbs.n && tbs.p[0] == 0xa0 &&
        (take(&tbs, 0xa0, &version) || number(&version, 2) || version.n))
        return -1;
    if (integer(&tbs, serial) || take(&tbs, 0x30, &tmp) || take(&tbs, 0x30, issuer) ||
        take(&tbs, 0x30, &tmp) || take(&tbs, 0x30, &tmp) || take(&tbs, 0x30, spki))
        return -1;
    return 0;
}
static int root_algorithm_allowed(WOLFSSL_X509 *cert)
{
    int size = 0;
    const uint8_t *raw = wolfSSL_X509_get_der(cert, &size);
    der serial, issuer, spki, algorithm, id;
    if (!raw || size <= 0 ||
        certificate_parts((der){raw, raw, (size_t)size, (size_t)size, 0x30},
                          &serial, &issuer, &spki) ||
        take(&spki, 0x30, &algorithm) || take(&algorithm, 6, &id))
        return 0;
    const uint8_t ec[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1};
    const uint8_t rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1};
    const uint8_t rsa_pss[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 10};
    const uint8_t ml_prefix[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3};
    return bytes(id, ec, sizeof ec) || bytes(id, rsa, sizeof rsa) ||
           bytes(id, rsa_pss, sizeof rsa_pss) ||
           (id.n == 9 && !memcmp(id.p, ml_prefix, sizeof ml_prefix) &&
            id.p[8] >= 17 && id.p[8] <= 19 && !algorithm.n);
}
/* Match mbedTLS's default chain policy. Trust anchor self-signatures are not
 * part of the authenticated path, but their public keys must still be strong. */
int wendy_pki_certificate_policy(WOLFSSL_X509 *cert, bool trust_anchor)
{
    if (!cert || !root_algorithm_allowed(cert))
        return -1;
    int type = wolfSSL_X509_get_pubkey_type(cert);
    if (type == RSAk || type == RSAPSSk || type == ECDSAk)
    {
        WOLFSSL_EVP_PKEY *key = wolfSSL_X509_get_pubkey(cert);
        int bits = key ? wolfSSL_EVP_PKEY_bits(key) : 0;
        wolfSSL_EVP_PKEY_free(key);
        if (bits < (type == ECDSAk ? 256 : 2048))
            return -1;
    }
    if (trust_anchor)
        return 0;
    int size = 0;
    const uint8_t *raw = wolfSSL_X509_get_der(cert, &size);
    der input = {raw, raw, size > 0 ? (size_t)size : 0, 0, 0}, outer, tbs, alg, id;
    if (!raw || size <= 0 || take(&input, 0x30, &outer) || input.n ||
        take(&outer, 0x30, &tbs) || take(&outer, 0x30, &alg) || take(&alg, 6, &id))
        return -1;
    const uint8_t rsa_prefix[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1};
    const uint8_t ec_prefix[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3};
    const uint8_t ml_prefix[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3};
    if ((id.n == 9 && !memcmp(id.p, rsa_prefix, sizeof rsa_prefix) &&
         id.p[8] >= 11 && id.p[8] <= 13) ||
        (id.n == 8 && !memcmp(id.p, ec_prefix, sizeof ec_prefix) &&
         id.p[7] >= 2 && id.p[7] <= 4) ||
        (id.n == 9 && !memcmp(id.p, ml_prefix, sizeof ml_prefix) &&
         id.p[8] >= 17 && id.p[8] <= 19))
        return 0;
    if (id.n == 9 && !memcmp(id.p, rsa_prefix, sizeof rsa_prefix) && id.p[8] == 10)
    {
        /* RSA-PSS omits hashAlgorithm only for its SHA-1 default. The signature
         * verifier separately validates MGF, salt and trailer parameters. */
        der params, hash, hash_id;
        const uint8_t sha2_prefix[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2};
        if (!take(&alg, 0x30, &params) && !alg.n &&
            !take(&params, 0xa0, &hash) && !algorithm(&hash, &hash_id) && !hash.n &&
            hash_id.n == 9 && !memcmp(hash_id.p, sha2_prefix, sizeof sha2_prefix) &&
            hash_id.p[8] >= 1 && hash_id.p[8] <= 3)
            return 0;
    }
    return -1;
}
static int verify_signature(der spki, der sig_alg, der attrs, der sig)
{
    der a, key_alg, key;
    if (take(&spki, 0x30, &a) || take(&a, 6, &key_alg) || take(&spki, 3, &key) || spki.n ||
        key.n < 2 || key.p[0])
        return -1;
    uint8_t *message = malloc(attrs.raw_n);
    if (!message)
        return -1;
    memcpy(message, attrs.raw, attrs.raw_n);
    message[0] = 0x31;
    int result = -1, valid = 0;
    const uint8_t ml_prefix[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3};
    if (key_alg.n == 9 && !memcmp(key_alg.p, ml_prefix, 8) && key_alg.p[8] >= 17 &&
        key_alg.p[8] <= 19 && !a.n && equal(key_alg, sig_alg))
    {
        dilithium_key *k = malloc(sizeof *k);
        if (k)
        {
            int level = key_alg.p[8] == 17   ? WC_ML_DSA_44
                        : key_alg.p[8] == 18 ? WC_ML_DSA_65
                                             : WC_ML_DSA_87;
            if (!wc_dilithium_init(k))
            {
                if (!wc_dilithium_set_level(k, level) &&
                    !wc_dilithium_import_public(key.p + 1, key.n - 1, k) &&
                    !wc_dilithium_verify_ctx_msg(sig.p, sig.n, NULL, 0, message, attrs.raw_n,
                                                 &valid, k) &&
                    valid)
                    result = 0;
                wc_dilithium_free(k);
            }
            free(k);
        }
    }
    else
    {
        const uint8_t ec[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1};
        const uint8_t es256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2};
        const uint8_t p256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7};
        const uint8_t p384[] = {0x2b, 0x81, 4, 0, 0x22};
        der curve;
        if (bytes(key_alg, ec, sizeof ec) && bytes(sig_alg, es256, sizeof es256) &&
            !take(&a, 6, &curve) && !a.n &&
            (bytes(curve, p256, sizeof p256) || bytes(curve, p384, sizeof p384)))
        {
            ecc_key k;
            uint8_t hash[32];
            if (!wc_ecc_init(&k))
            {
                if (!wc_ecc_import_x963(key.p + 1, key.n - 1, &k) &&
                    !wc_Hash(WC_HASH_TYPE_SHA256, message, attrs.raw_n, hash, sizeof hash) &&
                    !wc_ecc_verify_hash(sig.p, sig.n, hash, sizeof hash, &valid, &k) && valid)
                    result = 0;
                wc_ecc_free(&k);
            }
        }
    }
    free(message);
    return result;
}
static int valid_at(WOLFSSL_X509 *cert, time_t now)
{
    return cert && wolfSSL_X509_cmp_time(wolfSSL_X509_get_notBefore(cert), &now) == -1 &&
           wolfSSL_X509_cmp_time(wolfSSL_X509_get_notAfter(cert), &now) == 1;
}
/* The pinned wolfSSL X509_STORE implementation inserts intermediates as
 * temporary CAs without enforcing their key usage or path length. Enforce
 * those constraints on the authenticated, leaf-first path it selected. */
static int verify_path_constraints(WOLFSSL_STACK *path)
{
    int count = wolfSSL_sk_X509_num(path);
    if (count < 2 || count > 9)
        return -1;
    for (int i = 0; i < count; i++)
        if (wendy_pki_certificate_policy(wolfSSL_sk_X509_value(path, i), i == count - 1))
            return -1;
    int subordinate_cas = 0;
    for (int i = 1; i < count; i++)
    {
        WOLFSSL_X509 *cert = wolfSSL_sk_X509_value(path, i);
        int size = 0;
        const uint8_t *raw = wolfSSL_X509_get_der(cert, &size);
        DecodedCert *decoded = malloc(sizeof *decoded);
        if (!raw || size <= 0 || !decoded)
        {
            free(decoded);
            return -1;
        }
        wc_InitDecodedCert(decoded, raw, (word32)size, NULL);
        int result = wc_ParseCert(decoded, CERT_TYPE, NO_VERIFY, NULL);
        if (!result && (!decoded->isCA ||
                        (decoded->extKeyUsageSet && !(decoded->extKeyUsage & KEYUSE_KEY_CERT_SIGN)) ||
                        (decoded->pathLengthSet && subordinate_cas > decoded->pathLength)))
            result = -1;
        wc_FreeDecodedCert(decoded);
        free(decoded);
        if (result)
            return -1;
        if (wolfSSL_X509_NAME_cmp(wolfSSL_X509_get_issuer_name(cert),
                                 wolfSSL_X509_get_subject_name(cert)) != 0)
            subordinate_cas++;
    }
    return 0;
}
/* Certificates from the response are untrusted intermediates. Only the build's
 * pre-pinned PEM bundle enters the trust store. */
static int verify_chain(WOLFSSL_X509 *leaf, WOLFSSL_STACK *untrusted, const uint8_t *roots,
                        size_t size, time_t now)
{
    if (wendy_pki_verify_roots(roots, size) || !valid_at(leaf, now))
        return -1;
    for (int i = 0; i < wolfSSL_sk_X509_num(untrusted); i++)
        if (!valid_at(wolfSSL_sk_X509_value(untrusted, i), now))
            return -1;
    int result = -1, count = 0;
    WOLFSSL_X509_STORE *store = wolfSSL_X509_STORE_new();
    WOLFSSL_X509_STORE_CTX *ctx = wolfSSL_X509_STORE_CTX_new();
    WOLFSSL_BIO *bio = wolfSSL_BIO_new_mem_buf(roots, (int)size);
    if (!store || !ctx || !bio)
        goto done;
    /* Root AND temporary intermediate insertion use the wall clock before the
     * context time takes effect. Check every certificate at the supplied time;
     * disable only this isolated store's redundant wall-clock checks. */
    WOLFSSL_X509_VERIFY_PARAM *param = wolfSSL_X509_STORE_get0_param(store);
    if (!param || wolfSSL_X509_VERIFY_PARAM_set_flags(param, WOLFSSL_NO_CHECK_TIME) != WOLFSSL_SUCCESS)
        goto done;
    WOLFSSL_X509 *root;
    while ((root = wolfSSL_PEM_read_bio_X509(bio, NULL, NULL, NULL)))
    {
        int ok = valid_at(root, now) &&
                 wolfSSL_X509_STORE_add_cert(store, root) == WOLFSSL_SUCCESS;
        wolfSSL_X509_free(root);
        if (!ok)
            goto done;
        count++;
    }
    if (!count ||
        wolfSSL_X509_STORE_CTX_init(ctx, store, leaf, untrusted) != WOLFSSL_SUCCESS)
        goto done;
    /* Keep authenticated-time checking active in the verifier itself too.
     * Only store insertion must bypass the untrusted device clock. */
    WOLFSSL_X509_VERIFY_PARAM *context_param = wolfSSL_X509_STORE_CTX_get0_param(ctx);
    if (!context_param ||
        wolfSSL_X509_VERIFY_PARAM_clear_flags(context_param, WOLFSSL_NO_CHECK_TIME) != WOLFSSL_SUCCESS)
        goto done;
    wolfSSL_X509_STORE_CTX_set_time(ctx, 0, now);
    if (wolfSSL_X509_verify_cert(ctx) == WOLFSSL_SUCCESS)
        result = verify_path_constraints(wolfSSL_X509_STORE_CTX_get_chain(ctx));
    else
        printf("PKI chain verification error %d at depth %d\n",
               wolfSSL_X509_STORE_CTX_get_error(ctx), wolfSSL_X509_STORE_CTX_get_error_depth(ctx));
done:
    wolfSSL_BIO_free(bio);
    wolfSSL_X509_STORE_CTX_free(ctx);
    wolfSSL_X509_STORE_free(store);
    return result;
}
static int tsa_eku(der cert)
{
    DecodedCert *d = malloc(sizeof *d);
    if (!d)
        return -1;
    wc_InitDecodedCert(d, cert.p, cert.n, NULL);
    int result = wc_ParseCert(d, CERT_TYPE, NO_VERIFY, NULL);
    if (!result && (!d->extExtKeyUsageSet || !d->extExtKeyUsageCrit ||
                    d->extExtKeyUsage != EXTKEYUSE_TIMESTAMP || d->isCA))
        result = -1;
    wc_FreeDecodedCert(d);
    free(d);
    return result;
}
#ifdef ESP_PLATFORM
#include "esp_log.h"
#define PKI_VERIFY_DIAGNOSTICS
#endif
#ifdef PKI_VERIFY_DIAGNOSTICS
#define REQUIRE(x)                                                                                 \
    do                                                                                             \
    {                                                                                              \
        if (!(x))                                                                                  \
        {                                                                                          \
            printf("PKI verification failed at line %d\n", __LINE__);                               \
            goto done;                                                                             \
        }                                                                                          \
    } while (0)
#else
#define REQUIRE(x)                                                                                 \
    do                                                                                             \
    {                                                                                              \
        if (!(x))                                                                                  \
            goto done;                                                                             \
    } while (0)
#endif
int wendy_pki_verify_time(const uint8_t *input, size_t size, const uint8_t nonce[32],
                          const uint8_t *roots, size_t roots_size, time_t floor,
                          time_t *verified_time)
{
    int result = -1, count = 0, signer_index = -1;
    WOLFSSL_X509 *certs[8] = {0};
    der rawcerts[8] = {0};
    WOLFSSL_STACK *chain = NULL;
    der all = {input, input, size, size, 0}, resp, status, ci, wrapper, sd, tmp, ec, tst_bytes,
        certset, signers, si, sid, sid_issuer, sid_serial, attrs, sig_alg, sig;
    der tst, imprint, digest, generation, integer_value, serial, issuer, spki = {0};
    time_t when = 0;
    uint8_t hash[32], cert_hash_bytes[32];
    REQUIRE(input && size && size <= 65536 && nonce && roots && roots_size && verified_time);
    REQUIRE(!take(&all, 0x30, &resp) && !all.n && !take(&resp, 0x30, &status) &&
            !number(&status, 0) && !status.n);
    REQUIRE(!take(&resp, 0x30, &ci) && !resp.n &&
            !oid(&ci, signed_data_oid, sizeof signed_data_oid) && !take(&ci, 0xa0, &wrapper) &&
            !ci.n);
    REQUIRE(!take(&wrapper, 0x30, &sd) && !wrapper.n && !number(&sd, 3));
    REQUIRE(!take(&sd, 0x31, &tmp) && !sha256_algorithm(&tmp) && !tmp.n);
    REQUIRE(!take(&sd, 0x30, &ec) && !oid(&ec, tst_oid, sizeof tst_oid) &&
            !take(&ec, 0xa0, &wrapper) && !ec.n);
    REQUIRE(!take(&wrapper, 4, &tst_bytes) && !wrapper.n && !take(&sd, 0xa0, &certset) &&
            !take(&sd, 0x31, &signers) && !sd.n);
    REQUIRE(!take(&signers, 0x30, &si) && !signers.n && !number(&si, 1) && !take(&si, 0x30, &sid));
    REQUIRE(!take(&sid, 0x30, &sid_issuer) && !integer(&sid, &sid_serial) && !sid.n &&
            !sha256_algorithm(&si));
    REQUIRE(!take(&si, 0xa0, &attrs) && !algorithm(&si, &sig_alg) && !take(&si, 4, &sig) && !si.n);
    while (certset.n)
    {
        REQUIRE(count < 8 && !take(&certset, 0x30, &tmp));
        rawcerts[count] = (der){tmp.raw, tmp.raw, tmp.raw_n, tmp.raw_n, 0x30};
        const uint8_t *p = tmp.raw;
        certs[count] = wolfSSL_d2i_X509(NULL, &p, (int)tmp.raw_n);
        REQUIRE(certs[count] && p == tmp.raw + tmp.raw_n);
        REQUIRE(!certificate_parts(rawcerts[count], &serial, &issuer, &spki));
        if (equal(sid_serial, serial) && equal(sid_issuer, issuer))
        {
            REQUIRE(signer_index < 0);
            signer_index = count;
        }
        count++;
    }
    REQUIRE(signer_index >= 0);
    REQUIRE(!certificate_parts(rawcerts[signer_index], &serial, &issuer, &spki));
    REQUIRE(!tsa_eku(rawcerts[signer_index]));
    REQUIRE(!wc_Hash(WC_HASH_TYPE_SHA256, tst_bytes.p, tst_bytes.n, hash, sizeof hash));
    der attrlist = attrs, attr, id, set, value;
    int have_ct = 0, have_md = 0, have_ess = 0;
    while (attrlist.n)
    {
        REQUIRE(!take(&attrlist, 0x30, &attr) && !take(&attr, 6, &id) && !take(&attr, 0x31, &set) &&
                !attr.n);
        if (bytes(id, ct_oid, sizeof ct_oid))
        {
            REQUIRE(!have_ct++ && !oid(&set, tst_oid, sizeof tst_oid) && !set.n);
        }
        else if (bytes(id, md_oid, sizeof md_oid))
        {
            REQUIRE(!have_md++ && !take(&set, 4, &value) && !set.n && bytes(value, hash, 32));
        }
        else if (bytes(id, ess_oid, sizeof ess_oid))
        {
            /* ESSCertIDv2 binds the exact TSA certificate, not just its key. */
            der ess, ids, entry, cert_hash;
            REQUIRE(!have_ess++ && !take(&set, 0x30, &ess) && !set.n && !take(&ess, 0x30, &ids) &&
                    !ess.n);
            REQUIRE(!take(&ids, 0x30, &entry) && !ids.n);
            if (entry.n && entry.p[0] == 0x30)
                REQUIRE(!sha256_algorithm(&entry));
            REQUIRE(!take(&entry, 4, &cert_hash));
            if (entry.n)
            {
                /* RFC 5035 optionally binds the same signer by issuer/serial. */
                der issuer_serial, names, directory, name, ess_serial;
                REQUIRE(!take(&entry, 0x30, &issuer_serial) && !entry.n &&
                        !take(&issuer_serial, 0x30, &names) &&
                        !take(&names, 0xa4, &directory) && !names.n &&
                        !take(&directory, 0x30, &name) && !directory.n &&
                        equal(name, issuer) && !integer(&issuer_serial, &ess_serial) &&
                        !issuer_serial.n && equal(ess_serial, serial));
            }
            REQUIRE(!wc_Hash(WC_HASH_TYPE_SHA256, rawcerts[signer_index].p,
                             rawcerts[signer_index].n, cert_hash_bytes, sizeof cert_hash_bytes) &&
                    bytes(cert_hash, cert_hash_bytes, 32));
        }
    }
    REQUIRE(have_ct == 1 && have_md == 1 && have_ess == 1 &&
            !verify_signature(spki, sig_alg, attrs, sig));
    REQUIRE(!take(&tst_bytes, 0x30, &tst) && !tst_bytes.n && !number(&tst, 1) &&
            !take(&tst, 6, &tmp));
    REQUIRE(!take(&tst, 0x30, &imprint) && !sha256_algorithm(&imprint) &&
            !take(&imprint, 4, &digest) && !imprint.n);
    REQUIRE(!wc_Hash(WC_HASH_TYPE_SHA256, nonce, 32, hash, 32) && bytes(digest, hash, 32));
    REQUIRE(!integer(&tst, &integer_value) && !take(&tst, 24, &generation) &&
            !utc_time(generation, &when) && when >= floor);
    if (tst.n && tst.p[0] == 0x30)
        REQUIRE(!take(&tst, 0x30, &tmp)); /* accuracy */
    if (tst.n && tst.p[0] == 1)
        REQUIRE(!take(&tst, 1, &tmp) && tmp.n == 1 && (tmp.p[0] == 0 || tmp.p[0] == 255));
    REQUIRE(!integer(&tst, &integer_value));
    if (integer_value.n == 33 && integer_value.p[0] == 0)
    {
        integer_value.p++;
        integer_value.n--;
    }
    REQUIRE(bytes(integer_value, nonce, 32));
    if (tst.n && tst.p[0] == 0xa0)
        REQUIRE(!take(&tst, 0xa0, &tmp));
    REQUIRE(!tst.n);
    chain = wolfSSL_sk_X509_new_null();
    REQUIRE(chain);
    for (int i = 0; i < count; i++)
        if (i != signer_index)
            REQUIRE(wolfSSL_sk_X509_push(chain, certs[i]) > 0);
    REQUIRE(!verify_chain(certs[signer_index], chain, roots, roots_size, when));
    *verified_time = when;
    result = 0;
done:
    wolfSSL_sk_X509_free(chain);
    for (int i = 0; i < 8; i++)
        wolfSSL_X509_free(certs[i]);
    return result;
}

int wendy_pki_verify_identity(const uint8_t *pem, size_t size, const uint8_t *roots,
                              size_t roots_size, const uint8_t *key, size_t key_size,
                              const char *principal, time_t now, time_t *expires)
{
    int result = -1, count = 0;
    WOLFSSL_X509 *certs[8] = {0};
    WOLFSSL_STACK *chain = NULL;
    WOLFSSL_EVP_PKEY *private_key = NULL;
    DecodedCert *decoded = NULL;
    char *copy = NULL;
    int decoded_ready = 0;
    REQUIRE(pem && size && size <= 65536 && roots && roots_size && key && key_size && principal &&
            expires);
    copy = calloc(1, size + 1);
    REQUIRE(copy);
    memcpy(copy, pem, size);
    REQUIRE(!memchr(copy, 0, size));
    char *p = copy;
    while (*p)
    {
        while (*p == ' ' || *p == '\r' || *p == '\n' || *p == '\t')
            p++;
        if (!*p)
            break;
        REQUIRE(count < 8 && !strncmp(p, "-----BEGIN CERTIFICATE-----", 27));
        char *end = strstr(p, "-----END CERTIFICATE-----");
        REQUIRE(end);
        end += 25;
        certs[count] = wolfSSL_X509_load_certificate_buffer((uint8_t *)p, (int)(end - p),
                                                            WOLFSSL_FILETYPE_PEM);
        REQUIRE(certs[count]);
        count++;
        p = end;
    }
    REQUIRE(count > 0);
    chain = wolfSSL_sk_X509_new_null();
    REQUIRE(chain);
    for (int i = 1; i < count; i++)
        REQUIRE(wolfSSL_sk_X509_push(chain, certs[i]) > 0);
    REQUIRE(!verify_chain(certs[0], chain, roots, roots_size, now));
    int der_size = 0;
    const uint8_t *leaf = wolfSSL_X509_get_der(certs[0], &der_size);
    REQUIRE(leaf && der_size > 0);
    decoded = malloc(sizeof *decoded);
    REQUIRE(decoded);
    wc_InitDecodedCert(decoded, leaf, der_size, NULL);
    decoded_ready = 1;
    int parse_result = wc_ParseCert(decoded, CERT_TYPE, NO_VERIFY, NULL);

    REQUIRE(!parse_result && !decoded->isCA && decoded->extExtKeyUsageSet);
    REQUIRE((decoded->extExtKeyUsage & (EXTKEYUSE_CLIENT_AUTH | EXTKEYUSE_SERVER_AUTH)) ==
            (EXTKEYUSE_CLIENT_AUTH | EXTKEYUSE_SERVER_AUTH));
    int uris = 0;
    for (DNS_entry *alt = decoded->altNames; alt; alt = alt->next)
        if (alt->type == ASN_URI_TYPE)
        {
            REQUIRE((size_t)alt->len == strlen(principal) &&
                    !memcmp(alt->name, principal, alt->len));
            uris++;
        }
    REQUIRE(uris == 1);
    const uint8_t *key_cursor = key;
    private_key = wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, NULL, &key_cursor, (long)key_size);
    REQUIRE(private_key && key_cursor == key + key_size &&
            wolfSSL_X509_check_private_key(certs[0], private_key) == WOLFSSL_SUCCESS);
    struct tm tm = {0};
    REQUIRE(wolfSSL_ASN1_TIME_to_tm(wolfSSL_X509_get_notAfter(certs[0]), &tm) == WOLFSSL_SUCCESS);
    char date[16];
    REQUIRE(strftime(date, sizeof date, "%Y%m%d%H%M%SZ", &tm) == 15);
    der d = {(uint8_t *)date, NULL, 15, 0, 24};
    REQUIRE(!utc_time(d, expires) && *expires > now);
    result = 0;
done:
    if (decoded_ready)
        wc_FreeDecodedCert(decoded);
    free(decoded);
    wolfSSL_EVP_PKEY_free(private_key);
    wolfSSL_sk_X509_free(chain);
    for (int i = 0; i < 8; i++)
        wolfSSL_X509_free(certs[i]);
    free(copy);
    return result;
}

size_t wendy_pki_time_request(uint8_t out[128], const uint8_t nonce[32])
{
    /* DER RFC 3161, SHA-256(nonce), positive 32-byte nonce, certReq=true. */
    static const uint8_t prefix[] = {0x30, 0x5b, 0x02, 0x01, 0x01, 0x30, 0x31, 0x30,
                                     0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                                     0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    memcpy(out, prefix, sizeof prefix);
    if (wc_Hash(WC_HASH_TYPE_SHA256, nonce, 32, out + sizeof prefix, 32))
        return 0;
    size_t n = sizeof prefix + 32;
    out[n++] = 2;
    out[n++] = 32;
    memcpy(out + n, nonce, 32);
    n += 32;
    out[n++] = 1;
    out[n++] = 1;
    out[n++] = 0xff;
    return n;
}

/* Chain verification is performed by TLS before this identity check. */
int wendy_pki_verify_operator(const uint8_t *der, size_t size, const char *tenant)
{
    if (!der || !size || size > 65536 || !tenant || strlen(tenant) != 36)
        return -1;
    int ok = 0, uris = 0;
    DecodedCert *decoded = malloc(sizeof *decoded);
    if (!decoded)
        return -1;
    wc_InitDecodedCert(decoded, der, size, NULL);
    if (wc_ParseCert(decoded, CERT_TYPE, NO_VERIFY, NULL) == 0 && !decoded->isCA &&
        decoded->extExtKeyUsageSet && (decoded->extExtKeyUsage & EXTKEYUSE_CLIENT_AUTH))
    {
        char prefix[96];
        snprintf(prefix, sizeof prefix, "spiffe://wendy.sh/tenant/%s/operator/", tenant);
        size_t n = strlen(prefix);
        ok = 1;
        for (DNS_entry *alt = decoded->altNames; alt; alt = alt->next)
        {
            if (alt->type != ASN_URI_TYPE)
                continue;
            uris++;
            if ((size_t)alt->len != n + 36 || memcmp(alt->name, prefix, n))
            {
                ok = 0;
                continue;
            }
            for (size_t i = 0; i < 36; i++)
            {
                char c = alt->name[n + i];
                if (i == 8 || i == 13 || i == 18 || i == 23)
                {
                    if (c != '-')
                        ok = 0;
                }
                else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                    ok = 0;
            }
        }
    }
    wc_FreeDecodedCert(decoded);
    free(decoded);
    return ok && uris == 1 ? 0 : -1;
}

/* The grant binds the peer's sole URI, regardless of its certificate's signing
 * algorithm. The TLS handshake has already authenticated the certificate. */
int wendy_lite_peer_hash(const uint8_t *input, size_t size, uint8_t hash[32])
{
    if (!input || !size || size > 65536 || !hash)
        return -1;
    der all = {input, input, size, size, 0}, sequence;
    if (take(&all, 0x30, &sequence) || all.n)
        return -1;
    DecodedCert *decoded = malloc(sizeof *decoded);
    if (!decoded)
        return -1;
    wc_InitDecodedCert(decoded, input, (word32)size, NULL);
    int result = -1, count = 0;
    if (!wc_ParseCert(decoded, CERT_TYPE, NO_VERIFY, NULL))
        for (DNS_entry *alt = decoded->altNames; alt; alt = alt->next)
            if (alt->type == ASN_URI_TYPE)
            {
                count++;
                result = wc_Hash(WC_HASH_TYPE_SHA256, (const uint8_t *)alt->name,
                                 (word32)alt->len, hash, 32);
            }
    wc_FreeDecodedCert(decoded);
    free(decoded);
    return count == 1 && !result ? 0 : -1;
}
