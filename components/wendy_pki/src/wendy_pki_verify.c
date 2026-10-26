#include "wendy_pki_verify.h"
#include "wendy_pki_certificate_policy.h"
#include "wendy_pki_crypto.h"
#include "wendy_operator_auth.h"
#include "wendy_pki_mesh.h"
#include "wendy_peer_identity.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/oid.h>
#include <mbedtls/platform.h>

static pthread_once_t profile_once = PTHREAD_ONCE_INIT;
static mbedtls_x509_crt_profile certificate_profile;
static void init_profile(void)
{
    certificate_profile = mbedtls_x509_crt_profile_default;
    /* esp-pqc uses SHA-512 as the ML-DSA-65 profile marker. The signature
     * verifier still receives the complete certificate, without prehashing. */
    certificate_profile.allowed_mds = MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
        MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512);
    /* Mbed TLS also tests private key-container IDs against allowed_pks.
     * Keep that mask intact; our callback applies the algorithm allowlist. */
    certificate_profile.rsa_min_bitlen = 2048;
}
const mbedtls_x509_crt_profile *wendy_pki_certificate_profile(void)
{
    pthread_once(&profile_once, init_profile);
    return &certificate_profile;
}

static mbedtls_x509_crt *parse_cert(const uint8_t *data, size_t size)
{
    if (wendy_pki_crypto_init()) return NULL;
    mbedtls_x509_crt *cert = mbedtls_calloc(1, sizeof *cert);
    if (!cert) return NULL;
    mbedtls_x509_crt_init(cert);
    if (mbedtls_x509_crt_parse_der(cert, data, size) || cert->raw.len != size) {
        mbedtls_x509_crt_free(cert); mbedtls_free(cert); return NULL;
    }
    return cert;
}
static void free_cert(mbedtls_x509_crt *cert)
{
    if (cert) { mbedtls_x509_crt_free(cert); mbedtls_free(cert); }
}
static int parse_pem(mbedtls_x509_crt *cert, const uint8_t *data, size_t size)
{
    if (!data || !size || size > 65536 || memchr(data, 0, size) ||
        wendy_pki_crypto_init()) return -1;
    uint8_t *copy = calloc(1, size+1);
    if (!copy) return -1;
    memcpy(copy, data, size);
    char *p = (char *)copy;
    int count = 0;
    while (*p) {
        while (*p && strchr(" \t\r\n", *p)) p++;
        if (!*p) break;
        if (++count > 8 || strncmp(p, "-----BEGIN CERTIFICATE-----", 27)) { free(copy); return -1; }
        char *end = strstr(p, "-----END CERTIFICATE-----");
        if (!end) { free(copy); return -1; }
        p = end + 25;
    }
    int r = count ? mbedtls_x509_crt_parse(cert, copy, size+1) : -1;
    free(copy); return r;
}
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
        mbedtls_x509_crt cert;
        mbedtls_x509_crt_init(&cert);
        int parsed = parse_pem(&cert, (const uint8_t *)p, end-p);
        int policy = parsed ? -1 : wendy_pki_certificate_policy(&cert, true);
        int ca = !parsed && cert.MBEDTLS_PRIVATE(ca_istrue) && !cert.next && !policy;
        if (!ca) {
            fprintf(stderr, "PKI CA rejected: parse=%d ca=%d policy=%d\n",
                    parsed, (int)cert.MBEDTLS_PRIVATE(ca_istrue), policy);
        }
        mbedtls_x509_crt_free(&cert);
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
static const uint8_t ec_oid[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1};
static const uint8_t p256_oid[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7};
static const uint8_t p384_oid[] = {0x2b, 0x81, 4, 0, 0x22};
static const uint8_t mldsa65_oid[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 18};
static const uint8_t mldsa87_oid[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 19};

static int public_key_parts(der spki, der *id, der *params, der *key)
{
    if (take(&spki, 0x30, params) || take(params, 6, id) ||
        take(&spki, 3, key) || spki.n || key->n < 2 || key->p[0])
        return -1;
    return 0;
}

static int ec_public_key(der spki, bool allow_p384)
{
    der id, params, key, curve;
    return !public_key_parts(spki, &id, &params, &key) &&
        bytes(id, ec_oid, sizeof ec_oid) && !take(&params, 6, &curve) && !params.n &&
        (bytes(curve, p256_oid, sizeof p256_oid) ||
         (allow_p384 && bytes(curve, p384_oid, sizeof p384_oid)));
}

int wendy_pki_certificate_policy(const mbedtls_x509_crt *cert, bool trust_anchor)
{
    if (!cert || !cert->pk_raw.p || !cert->pk_raw.len)
        return -1;
    der raw = {cert->pk_raw.p, cert->pk_raw.p, cert->pk_raw.len, cert->pk_raw.len, 0};
    der spki, id, params, key;
    if (take(&raw, 0x30, &spki) || raw.n || public_key_parts(spki, &id, &params, &key))
        return -1;
    const uint8_t rsa_oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1};
    const uint8_t rsa_pss_oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 10};
    if (bytes(id, ec_oid, sizeof ec_oid)) {
        if (mbedtls_pk_get_bitlen(&cert->pk) < 256) return -1;
    } else if (bytes(id, rsa_oid, sizeof rsa_oid) || bytes(id, rsa_pss_oid, sizeof rsa_pss_oid)) {
        if (mbedtls_pk_get_bitlen(&cert->pk) < 2048) return -1;
    } else if (bytes(id, mldsa65_oid, sizeof mldsa65_oid)) {
        if (params.n || key.n != 1953) return -1;
    } else if (bytes(id, mldsa87_oid, sizeof mldsa87_oid)) {
        /* Existing PKI roots and intermediates use ML-DSA-87. Operator and
         * timestamp signing keys remain on ML-DSA-65. */
        if (params.n || key.n != 2593 || !cert->MBEDTLS_PRIVATE(ca_istrue)) return -1;
    } else {
        return -1;
    }
    if (trust_anchor) return 0;

    der input = {cert->raw.p, cert->raw.p, cert->raw.len, cert->raw.len, 0};
    der outer, tbs, signature_algorithm;
    if (take(&input, 0x30, &outer) || input.n || take(&outer, 0x30, &tbs) ||
        take(&outer, 0x30, &signature_algorithm) || take(&signature_algorithm, 6, &id))
        return -1;
    if (bytes(id, mldsa65_oid, sizeof mldsa65_oid) ||
        bytes(id, mldsa87_oid, sizeof mldsa87_oid))
        return signature_algorithm.n ? -1 : 0;
    const uint8_t rsa_prefix[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1};
    const uint8_t ec_prefix[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3};
    if ((id.n == 9 && !memcmp(id.p, rsa_prefix, sizeof rsa_prefix) &&
         id.p[8] >= 11 && id.p[8] <= 13) ||
        (id.n == 8 && !memcmp(id.p, ec_prefix, sizeof ec_prefix) &&
         id.p[7] >= 2 && id.p[7] <= 4))
        return 0;
    if (bytes(id, rsa_pss_oid, sizeof rsa_pss_oid) &&
        (cert->MBEDTLS_PRIVATE(sig_md) == MBEDTLS_MD_SHA256 ||
         cert->MBEDTLS_PRIVATE(sig_md) == MBEDTLS_MD_SHA384 ||
         cert->MBEDTLS_PRIVATE(sig_md) == MBEDTLS_MD_SHA512))
        return 0;
    return -1;
}

static int signature_algorithm(der *in, der *id)
{
    der seq, nil;
    if (take(in, 0x30, &seq) || take(&seq, 6, id)) return -1;
    // RFC 9881 requires absent parameters for pure ML-DSA AlgorithmIdentifier.
    if (bytes(*id, mldsa65_oid, sizeof mldsa65_oid)) return seq.n ? -1 : 0;
    if (seq.n && (take(&seq, 5, &nil) || nil.n)) return -1;
    return seq.n ? -1 : 0;
}

static int verify_signature(der spki, der sig_alg, der attrs, der sig)
{
    const uint8_t es256[] = {0x2a,0x86,0x48,0xce,0x3d,4,3,2};
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    uint8_t *message = malloc(attrs.raw_n), hash[32];
    int result = -1;
    if (!message) goto done;
    memcpy(message, attrs.raw, attrs.raw_n); message[0] = 0x31;
    if (mbedtls_pk_parse_public_key(&key, spki.raw, spki.raw_n)) goto done;
    if (bytes(sig_alg, mldsa65_oid, sizeof mldsa65_oid)) {
        der key_id, params, raw_key;
        if (public_key_parts(spki, &key_id, &params, &raw_key) || params.n ||
            !equal(key_id, sig_alg) || raw_key.n != 1953 || sig.n != 3309)
            goto done;
        // Pure ML-DSA signs the complete DER SET, with an empty context.
        result = mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_MLDSA65, &key,
            MBEDTLS_MD_NONE, message, attrs.raw_n, sig.p, sig.n);
    } else if (bytes(sig_alg, es256, sizeof es256) && ec_public_key(spki, true)) {
        if (wendy_pki_sha256(message, attrs.raw_n, hash)) goto done;
        result = mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_ECDSA, &key,
            MBEDTLS_MD_SHA256, hash, sizeof hash, sig.p, sig.n);
    }
done:
    free(message); mbedtls_pk_free(&key); return result;
}
static int cert_time(const mbedtls_x509_time *t, time_t *out)
{
    char text[16];
    if (snprintf(text, sizeof text, "%04d%02d%02d%02d%02d%02dZ",
        t->year,t->mon,t->day,t->hour,t->min,t->sec) != 15) return -1;
    return utc_time((der){(uint8_t *)text, NULL, 15, 0, 24}, out);
}
struct verification_time {
    time_t now;
    const mbedtls_x509_crt *anchors;
    time_t expires;
};
static bool valid_at(const mbedtls_x509_crt *cert, time_t now)
{
    time_t start, end;
    return !cert_time(&cert->valid_from, &start) && !cert_time(&cert->valid_to, &end) &&
        start <= now && end > now;
}
static int verify_at(void *context, mbedtls_x509_crt *cert, int depth, uint32_t *flags)
{
    (void)depth;
    struct verification_time *verification = context;
    time_t now = verification->now, start, end;
    bool anchor = false;
    for (const mbedtls_x509_crt *a = verification->anchors; a; a = a->next)
        if (a->raw.len == cert->raw.len && !memcmp(a->raw.p, cert->raw.p, a->raw.len))
            anchor = true;
    if (wendy_pki_certificate_policy(cert, anchor)) *flags |= MBEDTLS_X509_BADCERT_OTHER;
    // Replace only wall-clock date flags with checks at the authenticated time.
    *flags &= ~(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
    if (cert_time(&cert->valid_from, &start) || start > now) *flags |= MBEDTLS_X509_BADCERT_FUTURE;
    if (cert_time(&cert->valid_to, &end) || end <= now) *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
    else if (!verification->expires || end < verification->expires) verification->expires=end;
    return 0;
}
static int verify_chain(mbedtls_x509_crt *leaf, mbedtls_x509_crt **certs, int count,
    const uint8_t *roots, size_t size, time_t now, time_t *expires)
{
    mbedtls_x509_crt chain, *anchors = mbedtls_calloc(1, sizeof *anchors);
    mbedtls_x509_crt_init(&chain);
    if (anchors) mbedtls_x509_crt_init(anchors);
    int result = -1; uint32_t flags = 0;
    if (!anchors || wendy_pki_verify_roots(roots, size) || parse_pem(anchors, roots, size) ||
        mbedtls_x509_crt_parse_der(&chain, leaf->raw.p, leaf->raw.len)) goto done;
    /* Mbed TLS prefers parents valid at the system clock before calling the
     * verification callback. Only offer candidates valid at the signed time. */
    mbedtls_x509_crt **candidate = &anchors;
    while (*candidate) {
        mbedtls_x509_crt *cert = *candidate;
        if (valid_at(cert, now)) {
            candidate = &cert->next;
        } else {
            *candidate = cert->next;
            cert->next = NULL;
            free_cert(cert);
        }
    }
    if (!anchors) goto done;
    for (int i=0; i<count; i++) if (certs[i] != leaf && valid_at(certs[i], now) &&
        mbedtls_x509_crt_parse_der(&chain, certs[i]->raw.p, certs[i]->raw.len)) goto done;
    struct verification_time verification = {.now=now, .anchors=anchors};
    if (!mbedtls_x509_crt_verify_with_profile(&chain, anchors, NULL,
            wendy_pki_certificate_profile(), NULL, &flags, verify_at, &verification) && !flags)
    {
        if (expires) *expires=verification.expires;
        result = 0;
    }
done:
    mbedtls_x509_crt_free(&chain); free_cert(anchors); return result;
}
static int tsa_eku(der cert)
{
    mbedtls_x509_crt *crt = parse_cert(cert.p, cert.n);
    if (!crt) return -1;
    int valid = !crt->MBEDTLS_PRIVATE(ca_istrue) && crt->ext_key_usage.buf.p && !crt->ext_key_usage.next &&
        MBEDTLS_OID_CMP(MBEDTLS_OID_TIME_STAMPING, &crt->ext_key_usage.buf) == 0;
    free_cert(crt);
    if (!valid) return -1;
    // RFC 3161 requires a critical, exclusively timestamping EKU.
    der seq, tbs, item, extensions, ext, id, critical, value;
    if (take(&cert, 0x30, &seq) || take(&seq, 0x30, &tbs)) return -1;
    while (tbs.n && tbs.p[0] != 0xa3) {
        if (take(&tbs, tbs.p[0], &item)) return -1;
    }
    if (take(&tbs, 0xa3, &item) || take(&item, 0x30, &extensions) || item.n || tbs.n) return -1;
    const uint8_t eku[] = {0x55,0x1d,0x25};
    int found = 0;
    while (extensions.n) {
        if (take(&extensions, 0x30, &ext) || take(&ext, 6, &id)) return -1;
        if (bytes(id, eku, sizeof eku)) {
            if (found++ || take(&ext, 1, &critical) || critical.n != 1 || critical.p[0] != 255 ||
                take(&ext, 4, &value) || ext.n) return -1;
        }
    }
    return found == 1 ? 0 : -1;
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
    mbedtls_x509_crt *certs[8] = {0};
    der rawcerts[8] = {0};
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
    REQUIRE(!take(&si, 0xa0, &attrs) && !signature_algorithm(&si, &sig_alg) && !take(&si, 4, &sig) && !si.n);
    while (certset.n)
    {
        REQUIRE(count < 8 && !take(&certset, 0x30, &tmp));
        rawcerts[count] = (der){tmp.raw, tmp.raw, tmp.raw_n, tmp.raw_n, 0x30};
        certs[count] = parse_cert(tmp.raw, tmp.raw_n);
        REQUIRE(certs[count]);
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
    REQUIRE(!wendy_pki_sha256(tst_bytes.p, tst_bytes.n, hash));
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
                /* RFC 5035 optionally identifies the same certificate by issuer
                 * and serial. Accept one directoryName and check both fields. */
                der issuer_serial, names, directory, name, ess_serial;
                REQUIRE(!take(&entry, 0x30, &issuer_serial) && !entry.n &&
                        !take(&issuer_serial, 0x30, &names) &&
                        !take(&names, 0xa4, &directory) && !names.n &&
                        !take(&directory, 0x30, &name) && !directory.n &&
                        equal(name, issuer) && !integer(&issuer_serial, &ess_serial) &&
                        !issuer_serial.n && equal(ess_serial, serial));
            }
            REQUIRE(!wendy_pki_sha256(rawcerts[signer_index].p, rawcerts[signer_index].n, cert_hash_bytes) &&
                    bytes(cert_hash, cert_hash_bytes, 32));
        }
    }
    REQUIRE(have_ct == 1 && have_md == 1 && have_ess == 1 &&
            !verify_signature(spki, sig_alg, attrs, sig));
    REQUIRE(!take(&tst_bytes, 0x30, &tst) && !tst_bytes.n && !number(&tst, 1) &&
            !take(&tst, 6, &tmp));
    REQUIRE(!take(&tst, 0x30, &imprint) && !sha256_algorithm(&imprint) &&
            !take(&imprint, 4, &digest) && !imprint.n);
    REQUIRE(!wendy_pki_sha256(nonce, 32, hash) && bytes(digest, hash, 32));
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
    REQUIRE(!verify_chain(certs[signer_index], certs, count, roots, roots_size, when, NULL));
    *verified_time = when;
    result = 0;
done:
    for (int i = 0; i < 8; i++)
        free_cert(certs[i]);
    return result;
}

static int single_uri(mbedtls_x509_crt *crt, const char *expected)
{
    int count = 0;
    for (const mbedtls_x509_sequence *a = &crt->subject_alt_names; a && a->buf.p; a=a->next) {
        mbedtls_x509_subject_alternative_name san;
        if (mbedtls_x509_parse_subject_alt_name(&a->buf, &san) ||
            san.type != MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) continue;
        if (san.san.unstructured_name.len != strlen(expected) ||
            memcmp(san.san.unstructured_name.p, expected, strlen(expected))) return -1;
        count++;
    }
    return count == 1 ? 0 : -1;
}
static int has_eku(mbedtls_x509_crt *crt, const char *oid, size_t n)
{
    for (const mbedtls_x509_sequence *a=&crt->ext_key_usage; a && a->buf.p; a=a->next)
        if (a->buf.len == n && !memcmp(a->buf.p, oid, n)) return 1;
    return 0;
}
int wendy_pki_verify_identity(const uint8_t *pem, size_t size, const uint8_t *roots,
    size_t roots_size, const uint8_t *key, size_t key_size, const char *principal,
    time_t now, time_t *expires)
{
    if (!pem || !size || size>65536 || memchr(pem,0,size) || !roots || !roots_size ||
        !key || !key_size || !principal || !expires) return -1;
    mbedtls_x509_crt chain;
    mbedtls_pk_context private_key;
    mbedtls_x509_crt_init(&chain); mbedtls_pk_init(&private_key);
    int result = -1, count = 0;
    mbedtls_x509_crt *certs[8];
    der leaf_der, leaf_spki, serial, issuer, key_der = {key, key, key_size, key_size, 0}, key_sequence;
    if (take(&key_der, 0x30, &key_sequence) || key_der.n) goto done;
    if (parse_pem(&chain, pem, size)) goto done;
    leaf_der = (der){chain.raw.p, chain.raw.p, chain.raw.len, chain.raw.len, 0};
    if (certificate_parts(leaf_der, &serial, &issuer, &leaf_spki) ||
        !ec_public_key(leaf_spki, false)) goto done;
    for (mbedtls_x509_crt *c=&chain; c; c=c->next) {
        if (count==8) goto done;
        certs[count++]=c;
    }
    if (!count || verify_chain(&chain, certs, count, roots, roots_size, now, NULL) || chain.MBEDTLS_PRIVATE(ca_istrue) ||
        !has_eku(&chain, MBEDTLS_OID_CLIENT_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH)) ||
        !has_eku(&chain, MBEDTLS_OID_SERVER_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) ||
        single_uri(&chain, principal) ||
        mbedtls_pk_parse_key(&private_key,key,key_size,NULL,0) ||
        mbedtls_pk_check_pair(&chain.pk,&private_key) ||
        cert_time(&chain.valid_to, expires) || *expires<=now) goto done;
    result = 0;
done:
    mbedtls_pk_free(&private_key); mbedtls_x509_crt_free(&chain); return result;
}

int wendy_pki_mesh_chain(const uint8_t* const* data, const size_t* sizes, size_t count,
    const uint8_t* roots, size_t roots_size, const char* tenant, time_t now,
    struct wendy_pki_mesh_peer* out)
{
    if (!data || !sizes || !count || count > 8 || !roots || !roots_size || !tenant
        || !wendy_identity_uuid((const unsigned char*)tenant, strlen(tenant)) || !out || now <= 0)
        return -1;
    mbedtls_x509_crt* certs[8] = { 0 };
    int result = -1;
    size_t total = 0;
    /* An ML-DSA-65 key makes a peer about 2 KiB. Keep it off the TLS and mesh
     * task stacks, which also run the chain's ML-DSA verification. */
    struct wendy_pki_mesh_peer* peer = calloc(1, sizeof *peer);
    if (!peer)
        return -1;
    for (size_t i = 0; i < count; i++)
    {
        if (!sizes[i] || sizes[i] > 32768 || total > 32768 - sizes[i])
            goto done;
        total += sizes[i];
        certs[i] = parse_cert(data[i], sizes[i]);
        if (!certs[i] || certs[i]->raw.len != sizes[i])
            goto done;
    }
    mbedtls_x509_crt* leaf = certs[0];
    if (verify_chain(leaf, certs, (int)count, roots, roots_size, now, &peer->expires)
        || wendy_peer_auth_role(leaf, tenant) != WENDY_PEER_ROLE_DEVICE
        || !has_eku(leaf, MBEDTLS_OID_SERVER_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH))
        || peer->expires <= now)
        goto done;
    unsigned uris = 0;
    for (const mbedtls_x509_sequence* a = &leaf->subject_alt_names; a && a->buf.p; a = a->next)
    {
        mbedtls_x509_subject_alternative_name san;
        if (mbedtls_x509_parse_subject_alt_name(&a->buf, &san)
            || san.type != MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER)
            continue;
        const uint8_t* uri = san.san.unstructured_name.p;
        size_t n = san.san.unstructured_name.len;
        if (n != 105 || memcmp(uri, "spiffe://wendy.sh/tenant/", 25) || memcmp(uri + 25, tenant, 36)
            || memcmp(uri + 61, "/device/", 8) || !wendy_identity_uuid(uri + 69, 36))
            goto done;
        /* Length/offset checks below are deliberately derived from the prefix,
         * rather than relying on a device-name parser that also permits paths. */
        uris++;
    }
    /* Extract the exact UUID using the fixed canonical principal grammar. */
    if (uris != 1)
        goto done;
    for (const mbedtls_x509_sequence* a = &leaf->subject_alt_names; a && a->buf.p; a = a->next)
    {
        mbedtls_x509_subject_alternative_name san;
        if (!mbedtls_x509_parse_subject_alt_name(&a->buf, &san)
            && san.type == MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER)
            memcpy(peer->device, san.san.unstructured_name.p + 69, 36);
    }
    der raw = { leaf->raw.p, leaf->raw.p, leaf->raw.len, leaf->raw.len, 0 }, serial, issuer, spki;
    der id, params, key;
    if (certificate_parts(raw, &serial, &issuer, &spki))
        goto done;
    if (ec_public_key(spki, false))
    {
        int n = mbedtls_pk_write_pubkey_der(&leaf->pk, peer->spki, sizeof peer->spki);
        if (n <= 0 || (size_t)n > sizeof peer->spki)
            goto done;
        memmove(peer->spki, peer->spki + sizeof peer->spki - n, n);
        peer->spki_size = n;
    }
    else
    {
        /* Linux routers can hold pure ML-DSA-65 device keys. Keep the exact
         * certified SPKI; ML-DSA-44/87 and other algorithms stay rejected. */
        if (public_key_parts(spki, &id, &params, &key)
            || !bytes(id, mldsa65_oid, sizeof mldsa65_oid) || params.n || key.n != 1953
            || spki.raw_n > sizeof peer->spki)
            goto done;
        memcpy(peer->spki, spki.raw, spki.raw_n);
        peer->spki_size = spki.raw_n;
    }
    *out = *peer;
    result = 0;
done:
    for (size_t i = 0; i < count; i++)
        free_cert(certs[i]);
    free(peer);
    return result;
}

size_t wendy_pki_time_request(uint8_t out[128], const uint8_t nonce[32])
{
    /* DER RFC 3161, SHA-256(nonce), positive 32-byte nonce, certReq=true. */
    static const uint8_t prefix[] = {0x30, 0x5b, 0x02, 0x01, 0x01, 0x30, 0x31, 0x30,
                                     0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                                     0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    memcpy(out, prefix, sizeof prefix);
    if (wendy_pki_sha256(nonce, 32, out + sizeof prefix))
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
enum wendy_peer_role wendy_pki_verify_peer(const uint8_t *data, size_t size,
                                           const char *tenant)
{
    if (!data || !size || size>65536 || !tenant || strlen(tenant)!=36)
        return WENDY_PEER_ROLE_NONE;
    mbedtls_x509_crt *crt = parse_cert(data, size);
    if (!crt) return WENDY_PEER_ROLE_NONE;
    enum wendy_peer_role result = crt->raw.len == size &&
        !wendy_pki_certificate_policy(crt, false) ? wendy_peer_auth_role(crt, tenant)
                                                 : WENDY_PEER_ROLE_NONE;
    free_cert(crt); return result;
}

int wendy_pki_verify_operator(const uint8_t *data, size_t size, const char *tenant)
{
    return wendy_pki_verify_peer(data, size, tenant) == WENDY_PEER_ROLE_OPERATOR ? 0 : -1;
}
