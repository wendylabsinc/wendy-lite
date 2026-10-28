#include "wendy_pki_verify.h"
#include "wendy_pki_alloc.h"
#include "wendy_pki_work.h"
#include "wendy_cert_bundle.h"
#include "wendy_pki_parsed_identity.h"
#include "wendy_pki_certificate_policy.h"
#include "wendy_pki_crypto.h"
#include "wendy_operator_auth.h"
#include "wendy_pki_mesh.h"
#include "wendy_pki_operator.h"
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
/* Mesh verification consumes an immutable caller-owned DER array and returns
 * only copied identity metadata. Borrow those bytes until the synchronous
 * verification call ends, avoiding a second complete public-chain payload. */
static mbedtls_x509_crt *parse_cert_borrowed(const uint8_t *data, size_t size)
{
    if (wendy_pki_crypto_init()) return NULL;
    mbedtls_x509_crt *cert = mbedtls_calloc(1, sizeof *cert);
    if (!cert) return NULL;
    mbedtls_x509_crt_init(cert);
    if (mbedtls_x509_crt_parse_der_nocopy(cert, data, size) || cert->raw.len != size) {
        mbedtls_x509_crt_free(cert); mbedtls_free(cert); return NULL;
    }
    return cert;
}
static void free_cert(mbedtls_x509_crt *cert)
{
    if (cert) { mbedtls_x509_crt_free(cert); mbedtls_free(cert); }
}
/* PEM is an import boundary only. Library calls always consume DER. Borrowed
 * DER must outlive the parsed chain; imported PEM necessarily uses copies. */
int pki_parse_certificate_bundle(mbedtls_x509_crt *cert,const uint8_t *data,
                                 size_t size,bool borrow)
{
    if(!data || !size || size>65536 || wendy_pki_crypto_init())return -1;
    uint8_t *imported=NULL;
    if(data[0]!=0x30){
        size_t bytes=0;
        if(wendy_cert_bundle_measure(data,size,&bytes))return -1;
        imported=pki_owned_malloc(bytes);
        if(!imported)return MBEDTLS_ERR_X509_ALLOC_FAILED;
        if(wendy_cert_bundle_import(data,size,imported,bytes,&bytes)){
            pki_owned_free(imported);return -1;
        }
        data=imported;size=bytes;borrow=false;
    }
    size_t offset=0,bytes;const uint8_t *der;unsigned count=0;int next,result=0;
    while((next=wendy_cert_der_next(data,size,&offset,&der,&bytes))==1){
        if(++count>8){result=-1;break;}
        result=borrow ? mbedtls_x509_crt_parse_der_nocopy(cert,der,bytes):
                        mbedtls_x509_crt_parse_der(cert,der,bytes);
        if(result)break;
    }
    pki_owned_free(imported);return result ? result : next<0 || !count ? -1:0;
}
static int verify_roots_direct(const uint8_t *data,size_t size)
{
    if(!data || !size || size>16384 || wendy_pki_crypto_init())return -1;
    uint8_t *imported=NULL;
    if(data[0]!=0x30){
        size_t bytes=0;
        if(wendy_cert_bundle_measure(data,size,&bytes))return -1;
        imported=pki_owned_malloc(bytes);
        if(!imported)return -1;
        if(wendy_cert_bundle_import(data,size,imported,bytes,&bytes)){
            pki_owned_free(imported);return -1;
        }
        data=imported;size=bytes;
    }
    /* Check one borrowed anchor at a time, without a duplicate DER payload. */
    size_t offset=0,bytes;const uint8_t *der;unsigned count=0;int next,result=-1;
    while((next=wendy_cert_der_next(data,size,&offset,&der,&bytes))==1){
        if(++count>8)goto done;
        mbedtls_x509_crt cert;mbedtls_x509_crt_init(&cert);
        int parsed=mbedtls_x509_crt_parse_der_nocopy(&cert,der,bytes);
        int valid=!parsed && cert.MBEDTLS_PRIVATE(ca_istrue) && !cert.next &&
                   !wendy_pki_certificate_policy(&cert,true);
        mbedtls_x509_crt_free(&cert);
        if(!valid)goto done;
    }
    if(!next && count)result=0;
done:
    pki_owned_free(imported);return result;
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

static int own_public_key(der spki)
{
    if (ec_public_key(spki, false)) return 1;
#if defined(MBEDTLS_MLDSA65_PRIVATE_KEY)
    der id, params, key;
    return !public_key_parts(spki, &id, &params, &key) &&
        bytes(id, mldsa65_oid, sizeof mldsa65_oid) && !params.n && key.n == 1953;
#else
    return 0;
#endif
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
    uint8_t *message = pki_owned_malloc(attrs.raw_n), hash[32];
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
    pki_owned_free(message); mbedtls_pk_free(&key); return result;
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
static int verify_chain_parsed(mbedtls_x509_crt *leaf, mbedtls_x509_crt **certs, int count,
    mbedtls_x509_crt *anchors, time_t now, time_t *expires)
{
    if (!leaf || count < 1 || count > 8) return -1;
    mbedtls_x509_crt *valid[8], *anchor_next[8];
    size_t valid_count = 0, anchor_count = 0;
    for (mbedtls_x509_crt *root=anchors; root; root=root->next) {
        if (++anchor_count > 8 || !root->raw.len || !root->MBEDTLS_PRIVATE(ca_istrue) ||
            wendy_pki_certificate_policy(root,true)) return -1;
        for (int i=0;i<count;i++) if (root==certs[i]) return -1;
        if (valid_at(root,now)) valid[valid_count++]=root;
    }
    if (!valid_count) return -1;
    mbedtls_x509_crt *path[8] = {leaf}, *saved_next[8];
    size_t path_count = 1;
    bool have_leaf = false;
    for (int i = 0; i < count; i++) {
        if (certs[i] == leaf) { have_leaf = true; continue; }
        if (!valid_at(certs[i], now)) continue;
        if (path_count == 8) return -1;
        for (size_t j = 0; j < path_count; j++) if (path[j] == certs[i]) return -1;
        path[path_count++] = certs[i];
    }
    if (!have_leaf) return -1;
    /* Both lists belong exclusively to the caller. Offer only candidates
     * valid at signed time, then restore every link even on verifier failure. */
    for (size_t i=0;i<valid_count;i++) {
        anchor_next[i]=valid[i]->next;
        valid[i]->next=i+1<valid_count ? valid[i+1] : NULL;
    }
    for (size_t i = 0; i < path_count; i++) {
        saved_next[i] = path[i]->next;
        path[i]->next = i + 1 < path_count ? path[i+1] : NULL;
    }
    struct verification_time verification = {.now=now, .anchors=valid[0]};
    uint32_t flags=0;
    int verified = mbedtls_x509_crt_verify_with_profile(leaf, valid[0], NULL,
        wendy_pki_certificate_profile(), NULL, &flags, verify_at, &verification);
    for (size_t i = 0; i < path_count; i++) path[i]->next = saved_next[i];
    for (size_t i=0;i<valid_count;i++) valid[i]->next=anchor_next[i];
    if (verified || flags) return -1;
    if (expires) *expires=verification.expires;
    return 0;
}
static int verify_chain(mbedtls_x509_crt *leaf, mbedtls_x509_crt **certs, int count,
    const uint8_t *roots, size_t size, time_t now, time_t *expires)
{
    if (!roots || !size || size>16384) return -1;
    /* The caller's DER bundle remains immutable until this synchronous path
     * check ends. Borrow its payload while checking policy and signatures. */
    mbedtls_x509_crt anchors;
    mbedtls_x509_crt_init(&anchors);
    int result=pki_parse_certificate_bundle(&anchors,roots,size,true) ? -1 :
        verify_chain_parsed(leaf,certs,count,&anchors,now,expires);
    mbedtls_x509_crt_free(&anchors);
    return result;
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
static int verify_time_direct(const uint8_t *input, size_t size, const uint8_t nonce[32],
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
    /* RFC 3161 nonces are positive integers, not fixed-width octet strings.
     * DER removes leading zeroes and adds a sign octet for a high bit. */
    if (integer_value.n > 1 && integer_value.p[0] == 0) {
        integer_value.p++;
        integer_value.n--;
    }
    REQUIRE(integer_value.n <= 32);
    size_t nonce_padding = 32 - integer_value.n;
    for (size_t i = 0; i < nonce_padding; i++) REQUIRE(nonce[i] == 0);
    REQUIRE(bytes(integer_value, nonce + nonce_padding, integer_value.n));
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
int pki_identity_encoding(const uint8_t *pem, size_t size, const uint8_t *key, size_t key_size)
{
    size_t bytes=0;
    return !pem || !size || pem[0]!=0x30 || wendy_cert_bundle_measure(pem,size,&bytes) ||
           pki_key_encoding(key,key_size) ? -1:0;
}
int pki_key_encoding(const uint8_t *key,size_t key_size)
{
    if (!key || !key_size) return -1;
    der key_der = {key, key, key_size, key_size, 0}, sequence;
    return take(&key_der, 0x30, &sequence) || key_der.n ? -1 : 0;
}
int pki_verify_parsed_identity(mbedtls_x509_crt *chain, mbedtls_pk_context *key,
    const uint8_t *roots, size_t roots_size, mbedtls_x509_crt *anchors, const char *principal,
    time_t now, time_t *expires)
{
    if (!chain || !key || !roots || !roots_size || !principal || !expires) return -1;
    int count = 0;
    time_t chain_expires = 0;
    mbedtls_x509_crt *certs[8];
    der leaf_der = {chain->raw.p, chain->raw.p, chain->raw.len, chain->raw.len, 0};
    der leaf_spki, serial, issuer;
    if (certificate_parts(leaf_der, &serial, &issuer, &leaf_spki) ||
        !own_public_key(leaf_spki)) return -1;
    for (mbedtls_x509_crt *c=chain; c; c=c->next) {
        if (count==8) return -1;
        certs[count++]=c;
    }
    int verified = anchors ? verify_chain_parsed(chain,certs,count,anchors,now,&chain_expires) :
        verify_chain(chain,certs,count,roots,roots_size,now,&chain_expires);
    if (!count || verified ||
        chain->MBEDTLS_PRIVATE(ca_istrue) ||
        !has_eku(chain, MBEDTLS_OID_CLIENT_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH)) ||
        !has_eku(chain, MBEDTLS_OID_SERVER_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) ||
        single_uri(chain, principal) || mbedtls_pk_check_pair(&chain->pk,key) ||
        cert_time(&chain->valid_to, expires) || *expires<=now || chain_expires<=now) return -1;
    if (chain_expires < *expires) *expires = chain_expires;
    return 0;
}
static int verify_identity_direct(const uint8_t *pem, size_t size, const uint8_t *roots,
    size_t roots_size, const uint8_t *key, size_t key_size, const char *principal,
    time_t now, time_t *expires)
{
    if (!pem || !size || size>65536 || !roots || !roots_size ||
        !key || !key_size || !principal || !expires) return -1;
    mbedtls_x509_crt chain;
    mbedtls_pk_context private_key;
    mbedtls_x509_crt_init(&chain); mbedtls_pk_init(&private_key);
    int result = -1;
    der key_der = {key, key, key_size, key_size, 0}, key_sequence;
    if (take(&key_der, 0x30, &key_sequence) || key_der.n ||
        pki_parse_certificate_bundle(&chain,pem,size,true) || mbedtls_pk_parse_key(&private_key,key,key_size,NULL,0)) goto done;
    result = pki_verify_parsed_identity(&chain,&private_key,roots,roots_size,NULL,principal,now,expires);
done:
    mbedtls_pk_free(&private_key); mbedtls_x509_crt_free(&chain); return result;
}

static int mesh_chain(const uint8_t* const* data, const size_t* sizes, size_t count,
    const uint8_t* roots, size_t roots_size, mbedtls_x509_crt *anchors, const char* tenant, time_t now,
    struct wendy_pki_mesh_peer* out)
{
    if (!data || !sizes || !count || count > 8 || ((!roots || !roots_size) && !anchors) || !tenant
        || !wendy_identity_uuid((const unsigned char*)tenant, strlen(tenant)) || !out || now <= 0)
        return -1;
    mbedtls_x509_crt* certs[8] = { 0 };
    int result = -1;
    size_t total = 0;
    /* An ML-DSA-65 key makes a peer about 2 KiB. Keep it off the TLS and mesh
     * task stacks, which also run the chain's ML-DSA verification. */
    struct wendy_pki_mesh_peer* peer = pki_owned_calloc(1, sizeof *peer);
    if (!peer)
        return -1;
    for (size_t i = 0; i < count; i++)
    {
        if (!sizes[i] || sizes[i] > 32768 || total > 32768 - sizes[i])
            goto done;
        total += sizes[i];
        certs[i] = parse_cert_borrowed(data[i], sizes[i]);
        if (!certs[i] || certs[i]->raw.len != sizes[i])
            goto done;
    }
    mbedtls_x509_crt* leaf = certs[0];
    int verified=anchors ? verify_chain_parsed(leaf,certs,(int)count,anchors,now,&peer->expires):
        verify_chain(leaf,certs,(int)count,roots,roots_size,now,&peer->expires);
    if (verified
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
    pki_owned_free(peer);
    return result;
}

size_t wendy_pki_time_request(uint8_t out[128], const uint8_t nonce[32])
{
    /* DER RFC 3161, SHA-256 of all 32 nonce bytes, positive INTEGER,
     * certReq=true. Preserve the nonce value with canonical sign padding. */
    static const uint8_t prefix[] = {0x30, 0x5b, 0x02, 0x01, 0x01, 0x30, 0x31, 0x30,
                                     0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                                     0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    memcpy(out, prefix, sizeof prefix);
    if (wendy_pki_sha256(nonce, 32, out + sizeof prefix))
        return 0;
    size_t n = sizeof prefix + 32;
    size_t first = 0;
    while (first < 31 && nonce[first] == 0) first++;
    size_t bytes = 32 - first;
    bool sign_padding = (nonce[first] & 0x80) != 0;
    out[n++] = 2;
    out[n++] = (uint8_t)(bytes + sign_padding);
    if (sign_padding) out[n++] = 0;
    memcpy(out + n, nonce + first, bytes);
    n += bytes;
    out[n++] = 1;
    out[n++] = 1;
    out[n++] = 0xff;
    out[1] = (uint8_t)(n - 2);
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

int wendy_pki_mesh_chain(const uint8_t *const *data,const size_t *sizes,size_t count,
    const uint8_t *roots,size_t roots_size,const char *tenant,time_t now,
    struct wendy_pki_mesh_peer *peer)
{
    return mesh_chain(data,sizes,count,roots,roots_size,NULL,tenant,now,peer);
}
int pki_mesh_chain_anchors(const uint8_t *const *data,const size_t *sizes,size_t count,
    mbedtls_x509_crt *anchors,const char *tenant,time_t now,struct wendy_pki_mesh_peer *peer)
{
    return mesh_chain(data,sizes,count,NULL,0,anchors,tenant,now,peer);
}

struct roots_cpu {const uint8_t *data;size_t size;int result;};
static void roots_cpu(void *context){struct roots_cpu *j=context;j->result=verify_roots_direct(j->data,j->size);}
int wendy_pki_verify_roots(const uint8_t *data,size_t size)
{struct roots_cpu j={data,size,-1};return wendy_pki_work_run(roots_cpu,&j) ? -1:j.result;}
struct time_cpu {const uint8_t *input,*nonce,*roots;size_t size,roots_size;time_t floor,*verified;int result;};
static void time_cpu(void *context){struct time_cpu *j=context;j->result=verify_time_direct(j->input,j->size,j->nonce,j->roots,j->roots_size,j->floor,j->verified);}
int wendy_pki_verify_time(const uint8_t *input,size_t size,const uint8_t nonce[32],const uint8_t *roots,size_t roots_size,time_t floor,time_t *verified)
{struct time_cpu j={input,nonce,roots,size,roots_size,floor,verified,-1};return wendy_pki_work_run(time_cpu,&j) ? -1:j.result;}
struct identity_cpu {const uint8_t *cert,*roots,*key;size_t cert_size,roots_size,key_size;const char *principal;time_t now,*expires;int result;};
static void identity_cpu(void *context){struct identity_cpu *j=context;j->result=verify_identity_direct(j->cert,j->cert_size,j->roots,j->roots_size,j->key,j->key_size,j->principal,j->now,j->expires);}
int wendy_pki_verify_identity(const uint8_t *cert,size_t size,const uint8_t *roots,size_t roots_size,const uint8_t *key,size_t key_size,const char *principal,time_t now,time_t *expires)
{struct identity_cpu j={cert,roots,key,size,roots_size,key_size,principal,now,expires,-1};return wendy_pki_work_run(identity_cpu,&j) ? -1:j.result;}

int wendy_pki_operator_chain(const uint8_t *const *data,const size_t *sizes,size_t count,
    const uint8_t *roots,size_t roots_size,const char *tenant,time_t now,
    struct wendy_pki_operator_peer *out)
{
    /* Reuse the actual primary verifier and its valid-at path selection. No
     * authority from the descriptor, attachment peer or Lite twin is adopted.
     * This target keeps the existing eight-certificate path bound, while
     * allowing the primary protocol's128KiB total DER ceiling. */
    if(!data || !sizes || !count || count>8 || !roots || !roots_size || !tenant || !out || now<=0 ||
       !wendy_identity_uuid((const unsigned char*)tenant,strlen(tenant)))return -1;
    mbedtls_x509_crt *certs[8]={0};size_t total=0;int result=-1;
    struct wendy_pki_operator_peer *peer=pki_owned_calloc(1,sizeof *peer);
    if(!peer)return -1;
    for(size_t i=0;i<count;i++){
        if(!sizes[i] || sizes[i]>32768 || total>128*1024-sizes[i])goto done;
        total+=sizes[i];certs[i]=parse_cert_borrowed(data[i],sizes[i]);
        if(!certs[i] || certs[i]->raw.len!=sizes[i])goto done;
    }
    mbedtls_x509_crt *leaf=certs[0];
    if(leaf->MBEDTLS_PRIVATE(ca_istrue) || wendy_pki_certificate_policy(leaf,false) ||
       !(leaf->MBEDTLS_PRIVATE(key_usage) & MBEDTLS_X509_KU_DIGITAL_SIGNATURE) ||
       !has_eku(leaf,MBEDTLS_OID_CLIENT_AUTH,MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH)) ||
       verify_chain(leaf,certs,(int)count,roots,roots_size,now,&peer->expires) || peer->expires<=now)goto done;
    unsigned uris=0;
    for(const mbedtls_x509_sequence *a=&leaf->subject_alt_names;a && a->buf.p;a=a->next){
        mbedtls_x509_subject_alternative_name san;
        if(mbedtls_x509_parse_subject_alt_name(&a->buf,&san) || san.type!=MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER)continue;
        const uint8_t *uri=san.san.unstructured_name.p;size_t size=san.san.unstructured_name.len;
        if(wendy_pki_operator_principal((const char*)uri,size,tenant))goto done;
        memcpy(peer->principal,uri,size);peer->principal[size]=0;uris++;
    }
    if(uris!=1)goto done;
    /* Only the same two typed signing schemes as the Go proof contract. The
     * exact SPKI is retained; proof verification selects from its DER OID. */
    der raw={leaf->raw.p,leaf->raw.p,leaf->raw.len,leaf->raw.len,0},serial,issuer,spki,id,params,key;
    if(certificate_parts(raw,&serial,&issuer,&spki))goto done;
    if(ec_public_key(spki,false)){
        int n=mbedtls_pk_write_pubkey_der(&leaf->pk,peer->spki,sizeof peer->spki);
        if(n<=0 || (size_t)n>sizeof peer->spki)goto done;
        memmove(peer->spki,peer->spki+sizeof peer->spki-n,n);peer->spki_size=(size_t)n;
    }else{
        if(public_key_parts(spki,&id,&params,&key) || !bytes(id,mldsa65_oid,sizeof mldsa65_oid) ||
           params.n || key.n!=1953 || spki.raw_n>sizeof peer->spki)goto done;
        memcpy(peer->spki,spki.raw,spki.raw_n);peer->spki_size=spki.raw_n;
    }
    if(wendy_pki_sha256(data[0],sizes[0],peer->leaf_hash))goto done;
    *out=*peer;result=0;
done:
    for(size_t i=0;i<count;i++)free_cert(certs[i]);
    pki_owned_free(peer);return result;
}
