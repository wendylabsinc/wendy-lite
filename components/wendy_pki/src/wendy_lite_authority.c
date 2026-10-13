#include "wendy_pki_verify.h"
#include "wendy_operator_auth.h"
#include <stdlib.h>
#include <string.h>
#include <mbedtls/asn1.h>
#include <mbedtls/base64.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

static int p256(const mbedtls_x509_crt *cert)
{
    return mbedtls_pk_can_do(&cert->pk, MBEDTLS_PK_ECDSA) &&
           mbedtls_pk_ec(cert->pk)->MBEDTLS_PRIVATE(grp).id == MBEDTLS_ECP_DP_SECP256R1;
}

int wendy_pki_lite_authority_from_header(const char *header, char **pem)
{
    if (!pem) return -1;
    *pem = NULL;
    if (!header) return -1;
    size_t size = strnlen(header, WENDY_LITE_AUTHORITY_HEADER_MAX + 1);
    if (!size || size > WENDY_LITE_AUTHORITY_HEADER_MAX) return -1;
    uint8_t *der = malloc(size);
    unsigned char *encoded = malloc(size + 1);
    unsigned char *output = NULL;
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int result = -1;
    size_t der_size = 0, encoded_size = 0, output_size = 0;
    uint8_t hash[32];
    if (!der || !encoded ||
        mbedtls_base64_decode(der, size, &der_size, (const unsigned char *)header, size) ||
        !der_size ||
        mbedtls_base64_encode(encoded, size + 1, &encoded_size, der, der_size) ||
        encoded_size != size || memcmp(encoded, header, size) ||
        mbedtls_x509_crt_parse_der(&cert, der, der_size) ||
        cert.raw.len != der_size || cert.next || !p256(&cert) ||
        !cert.MBEDTLS_PRIVATE(ca_istrue) ||
        cert.MBEDTLS_PRIVATE(max_pathlen) != 1 || /* RFC 5280 pathLen = 0. */
        !(cert.MBEDTLS_PRIVATE(key_usage) & MBEDTLS_X509_KU_KEY_CERT_SIGN) ||
        cert.subject_raw.len != cert.issuer_raw.len ||
        memcmp(cert.subject_raw.p, cert.issuer_raw.p, cert.subject_raw.len) ||
        cert.MBEDTLS_PRIVATE(sig_md) != MBEDTLS_MD_SHA256 ||
        cert.MBEDTLS_PRIVATE(sig_pk) != MBEDTLS_PK_ECDSA ||
        mbedtls_sha256(cert.tbs.p, cert.tbs.len, hash, 0) ||
        mbedtls_pk_verify(&cert.pk, MBEDTLS_MD_SHA256, hash, sizeof hash,
                         cert.MBEDTLS_PRIVATE(sig).p, cert.MBEDTLS_PRIVATE(sig).len))
        goto done;
    /* Trust bootstrap does not depend on the device's initial wall clock.
     * Normal TLS validation still checks this CA's lifetime when it is used. */
    size_t capacity = size + size / 64 + 128;
    output = malloc(capacity);
    if (!output || mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
        "-----END CERTIFICATE-----\n", der, der_size, output, capacity, &output_size))
        goto done;
    *pem = (char *)output;
    output = NULL;
    result = 0;
done:
    free(output);
    free(encoded);
    free(der);
    mbedtls_x509_crt_free(&cert);
    return result;
}

/* mbedTLS exposes the decoded keyUsage bits but not its critical flag. Read
 * that flag from the already parsed, bounded DER extensions. */
static int critical_key_usage(const mbedtls_x509_crt *cert)
{
    if (!cert->v3_ext.p || !cert->v3_ext.len) return -1;
    unsigned char *p = cert->v3_ext.p;
    const unsigned char *end = p + cert->v3_ext.len;
    size_t size;
    if (mbedtls_asn1_get_tag(&p, end, &size, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) ||
        size != (size_t)(end - p)) return -1;
    int found = 0;
    while (p < end) {
        if (mbedtls_asn1_get_tag(&p, end, &size, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
            return -1;
        const unsigned char *extension_end = p + size;
        mbedtls_asn1_buf oid = {0};
        if (mbedtls_asn1_get_tag(&p, extension_end, &oid.len, MBEDTLS_ASN1_OID)) return -1;
        oid.p = p;
        p += oid.len;
        int critical = 0;
        int result = mbedtls_asn1_get_bool(&p, extension_end, &critical);
        if (result && result != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) return -1;
        if (mbedtls_asn1_get_tag(&p, extension_end, &size, MBEDTLS_ASN1_OCTET_STRING) ||
            size != (size_t)(extension_end - p)) return -1;
        if (MBEDTLS_OID_CMP(MBEDTLS_OID_KEY_USAGE, &oid) == 0) {
            if (!critical || found++) return -1;
        }
        p = (unsigned char *)extension_end;
    }
    return found == 1 ? 0 : -1;
}

int wendy_pki_verify_lite_operator(const uint8_t *der, size_t size, const char *tenant)
{
    /* id-kp-wendyLiteOperator: 1.3.6.1.4.1.65441.1.9 */
    static const unsigned char lite_eku[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xff, 0x21, 0x01, 0x09};
    if (!der || !size || size > 65536) return -1;
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int result = -1;
    if (mbedtls_x509_crt_parse_der(&cert, der, size) || cert.raw.len != size || cert.next ||
        !p256(&cert) || wendy_operator_auth_check(&cert, tenant) ||
        cert.MBEDTLS_PRIVATE(key_usage) != MBEDTLS_X509_KU_DIGITAL_SIGNATURE ||
        critical_key_usage(&cert)) goto done;
    int client = 0, lite = 0;
    for (const mbedtls_x509_sequence *eku = &cert.ext_key_usage; eku && eku->buf.p; eku = eku->next) {
        if (MBEDTLS_OID_CMP(MBEDTLS_OID_CLIENT_AUTH, &eku->buf) == 0) client++;
        else if (eku->buf.len == sizeof lite_eku && !memcmp(eku->buf.p, lite_eku, sizeof lite_eku)) lite++;
        else goto done;
    }
    if (client == 1 && lite == 1) result = 0;
done:
    mbedtls_x509_crt_free(&cert);
    return result;
}
