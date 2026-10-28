#include "wendy_pki_parsed_identity.h"
#include "wendy_pki_crypto.h"
#include "wendy_cert_bundle.h"
#include <stdlib.h>

int pki_parse_certificate_bundle(mbedtls_x509_crt *cert, const uint8_t *data,
                                 size_t size, bool borrow)
{
    if (!cert || !data || !size || size > WENDY_CERT_BUNDLE_MAX_BYTES ||
        wendy_pki_crypto_init()) return -1;
    uint8_t *imported = NULL;
    if (data[0] != 0x30) {
        size_t bytes = 0;
        if (wendy_cert_bundle_measure(data, size, &bytes)) return -1;
        imported = malloc(bytes);
        if (!imported) return MBEDTLS_ERR_X509_ALLOC_FAILED;
        if (wendy_cert_bundle_import(data, size, imported, bytes, &bytes)) {
            free(imported);
            return -1;
        }
        data = imported;
        size = bytes;
        borrow = false;
    }
    size_t offset = 0, bytes;
    const uint8_t *der;
    unsigned count = 0;
    int next, result = 0;
    while ((next = wendy_cert_der_next(data, size, &offset, &der, &bytes)) == 1) {
        if (++count > WENDY_CERT_BUNDLE_MAX_CERTS) {
            result = -1;
            break;
        }
        result = borrow ? mbedtls_x509_crt_parse_der_nocopy(cert, der, bytes) :
                          mbedtls_x509_crt_parse_der(cert, der, bytes);
        if (result) break;
    }
    free(imported);
    return result ? result : (next < 0 || !count ? -1 : 0);
}
