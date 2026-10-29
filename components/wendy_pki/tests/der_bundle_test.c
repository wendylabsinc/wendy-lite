/* Ordinary import/ownership coverage using the existing P-256 certificate. */
#include "wendy_pki_parsed_identity.h"
#include "wendy_cert_bundle.h"
#include "wendy_pki_crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *read_fixture(const char *directory, size_t *size)
{
    char path[1024];
    assert(snprintf(path, sizeof path, "%s/identity.pem", directory) < (int)sizeof path);
    FILE *file = fopen(path, "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long length = ftell(file);
    assert(length > 0 && !fseek(file, 0, SEEK_SET));
    uint8_t *data = malloc((size_t)length + 1);
    assert(data && fread(data, 1, (size_t)length, file) == (size_t)length);
    fclose(file);
    data[length] = 0;
    *size = (size_t)length;
    return data;
}

static void check_chain(mbedtls_x509_crt *chain, const uint8_t *der,
                        size_t bytes, unsigned count)
{
    for (unsigned i = 0; i < count; i++) {
        assert(chain && chain->raw.len == bytes && !memcmp(chain->raw.p, der, bytes));
        chain = chain->next;
    }
    assert(!chain);
}

int main(int argc, char **argv)
{
    assert(argc == 2 && !wendy_pki_crypto_init());
    size_t pem_size, der_size = 0, written = 0;
    uint8_t *pem = read_fixture(argv[1], &pem_size);
    mbedtls_x509_crt reference, chain;
    mbedtls_x509_crt_init(&reference);
    assert(!mbedtls_x509_crt_parse(&reference, pem, pem_size + 1));
    assert(!reference.next);
    assert(!wendy_cert_bundle_measure(pem, pem_size, &der_size));
    assert(der_size == reference.raw.len);
    uint8_t *der = malloc(der_size), *bundle = malloc(der_size * WENDY_CERT_BUNDLE_MAX_CERTS);
    assert(der && bundle);
    assert(!wendy_cert_bundle_import(pem, pem_size, der, der_size, &written));
    assert(written == der_size && !memcmp(der, reference.raw.p, der_size));
    assert(wendy_cert_bundle_import(pem, pem_size, der, der_size - 1, &written));
    assert(!wendy_cert_bundle_import(pem, pem_size, der, der_size, &written));

    /* Multiple PEM blocks and surrounding whitespace import as one DER chain. */
    size_t double_size = pem_size * 2 + 3;
    uint8_t *double_pem = malloc(double_size);
    assert(double_pem);
    double_pem[0] = ' ';
    memcpy(double_pem + 1, pem, pem_size);
    double_pem[1 + pem_size] = '\n';
    memcpy(double_pem + 2 + pem_size, pem, pem_size);
    double_pem[double_size - 1] = '\t';
    assert(!wendy_cert_bundle_measure(double_pem, double_size, &written));
    assert(written == der_size * 2);
    mbedtls_x509_crt_init(&chain);
    assert(!pki_parse_certificate_bundle(&chain, double_pem, double_size, false));
    check_chain(&chain, der, der_size, 2);
    mbedtls_x509_crt_free(&chain);
    free(double_pem);

    /* Both copy modes survive releasing the original input. PEM borrow requests
     * still own their DER since the temporary import buffer is short lived. */
    mbedtls_x509_crt_init(&chain);
    assert(!pki_parse_certificate_bundle(&chain, pem, pem_size, true));
    memset(pem, 0, pem_size);
    free(pem);
    check_chain(&chain, der, der_size, 1);
    mbedtls_x509_crt_free(&chain);
    mbedtls_x509_crt_init(&chain);
    assert(!pki_parse_certificate_bundle(&chain, der, der_size, false));
    assert(chain.raw.p != der);
    check_chain(&chain, der, der_size, 1);
    mbedtls_x509_crt_free(&chain);

    /* A concatenated maximum-sized chain uses the original immutable extents
     * in nocopy mode, without a second encoded allocation. */
    for (unsigned i = 0; i < WENDY_CERT_BUNDLE_MAX_CERTS; i++)
        memcpy(bundle + i * der_size, der, der_size);
    size_t offset = 0, bytes;
    const uint8_t *part;
    for (unsigned i = 0; i < WENDY_CERT_BUNDLE_MAX_CERTS; i++) {
        assert(wendy_cert_der_next(bundle, der_size * WENDY_CERT_BUNDLE_MAX_CERTS,
                                   &offset, &part, &bytes) == 1);
        assert(part == bundle + i * der_size && bytes == der_size);
    }
    assert(wendy_cert_der_next(bundle, offset, &offset, &part, &bytes) == 0);
    assert(!wendy_cert_bundle_measure(bundle, offset, &written) && written == offset);
    mbedtls_x509_crt_init(&chain);
    assert(!pki_parse_certificate_bundle(&chain, bundle, offset, true));
    check_chain(&chain, der, der_size, WENDY_CERT_BUNDLE_MAX_CERTS);
    mbedtls_x509_crt *node = &chain;
    for (unsigned i = 0; i < WENDY_CERT_BUNDLE_MAX_CERTS; i++, node = node->next)
        assert(node->raw.p == bundle + i * der_size);
    mbedtls_x509_crt_free(&chain);

    /* Ordinary incomplete-input failures leave the initialized chain freeable. */
    mbedtls_x509_crt_init(&chain);
    assert(pki_parse_certificate_bundle(&chain, der, der_size - 1, false));
    assert(pki_parse_certificate_bundle(&chain, der, 0, false));
    assert(pki_parse_certificate_bundle(NULL, der, der_size, false));
    mbedtls_x509_crt_free(&chain);
    free(bundle);
    free(der);
    mbedtls_x509_crt_free(&reference);
    puts("DER import and direct parse ownership tests passed");
}
