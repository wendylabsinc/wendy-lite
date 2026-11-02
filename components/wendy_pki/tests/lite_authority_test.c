/* Host driver for the production Lite authority and operator profile helpers. */
#include "wendy_pki_verify.h"
#include "wendy_pki_crypto.h"
#include "wendy_net_memory.h"
#include <mbedtls/platform.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <mbedtls/x509_crt.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *load(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long length = ftell(file);
    assert(length >= 0 && !fseek(file, 0, SEEK_SET));
    *size = (size_t)length;
    unsigned char *data = calloc(1, *size + 1);
    assert(data && fread(data, 1, *size, file) == *size);
    fclose(file);
    return data;
}

int main(int argc, char **argv)
{
    assert(argc >= 4);
    /* Match the firmware allocator ABI: every Mbed TLS/PKI-owned pointer
     * carries an ownership prefix, even when its owner is uncharged. */
    assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,
                                             wendy_net_memory_scoped_free));
    assert(mbedtls_psa_set_key_slot_table_allocator(wendy_pki_crypto_shared_calloc) == PSA_SUCCESS);
    assert(!wendy_pki_crypto_init());
    wendy_net_memory_t memory = WENDY_NET_MEMORY_INITIALIZER;
    assert(wendy_net_memory_open(&memory, 1024 * 1024, false));
    wendy_net_memory_scope_t previous =
        wendy_net_memory_scope_enter(&memory, WENDY_NET_MEMORY_INTERNAL);
    size_t size;
    unsigned char *data = load(argv[2], &size);
    int expected = !strcmp(argv[3], "valid");
    assert(expected || !strcmp(argv[3], "invalid"));
    int result;
    if (!strcmp(argv[1], "authority")) {
        uint8_t *der = NULL;
        size_t der_size = 0;
        result = wendy_pki_lite_authority_from_header((const char *)data, &der, &der_size);
        if (!result) {
            assert(der && argc == 5);
            size_t expected_size;
            unsigned char *expected_der = load(argv[4], &expected_size);
            mbedtls_x509_crt certificate;
            mbedtls_x509_crt_init(&certificate);
            assert(!mbedtls_x509_crt_parse_der(&certificate, der, der_size));
            assert(certificate.next == NULL);
            assert(certificate.raw.len == expected_size);
            assert(!memcmp(certificate.raw.p, expected_der, expected_size));
            mbedtls_x509_crt_free(&certificate);
            free(expected_der);
        } else {
            assert(der == NULL);
        }
        /* The public import API transfers raw libc storage to issue(),
         * whose cleanup uses free(). No scoped allocation may escape. */
        wendy_pki_crypto_cleanup();
        assert(wendy_net_memory_drained(&memory));
        free(der);
    } else if (!strcmp(argv[1], "operator")) {
        assert(argc == 5);
        result = wendy_pki_verify_lite_operator(data, size, argv[4]);
    } else {
        assert(!strcmp(argv[1], "arguments") && argc == 5);
        uint8_t *der = NULL;
        size_t der_size = 0;
        assert(wendy_pki_lite_authority_from_header(NULL, &der, &der_size));
        assert(der == NULL);
        assert(wendy_pki_lite_authority_from_header("", NULL, &der_size));
        assert(wendy_pki_verify_lite_operator(NULL, size, argv[4]));
        assert(wendy_pki_verify_lite_operator(data, 0, argv[4]));
        assert(wendy_pki_verify_lite_operator(data, size, NULL));
        assert(wendy_pki_verify_lite_operator(data, size, ""));
        result = 0;
    }
    wendy_pki_crypto_cleanup();
    assert(wendy_net_memory_drained(&memory));
    wendy_net_memory_scope_leave(previous);
    wendy_net_memory_close(&memory);
    free(data);
    if ((!result) != expected) {
        fprintf(stderr, "%s %s: expected %s, got %d\n", argv[1], argv[2], argv[3], result);
        return 1;
    }
    return 0;
}
