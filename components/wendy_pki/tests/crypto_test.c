#include "wendy_pki_crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <mbedtls/pk.h>
#include <mbedtls/pem.h>
#include <mbedtls/x509_csr.h>

/* Exercise persisted SEC1 keys and the actual enrollment CSR format across
 * the mbedTLS 3 -> PSA-backed mbedTLS 4 transition. */
static void check_key(const uint8_t *der, size_t size)
{
    mbedtls_pk_context key;
    mbedtls_x509write_csr writer;
    mbedtls_x509_csr parsed;
    mbedtls_pk_init(&key);
    mbedtls_x509write_csr_init(&writer);
    mbedtls_x509_csr_init(&parsed);
    int result = mbedtls_pk_parse_key(&key, der, size, NULL, 0);
    if (result) {
        uint8_t encoded[1024];
        size_t encoded_size;
        assert(!mbedtls_pem_write_buffer("-----BEGIN EC PRIVATE KEY-----\n",
            "-----END EC PRIVATE KEY-----\n", der, size, encoded, sizeof encoded, &encoded_size));
        int pem_result = mbedtls_pk_parse_key(&key, encoded, encoded_size, NULL, 0);
        fprintf(stderr, "P-256 DER parse failed: -0x%x (%zu bytes), PEM -0x%x\n",
                -result, size, -pem_result);
    }
    assert(!result);
    assert(mbedtls_pk_get_key_type(&key) == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    assert(mbedtls_pk_get_bitlen(&key) == 256);
    assert(!mbedtls_x509write_csr_set_subject_name(&writer, "CN=lite-migration-test"));
    mbedtls_x509write_csr_set_key(&writer, &key);
    mbedtls_x509write_csr_set_md_alg(&writer, MBEDTLS_MD_SHA256);
    uint8_t pem[4096];
    assert(!mbedtls_x509write_csr_pem(&writer, pem, sizeof pem));
    assert(!mbedtls_x509_csr_parse(&parsed, pem, strlen((char *)pem) + 1));
    assert(!mbedtls_pk_check_pair(&parsed.pk, &key));
    uint8_t hash[32];
    assert(!wendy_pki_sha256(parsed.cri.p, parsed.cri.len, hash));
    assert(parsed.MBEDTLS_PRIVATE(sig_md) == MBEDTLS_MD_SHA256);
    assert(!mbedtls_pk_verify(&parsed.pk, MBEDTLS_MD_SHA256, hash, sizeof hash,
                              parsed.MBEDTLS_PRIVATE(sig).p, parsed.MBEDTLS_PRIVATE(sig).len));
    hash[0] ^= 1;
    assert(mbedtls_pk_verify(&parsed.pk, MBEDTLS_MD_SHA256, hash, sizeof hash,
                             parsed.MBEDTLS_PRIVATE(sig).p, parsed.MBEDTLS_PRIVATE(sig).len) != 0);
    mbedtls_x509_csr_free(&parsed);
    mbedtls_x509write_csr_free(&writer);
    mbedtls_pk_free(&key);
}

static void *concurrent_crypto(void *unused)
{
    (void)unused;
    for (unsigned i = 0; i < 4; i++) {
        uint8_t der[256];
        int size = wendy_pki_generate_key_der(der, sizeof der);
        assert(size > 0 && size <= sizeof der);
        check_key(der + sizeof der - size, size);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    /* BLE, LAN, and the Cloud worker can initialize/use PSA concurrently. */
    pthread_t workers[4];
    for (unsigned i = 0; i < 4; i++)
        assert(!pthread_create(&workers[i], NULL, concurrent_crypto, NULL));
    for (unsigned i = 0; i < 4; i++)
        assert(!pthread_join(workers[i], NULL));
    assert(!wendy_pki_crypto_init());
    uint8_t generated[256], second[256], persisted[256], hash[32];
    static const uint8_t abc_sha256[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    assert(!wendy_pki_sha256((const uint8_t *)"abc", 3, hash));
    assert(!memcmp(hash, abc_sha256, sizeof hash));
    int size = wendy_pki_generate_key_der(generated, sizeof generated);
    int second_size = wendy_pki_generate_key_der(second, sizeof second);
    assert(size > 0 && size <= sizeof generated);
    assert(second_size > 0 && second_size <= sizeof second);
    assert(size != second_size || memcmp(generated + sizeof generated - size,
                                         second + sizeof second - second_size, size));
    check_key(generated + sizeof generated - size, size);
    uint8_t tiny[1];
    assert(wendy_pki_generate_key_der(tiny, sizeof tiny) < 0);
    FILE *file = fopen(argv[1], "rb");
    assert(file);
    size_t persisted_size = fread(persisted, 1, sizeof persisted, file);
    assert(persisted_size && !ferror(file) && fgetc(file) == EOF);
    fclose(file);
    check_key(persisted, persisted_size);
    puts("P-256 persisted key and CSR compatibility passed");
    return 0;
}
