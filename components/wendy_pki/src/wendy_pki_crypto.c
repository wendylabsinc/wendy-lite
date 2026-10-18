#include "wendy_pki_crypto.h"
#include <pthread.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>

static pthread_once_t crypto_once = PTHREAD_ONCE_INIT;
static int crypto_status = -1;
static void init_crypto(void)
{
    crypto_status = psa_crypto_init() == PSA_SUCCESS ? 0 : -1;
}

int wendy_pki_crypto_init(void)
{
    return pthread_once(&crypto_once, init_crypto) == 0 ? crypto_status : -1;
}

int wendy_pki_sha256(const uint8_t *data, size_t size, uint8_t hash[32])
{
    size_t written = 0;
    return !wendy_pki_crypto_init() &&
           psa_hash_compute(PSA_ALG_SHA_256, data, size, hash, 32, &written) == PSA_SUCCESS &&
           written == 32 ? 0 : -1;
}

int wendy_pki_generate_key_der(uint8_t *buffer, size_t capacity)
{
    if (!buffer || !capacity || wendy_pki_crypto_init()) return -1;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    int result = -1;
    if (psa_generate_key(&attributes, &key) == PSA_SUCCESS &&
        !mbedtls_pk_copy_from_psa(key, &pk))
        result = mbedtls_pk_write_key_der(&pk, buffer, capacity);
    mbedtls_pk_free(&pk);
    psa_destroy_key(key);
    psa_reset_key_attributes(&attributes);
    return result;
}
