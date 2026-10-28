#include "wendy_ble_setup_crypto.h"
#include "mbedtls/platform_util.h"
#include <string.h>

void wble_setup_crypto_close(struct wble_setup_crypto *s)
{
    psa_destroy_key(s->read_key);
    psa_destroy_key(s->write_key);
    mbedtls_platform_zeroize(s, sizeof *s);
}

bool wble_setup_crypto_derive(struct wble_setup_crypto *s, psa_key_id_t key,
                             const uint8_t peer[32], uint8_t public_key[32])
{
    static const uint8_t info[] = "wendy-ble-setup-v1";
    uint8_t shared[32] = {0}, salt[64], keys[64] = {0};
    size_t size = 0;
    bool ok = false;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    if (s->read_key || s->write_key) goto done;
    if (psa_export_public_key(key, public_key, 32, &size) != PSA_SUCCESS || size != 32 ||
        psa_raw_key_agreement(PSA_ALG_ECDH, key, peer, 32, shared, sizeof shared, &size) != PSA_SUCCESS || size != 32)
        goto done;
    /* Reject the all-zero shared secret even on backends that don't do so. */
    uint8_t nonzero = 0;
    for (size_t i = 0; i < sizeof shared; ++i) nonzero |= shared[i];
    if (!nonzero) goto done;
    memcpy(salt, peer, 32);
    memcpy(salt + 32, public_key, 32);
    if (psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256)) != PSA_SUCCESS ||
        psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, sizeof salt) != PSA_SUCCESS ||
        psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, shared, sizeof shared) != PSA_SUCCESS ||
        psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info, sizeof info - 1) != PSA_SUCCESS ||
        psa_key_derivation_output_bytes(&op, keys, sizeof keys) != PSA_SUCCESS)
        goto done;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    if (psa_import_key(&attr, keys, 32, &s->read_key) != PSA_SUCCESS) goto done;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    if (psa_import_key(&attr, keys + 32, 32, &s->write_key) != PSA_SUCCESS) goto done;
    s->counter = 0;
    s->response_pending = false;
    ok = true;
done:
    psa_key_derivation_abort(&op);
    psa_reset_key_attributes(&attr);
    mbedtls_platform_zeroize(shared, sizeof shared);
    mbedtls_platform_zeroize(keys, sizeof keys);
    if (!ok) wble_setup_crypto_close(s);
    return ok;
}

bool wble_setup_crypto_accept(struct wble_setup_crypto *s, const uint8_t peer[32], uint8_t public_key[32])
{
    if (psa_crypto_init() != PSA_SUCCESS) return false;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr, 255);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    bool ok = psa_generate_key(&attr, &key) == PSA_SUCCESS &&
              wble_setup_crypto_derive(s, key, peer, public_key);
    psa_destroy_key(key);
    psa_reset_key_attributes(&attr);
    return ok;
}

static void nonce_for(uint64_t counter, uint8_t nonce[12])
{
    memset(nonce, 0, 12);
    for (int i = 11; i >= 4; --i) { nonce[i] = counter; counter >>= 8; }
}

bool wble_setup_crypto_open(struct wble_setup_crypto *s, const uint8_t *data, size_t size,
                           uint8_t *out, size_t capacity, size_t *written)
{
    uint8_t nonce[12];
    *written = 0;
    if (!s->read_key || s->response_pending || s->counter == UINT64_MAX || size < 28)
        return false;
    nonce_for(s->counter + 1, nonce);
    if (memcmp(nonce, data, 12) ||
        psa_aead_decrypt(s->read_key, PSA_ALG_GCM, nonce, 12, NULL, 0,
                         data + 12, size - 12, out, capacity, written) != PSA_SUCCESS)
        return false;
    ++s->counter;
    s->response_pending = true;
    return true;
}

bool wble_setup_crypto_seal(struct wble_setup_crypto *s, const uint8_t *data, size_t size,
                           uint8_t *out, size_t capacity, size_t *written)
{
    *written = 0;
    if (!s->write_key || !s->response_pending || capacity < 28) return false;
    nonce_for(s->counter, out);
    /* Consume the nonce even if encryption fails. Never retry it. */
    s->response_pending = false;
    if (psa_aead_encrypt(s->write_key, PSA_ALG_GCM, out, 12, NULL, 0,
                         data, size, out + 12, capacity - 12, written) != PSA_SUCCESS)
        return false;
    *written += 12;
    return true;
}
