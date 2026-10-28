#include "wendy_ble_setup_crypto.h"
#include "setup_wire_fixture.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    assert(psa_crypto_init() == PSA_SUCCESS);
    uint8_t secret[32], public_key[32], plaintext[128], sealed[128], tampered[sizeof fixture_request];
    for (size_t i = 0; i < sizeof secret; ++i) secret[i] = i + 33;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr, 255);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    assert(psa_import_key(&attr, secret, sizeof secret, &key) == PSA_SUCCESS);
    struct wble_setup_crypto crypto = {0};
    assert(wble_setup_crypto_derive(&crypto, key, fixture_client, public_key));
    assert(!memcmp(public_key, fixture_server, 32));
    size_t size;
    assert(!wble_setup_crypto_seal(&crypto, (const uint8_t *)"connected", 9, sealed, sizeof sealed, &size));
    memcpy(tampered, fixture_request, sizeof tampered);
    tampered[sizeof tampered - 1] ^= 1;
    assert(!wble_setup_crypto_open(&crypto, tampered, sizeof tampered, plaintext, sizeof plaintext, &size));
    assert(crypto.counter == 0);
    memcpy(tampered, fixture_request, sizeof tampered);
    tampered[11] = 2; // Out-of-order counter, including before the first request.
    assert(!wble_setup_crypto_open(&crypto, tampered, sizeof tampered, plaintext, sizeof plaintext, &size));
    assert(wble_setup_crypto_open(&crypto, fixture_request, sizeof fixture_request, plaintext, sizeof plaintext, &size));
    assert(size == 13 && !memcmp(plaintext, "wifi password", size));
    assert(!wble_setup_crypto_open(&crypto, fixture_request, sizeof fixture_request, plaintext, sizeof plaintext, &size));
    assert(wble_setup_crypto_seal(&crypto, (const uint8_t *)"connected", 9, sealed, sizeof sealed, &size));
    assert(size == sizeof fixture_response && !memcmp(sealed, fixture_response, size));
    assert(!wble_setup_crypto_seal(&crypto, (const uint8_t *)"connected", 9, sealed, sizeof sealed, &size));
    assert(!wble_setup_crypto_open(&crypto, fixture_request, sizeof fixture_request, plaintext, sizeof plaintext, &size));
    wble_setup_crypto_close(&crypto);
    assert(!crypto.read_key && !crypto.write_key && !crypto.counter);
    uint8_t zero[32] = {0};
    assert(!wble_setup_crypto_derive(&crypto, key, zero, public_key));
    assert(!crypto.read_key && !crypto.write_key);
    assert(psa_destroy_key(key) == PSA_SUCCESS);
    // Exercise production entropy/generation as well as the deterministic fixture.
    assert(wble_setup_crypto_accept(&crypto, fixture_client, public_key));
    wble_setup_crypto_close(&crypto);
    psa_reset_key_attributes(&attr);
    puts("BLE setup Swift/Go interoperability, tamper and replay tests passed");
}
