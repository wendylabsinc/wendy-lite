#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "psa/crypto.h"

struct wble_setup_crypto {
    psa_key_id_t read_key, write_key;
    uint64_t counter;
    bool response_pending;
};
/* Context must be zero-initialized. Every failure requires close. */
bool wble_setup_crypto_accept(struct wble_setup_crypto *, const uint8_t peer[32], uint8_t public_key[32]);
/* Derive from an existing ephemeral key. Does not take ownership of key. */
bool wble_setup_crypto_derive(struct wble_setup_crypto *, psa_key_id_t key,
                             const uint8_t peer[32], uint8_t public_key[32]);
bool wble_setup_crypto_open(struct wble_setup_crypto *, const uint8_t *, size_t,
                           uint8_t *, size_t, size_t *);
bool wble_setup_crypto_seal(struct wble_setup_crypto *, const uint8_t *, size_t,
                           uint8_t *, size_t, size_t *);
void wble_setup_crypto_close(struct wble_setup_crypto *);
