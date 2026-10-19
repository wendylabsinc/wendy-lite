#pragma once
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#define WENDY_LITE_KEY_BYTES 65
#define WENDY_LITE_GRANT_FIXED 293
#define WENDY_LITE_GRANT_MAX (WENDY_LITE_GRANT_FIXED + 128)
struct wendy_lite_key {
    uint8_t id_size;
    uint8_t id[128];
    uint8_t public_key[WENDY_LITE_KEY_BYTES];
};
/* Owned by one authenticated outer TLS connection. Never populated by the CLI. */
struct wendy_lite_trust {
    uint8_t count;
    struct wendy_lite_key keys[2];
    uint8_t session[16];
    uint8_t grant_hash[32];
};
int wendy_lite_key_id(const uint8_t *id, size_t size);
int wendy_lite_verify_grant(const uint8_t *record, size_t size,
    const struct wendy_lite_trust *trust, const uint8_t device[32],
    const uint8_t operator_id[32], const uint8_t operator_spki[32],
    time_t now, uint64_t *session_expires);
/* A grant's expiry bounds presentation only. On success session_expires is
 * issued_at + 1800; the caller must cap it by both authenticated certificate
 * expiries. Output is unchanged on failure. */
/* Only used after the TLS verifier has accepted the certificate's role and tenant. */
int wendy_lite_peer_hash(const uint8_t *der, size_t size, uint8_t hash[32]);
int wendy_lite_peer_spki_hash(const uint8_t *der, size_t size, uint8_t hash[32]);
int wendy_lite_peer_expiry(const uint8_t *der, size_t size, time_t *expires);
