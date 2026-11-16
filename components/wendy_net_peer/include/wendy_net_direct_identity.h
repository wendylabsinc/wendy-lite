#pragma once
#include <stdint.h>
#include <stddef.h>
/* All fields locally derived from authenticated material, not offered by a
 * peer: SHA256 exact canonical principal URI, instance UUID, SHA256 DER SPKI,
 * role0 device/1 operator. Local trust/config epoch changes must destroy session
 * authority and attachment must never extend its original security deadline. */
struct wn_direct_endpoint_identity {
    uint8_t principal[32], key[32], instance[16], role;
};
/* Logical coordinator first, selected by full authenticated identities/UUIDs. */
int wn_direct_identity_digest(const struct wn_direct_endpoint_identity *coordinator,
                              const struct wn_direct_endpoint_identity *participant,
                              uint8_t out[32]);
/* Inputs must already be authenticated and canonical. No input pointer is
 * retained. Principal length excludes NUL; embedded NUL is rejected. Device
 * pairs order by full UUID; pairs containing an operator order by principal,
 * then UUID, exactly like WendyOS meshid.Compare. Equal identities fail. */
struct wn_direct_authenticated_endpoint {
    const char *principal;
    size_t principal_size;
    uint8_t key[32], instance[16], role;
};
struct wn_direct_identity_pair {
    struct wn_direct_endpoint_identity local, peer;
    uint8_t digest[32], local_role;
};
int wn_direct_identity_pair(const struct wn_direct_authenticated_endpoint *local,
                            const struct wn_direct_authenticated_endpoint *peer,
                            struct wn_direct_identity_pair *out);
