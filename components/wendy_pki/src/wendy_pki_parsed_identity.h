#pragma once
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <time.h>
#include <stdbool.h>
#include "wendy_pki_certificate_time.h"
/* Caller exclusively owns the parsed chain/key. Full path, principal, both
 * TLS usages, key match and selected-path expiry checks remain mandatory. */
int pki_verify_parsed_identity(mbedtls_x509_crt *chain, mbedtls_pk_context *key,
                               const uint8_t *roots, size_t roots_size, mbedtls_x509_crt *anchors,
                               const char *principal, time_t now, time_t *expires);
int pki_verify_parsed_identity_policy(mbedtls_x509_crt *, mbedtls_pk_context *,
    const uint8_t *, size_t, mbedtls_x509_crt *, const char *, time_t,
    const struct wendy_pki_certificate_time *, time_t *not_before, time_t *expires);
/* Check complete DER bundle and key extents without allocating. */
int pki_identity_encoding(const uint8_t *pem, size_t size, const uint8_t *key, size_t key_size);
int pki_key_encoding(const uint8_t *key, size_t key_size);
/* Read already parsed peer metadata without allocating another DER/key copy. */
int pki_parsed_peer_not_before(const mbedtls_x509_crt *cert, time_t *not_before);
int pki_parsed_peer_expiry(const mbedtls_x509_crt *cert, time_t *expires);
/* MBEDTLS_X509_BADCERT_EXPIRED and _FUTURE flags of a certificate at the given
 * time. A date that cannot be read counts as outside the validity period. */
uint32_t pki_parsed_date_flags(const mbedtls_x509_crt *cert, time_t now);

struct wendy_pki_mesh_peer;
/* Full independent proof verification; caller exclusively owns parsed anchors.
 * Root policy, complete signature path and signed-time expiry are checked. */
int pki_mesh_chain_anchors(const uint8_t *const *der, const size_t *sizes, size_t count,
                           mbedtls_x509_crt *anchors, const char *tenant, time_t now,
                           struct wendy_pki_mesh_peer *);

int pki_mesh_chain_anchors_policy(const uint8_t *const *, const size_t *, size_t,
    mbedtls_x509_crt *, const char *, time_t, const struct wendy_pki_certificate_time *,
    struct wendy_pki_mesh_peer *);

/* Append up to eight complete DER certificates directly to an initialized
 * chain. PEM is decoded at this import boundary and always copied by Mbed TLS.
 * For DER with borrow=true, input must remain immutable and alive until the
 * chain is freed. The caller owns/frees the chain, also after a partial failure.
 * This only parses certificates; callers still verify trust and usage policy. */
int pki_parse_certificate_bundle(mbedtls_x509_crt *cert, const uint8_t *data, size_t size,
                                 bool borrow);
