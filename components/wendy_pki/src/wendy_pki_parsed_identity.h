#pragma once
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <time.h>
#include <stdbool.h>
/* Caller exclusively owns the parsed chain/key. Full path, principal, both
 * TLS usages, key match and selected-path expiry checks remain mandatory. */
int pki_verify_parsed_identity(mbedtls_x509_crt *chain, mbedtls_pk_context *key,
    const uint8_t *roots, size_t roots_size, mbedtls_x509_crt *anchors, const char *principal,
    time_t now, time_t *expires);
/* Check complete DER bundle and key extents without allocating. */
int pki_identity_encoding(const uint8_t *pem, size_t size, const uint8_t *key, size_t key_size);
int pki_key_encoding(const uint8_t *key,size_t key_size);
/* Read already parsed peer metadata without allocating another DER/key copy. */
int pki_parsed_peer_expiry(const mbedtls_x509_crt *cert,time_t *expires);

struct wendy_pki_mesh_peer;
/* Full independent proof verification; caller exclusively owns parsed anchors.
 * Root policy, complete signature path and signed-time expiry are checked. */
int pki_mesh_chain_anchors(const uint8_t *const *der,const size_t *sizes,size_t count,
    mbedtls_x509_crt *anchors,const char *tenant,time_t now,struct wendy_pki_mesh_peer *);

/* DER is passed directly to the library. PEM is imported only at boundaries. */
int pki_parse_certificate_bundle(mbedtls_x509_crt *,const uint8_t *,size_t,bool borrow);
