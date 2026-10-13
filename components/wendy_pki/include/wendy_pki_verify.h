#ifndef WENDY_PKI_VERIFY_H
#define WENDY_PKI_VERIFY_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "wendy_peer_role.h"
#define WENDY_LITE_AUTHORITY_HEADER_MAX 4096
/* Decode the authenticated enrollment header into one self-signed P-256 CA.
 * This establishes only the Lite operator pin, never device/TSA/HTTPS trust.
 * The caller owns the allocated, NUL-terminated PEM on success. */
int wendy_pki_lite_authority_from_header(const char *header, char **pem);
/* After TLS verification against the isolated Lite operator CA, enforce the
 * exact Lite operator profile and the locally enrolled tenant. */
int wendy_pki_verify_lite_operator(const uint8_t *der, size_t size, const char *tenant);
/* Strict, bounded PEM CA bundle validation, independent of the boot clock. */
int wendy_pki_verify_roots(const uint8_t *pem, size_t size);
/* Verify a nonce-bound RFC 3161 response. Nothing changes the system clock here.
 * The trust bundle must be pinned before enrollment. Returns 0 on success. */
int wendy_pki_verify_time(const uint8_t *der, size_t size, const uint8_t nonce[32],
                          const uint8_t *roots, size_t roots_size, time_t floor,
                          time_t *verified_time);
/* Verify a leaf-first PEM chain, exact SPIFFE URI, and its P-256 private key. */
int wendy_pki_verify_identity(const uint8_t *pem, size_t size, const uint8_t *roots,
                              size_t roots_size, const uint8_t *key, size_t key_size,
                              const char *principal, time_t now, time_t *expires);
#endif

/* RFC 3161 request for a positive, nonzero 32-byte device nonce. */
size_t wendy_pki_time_request(uint8_t out[128], const uint8_t nonce[32]);

/* After TLS chain verification: require one same-tenant operator URI and clientAuth. */
int wendy_pki_verify_operator(const uint8_t *der, size_t size, const char *tenant);

/* Same leaf policy as verify_operator, returning its operator/device role.
 * The caller must also verify the TLS chain before authorizing the role. */
enum wendy_peer_role wendy_pki_verify_peer(const uint8_t *der, size_t size,
                                           const char *tenant);

int wendy_pki_rng(void *context, unsigned char *out, size_t size);
