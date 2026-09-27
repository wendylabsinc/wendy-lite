#ifndef WENDY_PKI_VERIFY_H
#define WENDY_PKI_VERIFY_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>
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
