#pragma once
#include <stddef.h>
#include <stdint.h>

/* PSA initialization is shared by enrollment, TLS, and standalone verifiers. */
int wendy_pki_crypto_init(void);
int wendy_pki_sha256(const uint8_t *data, size_t size, uint8_t hash[32]);
/* Generate the same P-256 SEC1 DER stored by earlier firmware. On success,
 * return the length; the DER occupies the end of the caller's buffer. */
int wendy_pki_generate_key_der(uint8_t *buffer, size_t capacity);
