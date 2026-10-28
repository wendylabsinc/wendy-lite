#pragma once
#include <stddef.h>
#include <stdint.h>

/* Confirm the pre-PSA startup allocator hook and enable task-local ownership.
 * app_main must call this before application networking/core initialization. */
int wendy_pki_memory_init(void);

/* PSA initialization is shared by enrollment, TLS, and standalone verifiers. */
int wendy_pki_crypto_init(void);
/* Process-global PSA table metadata only, with the universal prefix/free ABI.
 * Real key bytes retain the initiating context's allocation scope. */
void *wendy_pki_crypto_shared_calloc(size_t count,size_t bytes);
/* Retire empty extra metadata tables; preserves all live keys and initial cache.
 * Actor-side closes skip synchronous work; final OFF submits its own future. */
void wendy_pki_crypto_cleanup(void);
int wendy_pki_sha256(const uint8_t *data, size_t size, uint8_t hash[32]);
/* Generate the same P-256 SEC1 DER stored by earlier firmware. On success,
 * return the length; the DER occupies the end of the caller's buffer. */
int wendy_pki_generate_key_der(uint8_t *buffer, size_t capacity);
