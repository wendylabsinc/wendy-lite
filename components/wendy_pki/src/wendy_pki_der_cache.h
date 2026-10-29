/* Derived PUBLIC certificate bytes only. Never an identity/trust assertion.
 * TLS setup binds these bytes to a verified local path, key, principal and time.
 */
#pragma once
#include "nvs.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#define PKI_DER_PARTS 8
struct pki_der_source
{
    nvs_handle_t handle;
    unsigned count;
    uint8_t hashes[PKI_DER_PARTS][32];
    bool ranges;
    uint32_t sizes[PKI_DER_PARTS];
};
/* Invalid/missing derived data is a cache miss. Main certificate is untouched.
 */
int pki_der_cache_open(nvs_handle_t, struct pki_der_source *);
/* 1 is an owned DER part, 0 the exact end, negative a read failure. Preserve
 * MBEDTLS_ERR_X509_ALLOC_FAILED so TLS can release optional reservations. */
/* PKI-owned output: release with pki_owned_free, or transfer to Mbed TLS. */
int pki_der_cache_read(void *, unsigned, uint8_t **, size_t *);
/* Hash actual public bytes in512B chunks when ranges are available. */
int pki_der_cache_hash(void *, unsigned, uint8_t[32], size_t *);
/* Optional derived public range cache. Caller holds the identity lock. A
 * failed preparation preserves the original full-part reader. Each range
 * read hashes the whole part in bounded chunks against the verified TLS
 * presentation's exact hash before returning success. */
int pki_der_cache_prepare_ranges(struct pki_der_source *);
int pki_der_cache_read_range(void *,unsigned,size_t,uint8_t *,size_t,
                             const uint8_t expected[32]);
/* Before replacing the main certificate, durably remove metadata FIRST.
 * Partial writes/power loss can leave unused parts, never an admitted chain. */
int pki_der_cache_invalidate(nvs_handle_t);
int pki_der_cache_build(nvs_handle_t, const uint8_t *pem, size_t);

/* Read-only content-addressed local public DER. Never builds/repairs or
 * invalidates flash on a miss. Returns bytes,1 for size-only,-1 missing/error. */
int pki_der_cache_part(struct pki_der_source *,const uint8_t hash[32],size_t offset,
                       uint8_t out[1024],size_t *total);
