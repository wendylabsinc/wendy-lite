#pragma once

#include <stddef.h>
#include <stdint.h>

#define WENDY_CERT_BUNDLE_MAX_BYTES 65536U
#define WENDY_CERT_BUNDLE_MAX_CERTS 8U

/* Runtime bundles are concatenated complete DER certificates. PEM is accepted
 * only by the import boundary; no terminating NUL is required. These helpers
 * check DER extents, not X.509 certificate semantics or trust. Return 0 on
 * success, -1 on invalid input/insufficient output. Output may be partial on
 * failure. Measure calculates capacity; import also checks decoded DER extents.
 * Input/output buffers must not overlap. */
int wendy_cert_bundle_measure(const uint8_t *data, size_t size, size_t *bytes);
int wendy_cert_bundle_import(const uint8_t *data, size_t size, uint8_t *out,
                             size_t capacity, size_t *bytes);
/* Returns 1 for a sequence, 0 at exact end, -1 for an invalid extent.
 * Updates offset and outputs only when it returns 1. */
int wendy_cert_der_next(const uint8_t *data, size_t size, size_t *offset,
                        const uint8_t **der, size_t *bytes);
