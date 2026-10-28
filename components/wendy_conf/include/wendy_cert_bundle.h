#pragma once
#include <stddef.h>
#include <stdint.h>
/* Runtime bundles are concatenated complete DER certificates (at most eight).
 * PEM is accepted only by the import boundary. No terminating NUL is required.
 * All functions return zero on success. */
int wendy_cert_bundle_measure(const uint8_t *,size_t,size_t *);
int wendy_cert_bundle_import(const uint8_t *,size_t,uint8_t *,size_t,size_t *);
/* Returns 1 for a certificate, 0 at exact end, -1 for an invalid extent. */
int wendy_cert_der_next(const uint8_t *,size_t,size_t *,const uint8_t **,size_t *);
