#pragma once

#include <mbedtls/x509_crt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Append up to eight complete DER certificates directly to an initialized
 * chain. PEM is decoded at this import boundary and always copied by Mbed TLS.
 * For DER with borrow=true, input must remain immutable and alive until the
 * chain is freed. The caller owns/frees the chain, also after a partial failure.
 * This only parses certificates; callers still verify trust and usage policy. */
int pki_parse_certificate_bundle(mbedtls_x509_crt *cert, const uint8_t *data,
                                 size_t size, bool borrow);
