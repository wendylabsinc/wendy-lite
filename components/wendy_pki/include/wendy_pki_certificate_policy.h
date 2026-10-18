#pragma once

#include <stdbool.h>
#include <mbedtls/x509_crt.h>

/* SHA-2 profile. Every verification callback must also apply the policy below. */
const mbedtls_x509_crt_profile *wendy_pki_certificate_profile(void);

/* Allow only strong RSA, EC or pure ML-DSA-65 keys and signatures.
 * An anchor must be an exact certificate from the pinned trust bundle.
 * Its self-signature is not part of the path, but its key must be strong. */
int wendy_pki_certificate_policy(const mbedtls_x509_crt *cert, bool trust_anchor);
