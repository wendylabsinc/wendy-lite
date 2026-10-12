#ifndef WENDY_OPERATOR_AUTH_H
#define WENDY_OPERATOR_AUTH_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "mbedtls/x509_crt.h"
#include "wendy_peer_role.h"

struct wendy_operator_auth {
    char tenant[37];
    bool allow_device;
    /* Set by verification and pinned for subsequent TLS renegotiations.
     * Use only after the complete handshake and chain verification succeed. */
    enum wendy_peer_role role;
};

/* Derive the tenant from the locally provisioned device certificate. Unknown,
 * ambiguous or non-device identities fail closed. Returns zero on success. */
int wendy_operator_auth_init(struct wendy_operator_auth *auth,
                             const uint8_t *device_der, size_t size);

/* Identity and explicit clientAuth checks only. The TLS handshake must also
 * authenticate the chain, validity and possession of the private key. */
int wendy_operator_auth_check(const mbedtls_x509_crt *crt, const char *tenant);

/* Classify one same-tenant operator/device URI with explicit clientAuth.
 * Identity policy only: TLS must verify the chain and private-key possession. */
enum wendy_peer_role wendy_peer_auth_role(const mbedtls_x509_crt *crt,
                                          const char *tenant);

/* mbedTLS verification callback for REQUIRED client authentication. Never
 * clears chain verification flags. ctx points to struct wendy_operator_auth.
 * Device clients require allow_device=true; the default is operator-only. */
int wendy_operator_auth_verify(void *ctx, mbedtls_x509_crt *crt,
                               int depth, uint32_t *flags);

#endif
