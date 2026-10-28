/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_pki_mesh.h"

#define WENDY_PKI_OPERATOR_PRINCIPAL_MAX 1024
#define WENDY_PKI_OPERATOR_BODY_MAX 32768
#define WENDY_PKI_OPERATOR_ENVELOPE_MAX (44 * 1024)

/* Separate primary operator identity. Never represent it as a device UUID.
 * This worker-owned output contains no private material. */
struct wendy_pki_operator_peer {
    char principal[WENDY_PKI_OPERATOR_PRINCIPAL_MAX + 1];
    time_t expires;
    uint8_t leaf_hash[32];
    uint8_t spki[WENDY_PKI_MESH_SPKI_MAX];
    size_t spki_size;
};
/* Shape only: exact serialized URI bytes, canonical tenant and operator kind.
 * URI escaping remains opaque; this function grants no trust. */
int wendy_pki_operator_principal(const char *,size_t,const char *tenant);
/* Worker-only primary v4-manifest verification. The peer must come from independently
 * verified primary client-auth roots; a Lite authority twin is not a root. */
int wendy_pki_operator_manifest_verify(const struct wendy_pki_operator_peer *,
    const void *body,size_t,const uint8_t *signature,size_t);
int wendy_pki_operator_chain(const uint8_t *const *der,const size_t *,size_t,
    const uint8_t *roots,size_t roots_size,const char *tenant,time_t,
    struct wendy_pki_operator_peer *);
