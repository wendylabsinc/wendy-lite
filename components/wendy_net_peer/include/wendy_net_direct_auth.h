#pragma once
#include "wendy_net_direct_identity.h"
#include "wendy_pki_mesh.h"

/* Value-only policy: safe to copy into the retained registry allocation. */
struct wn_direct_policy {
    struct wendy_pki_mesh_identity identity;
    struct wendy_pki_mesh_public_index certificate;
    int64_t deadline;
    bool operator_peer;
};
struct wn_direct_auth {
    struct wn_direct_policy policy;
    struct wn_direct_identity_pair identities;
};
/* Actor exclusively owns completed TLS (no crypto loan). Operator instance is
 * from its validated hello; device instance comes from certificate identity.
 * This grants no carrier eligibility: caller still enforces physical BLE,
 * negotiated capability and duplicate selection before registry admission. */
int wn_direct_auth_capture(wendy_pki_connection *, const struct wendy_pki_mesh_identity *,
                           const uint8_t operator_instance[16], int64_t now,
                           struct wn_direct_auth *);
int wn_direct_policy_check(void *, int64_t now, int64_t *deadline);
