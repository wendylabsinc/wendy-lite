#include "wendy_net_direct_auth.h"
#include "wendy_net_direct_registry.h"
#include "wendy_net_peer_protocol.h"
#include "wendy_pki_operator.h"
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(struct wn_direct_policy) <= WN_DIRECT_POLICY_MAX,
               "retained direct policy capacity");

int wn_direct_policy_check(void *arg, int64_t now, int64_t *deadline)
{
    const struct wn_direct_policy *p = arg;
    if (!p || !deadline || now < 0 || now >= p->deadline ||
        !wendy_pki_mesh_identity_current(&p->identity, now) ||
        !wendy_pki_mesh_public_index_current(&p->certificate, &p->identity))
        return -1;
    if (p->deadline < *deadline)
        *deadline = p->deadline;
    return 0;
}
int wn_direct_auth_capture(wendy_pki_connection *connection,
                           const struct wendy_pki_mesh_identity *identity,
                           const uint8_t operator_instance[16], int64_t now,
                           struct wn_direct_auth *out)
{
    if (!out)
        return -1;
    memset(out, 0, sizeof *out);
    if (!connection || !identity || now < 0)
        return -1;
    uint8_t tenant[16];
    if (strnlen(identity->tenant, sizeof identity->tenant) != 36 ||
        strnlen(identity->device, sizeof identity->device) != 36 ||
        strnlen(identity->peer, sizeof identity->peer) > 36 ||
        wn_uuid_parse(identity->tenant, tenant))
        return -1;
    struct wn_direct_auth auth = {0};
    auth.policy.identity = *identity;
    if (wendy_pki_mesh_binding_deadline(connection, &auth.policy.deadline) ||
        wendy_pki_mesh_public_index_snapshot(connection, identity, &auth.policy.certificate) ||
        wn_direct_policy_check(&auth.policy, now, &auth.policy.deadline))
        return -1;
    struct wn_direct_authenticated_endpoint local = {0}, peer = {0};
    if (wendy_pki_mesh_key_bindings(connection, local.key, peer.key) ||
        wn_uuid_parse(identity->device, local.instance))
        return -1;
    char own[128], remote[128];
    int n = snprintf(own, sizeof own, "spiffe://wendy.sh/tenant/%s/device/%s", identity->tenant,
                     identity->device);
    if (n < 0 || (size_t)n >= sizeof own)
        return -1;
    local.principal = own;
    local.principal_size = (size_t)n;
    const struct wendy_pki_operator_peer *op = wendy_pki_mesh_authenticated_operator(connection);
    if (op) {
        if (!operator_instance)
            return -1;
        peer.role = 1;
        peer.principal = op->principal;
        peer.principal_size = strnlen(op->principal, sizeof op->principal);
        memcpy(peer.instance, operator_instance, 16);
    } else {
        if (wn_uuid_parse(identity->peer, peer.instance))
            return -1;
        n = snprintf(remote, sizeof remote, "spiffe://wendy.sh/tenant/%s/device/%s",
                     identity->tenant, identity->peer);
        if (n < 0 || (size_t)n >= sizeof remote)
            return -1;
        peer.principal = remote;
        peer.principal_size = (size_t)n;
    }
    if (wn_direct_identity_pair(&local, &peer, &auth.identities))
        return -1;
    auth.policy.operator_peer = op != NULL;
    *out = auth;
    return 0;
}
