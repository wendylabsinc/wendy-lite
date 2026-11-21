#include "wendy_net_direct_transaction.h"
#include <mbedtls/platform_util.h>
#include <string.h>
static bool nonzero(const uint8_t *p, size_t n)
{
    uint8_t value = 0;
    while (n--)
        value |= *p++;
    return value != 0;
}
int wn_direct_transaction_prepare(struct wn_direct_transaction *out,
                                  const struct wn_direct_session_binding *binding,
                                  struct wn_direct_generation *gate, uint64_t token,
                                  const struct wn_direct_attachment *a, const uint8_t nonce[16],
                                  const struct wn_direct_recovery_view *local,
                                  const struct wn_direct_recovery_view *remote,
                                  wn_direct_exporter exporter, void *export_arg)
{
    if (!out || !binding || !gate || !a || !nonce || !exporter ||
        (gate->phase != WN_DIRECT_SUSPENDED && gate->phase != WN_DIRECT_NEGOTIATING) ||
        binding->role > 1 || !nonzero(binding->session_id, 32) ||
        !nonzero(binding->capability, 32) || !nonzero(binding->identity_digest, 32) ||
        !nonzero(nonce, 16) || memcmp(a->session_id, binding->session_id, 32) ||
        memcmp(a->identity_digest, binding->identity_digest, 32))
        return -1;
    const uint8_t *own = binding->role ? a->participant_nonce : a->coordinator_nonce,
                  *other = binding->role ? a->coordinator_nonce : a->participant_nonce;
    if (memcmp(own, nonce, 16) || !nonzero(other, 16))
        return -1;
    struct wn_direct_transaction t = {.gate = gate,
                                      .token = token,
                                      .generation = a->generation,
                                      .role = binding->role};
    if (wn_direct_attachment_context(a, t.context) ||
        wn_direct_generation_begin(gate, token, a->generation, (enum wn_direct_mode)a->mode,
                                   t.context))
        return -1;
    uint8_t digest[32];
    const struct wn_direct_recovery_view *c = binding->role ? remote : local,
                                         *p = binding->role ? local : remote;
    if (wn_direct_recovery_digest(c, p, digest) || memcmp(digest, a->snapshot_digest, 32) ||
        wn_direct_recovery_validate(local, remote, binding->role) ||
        exporter(export_arg, t.context, t.exporter))
        goto failed;
    memcpy(t.capability, binding->capability, 32);
    if (wn_direct_attachment_proof(t.capability, t.exporter, t.context, t.role, t.proof))
        goto failed;
    *out = t;
    mbedtls_platform_zeroize(&t, sizeof t);
    return 0;
failed:
    wn_direct_generation_lost(gate, token);
    mbedtls_platform_zeroize(&t, sizeof t);
    return -1;
}
int wn_direct_transaction_peer_proof(struct wn_direct_transaction *t, const uint8_t *proof,
                                     size_t size)
{
    if (!t || !t->gate ||
        wn_direct_attachment_verify(t->capability, t->exporter, t->context, (uint8_t)(1 - t->role),
                                    proof, size))
        return -1;
    return wn_direct_generation_ready(t->gate, t->token, t->generation);
}
int wn_direct_transaction_commit(struct wn_direct_transaction *t,
                                 int (*apply)(void *),
                                 void *arg)
{
    if (!t || !t->gate)
        return -1;
    if (!t->applied) {
        if (!apply || t->gate->phase != WN_DIRECT_READY || t->gate->pending_token != t->token ||
            t->gate->pending_generation != t->generation)
            return -1;
        if (apply(arg)) {
            wn_direct_generation_close(t->gate);
            return -1;
        }
        t->applied = true;
    }
    return wn_direct_generation_commit(t->gate, t->token, t->generation);
}
int wn_direct_transaction_activate(struct wn_direct_transaction *t)
{
    return t && t->gate && t->applied
               ? wn_direct_generation_activate(t->gate, t->token, t->generation)
               : -1;
}
void wn_direct_transaction_clear(struct wn_direct_transaction *t)
{
    if (t)
        mbedtls_platform_zeroize(t, sizeof *t);
}
