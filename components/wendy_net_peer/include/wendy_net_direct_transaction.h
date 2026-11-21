#pragma once
#include "wendy_net_direct_binding.h"
#include "wendy_net_direct_generation.h"
#include "wendy_net_direct_recovery_plan.h"
struct wn_direct_session_binding {
    uint8_t session_id[32], capability[32], identity_digest[32], role;
};
/* Export the fixed direct-attachment label from the authenticated candidate
 * connection identified by token. Never cache/reuse an old TLS exporter. */
typedef int (*wn_direct_exporter)(void *, const uint8_t context[32], uint8_t out[32]);
struct wn_direct_transaction {
    struct wn_direct_generation *gate;
    uint64_t token, generation;
    uint8_t capability[32], exporter[32], context[32], proof[32], role;
    bool applied;
};
/* The transaction validates immutable snapshots without retaining actions. Old
 * workers must be joined, candidate identity authorized and resources reserved.
 * SessionID/capability are random RAM authority, never TLS tickets. */
int wn_direct_transaction_prepare(
    struct wn_direct_transaction *, const struct wn_direct_session_binding *,
    struct wn_direct_generation *, uint64_t token, const struct wn_direct_attachment *,
    const uint8_t local_nonce[16], const struct wn_direct_recovery_view *local,
    const struct wn_direct_recovery_view *remote, wn_direct_exporter, void *export_arg);
int wn_direct_transaction_peer_proof(struct wn_direct_transaction *, const uint8_t *, size_t);
/* Apply failure closes the entire session; no rollback after partial effects. */
int wn_direct_transaction_commit(struct wn_direct_transaction *,
                                 int (*apply)(void *),
                                 void *);
int wn_direct_transaction_activate(struct wn_direct_transaction *);
/* Use only once no protocol retransmission may refer to this transaction. */
void wn_direct_transaction_clear(struct wn_direct_transaction *);
