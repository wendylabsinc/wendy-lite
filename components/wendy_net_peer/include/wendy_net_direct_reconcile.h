#pragma once
#include "wendy_net_direct_buffer.h"
#include "wendy_net_direct_ack.h"
/* Capture after fencing/joining old attachment workers. Session generation,
 * OPEN identity and result must be authenticated and validated separately. */
struct wn_direct_snapshot {
    uint64_t acked, offered, tail, remote_limit;
    uint64_t consumed, received, limit;
    uint64_t send_final, receive_final;
    bool send_finished, receive_finished;
};
struct wn_direct_reconciliation {
    struct wn_direct_receipt outgoing;
    uint64_t incoming_final;
    bool incoming_finished, replay_fin;
};
bool wn_direct_snapshot_valid(const struct wn_direct_snapshot *);
struct wn_direct_snapshot wn_direct_snapshot(const struct wn_direct_sender *,
                                             const struct wn_direct_receiver *);
/* Pure validation. Validate ALL flows before applying any plan. On commit,
 * apply outgoing via send_state, restart replay at outgoing.received, and
 * record incoming FIN via receive_finish (not immediate socket shutdown). */
int wn_direct_reconcile(const struct wn_direct_snapshot *local,
                        const struct wn_direct_snapshot *remote,
                        struct wn_direct_reconciliation *out);
