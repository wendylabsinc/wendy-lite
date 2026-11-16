#pragma once
#include "wendy_net_direct_session.h"
#include "wendy_net_carrier.h"

/* Zero-initialized per-carrier adapter; the referenced logical session must outlive it. The
 * existing mesh actor still owns wnc_pump and routes ordinary control/IP frames.
 * Direct callbacks never recursively pump TLS or block on a backend socket. */
struct wn_direct_carrier {
    struct wn_direct_session *session;
    struct wnc_carrier *carrier;
    uint64_t token;
    uint32_t alias;
    uint8_t role, proposal_received, proposal_outgoing;
    bool proposal_held, proposal_sent, proposal_accepted;
    int64_t proposal_retry, proposal_retry_delay, proposal_deadline;
    uint8_t *parked_offer; /* At most one 137-byte next-epoch OFFER, ledger charged. */
    int64_t (*now)(void *);
    void *clock_arg;
    /* Zero means the backend operation is owned/queued. A positive stable result
     * refuses this OPEN. Caller authorizes the exact target and must eventually
     * complete an accepted operation by ID, disposing late unclaimed sockets. */
    uint16_t (*open)(void *, uint32_t, struct wn_direct_request);
    void *open_arg;
};
int wn_direct_carrier_bind(struct wn_direct_carrier *, struct wn_direct_session *,
                           struct wnc_carrier *, int64_t (*now)(void *), void *clock_arg,
                           uint16_t (*open)(void *, uint32_t, struct wn_direct_request),
                           void *open_arg);
/* Copies a bounded burst to the ordered carrier queue. LIMIT/NOMEM retains
 * the same record and returns progress/idle; the actor must continue ingress.
 * Negative return retires the physical carrier, not implicitly all app sockets. */
int wn_direct_carrier_flush(struct wn_direct_carrier *, unsigned max_records);
/* Call only after the actor fenced its TLS worker and wnc_deinit discarded all
 * queued writer references. This detaches but preserves the logical session. */
int wn_direct_carrier_unbind(struct wn_direct_carrier *, int64_t now);

/* Promotion handoff: no worker may be borrowing the carrier/TLS. Unlike unbind,
 * leaves mesh IP/routing and copied old writes alive. Detaches logical state
 * after installing a discard callback, so late BLE records cannot mutate the
 * promoted epoch. Caller retains/releases its registry pin independently. */
int wn_direct_carrier_retire(struct wn_direct_carrier *, int64_t now);
/* Reusable-lane handoff, only after mutual capability negotiation. Detaches
 * the old owner but continues draining its records. A next-epoch OFFER can be
 * retained until the runtime proves bilateral retirement and binds alias+1.
 * This function alone never authorizes creating a fresh logical epoch. */
int wn_direct_carrier_park(struct wn_direct_carrier *, int64_t now);

/* Only coordinator0 proposes. Participant1 promptly answers BUSY unless it
 * can reserve local outgoing admission. Zero waits, one means both reserved,
 * two permanently retires the lane, negative is a carrier error. Reservation
 * callbacks are actor-owned; caller releases after binding the active epoch
 * or terminating the physical link. No original application is redialed. */
int wn_direct_carrier_propose(struct wn_direct_carrier *, bool retired, bool permitted,
                              bool (*reserve)(void *), void (*release)(void *), void *arg,
                              int64_t now);

/* A newly authenticated carrier negotiated a deferred lane. No logical owner
 * exists yet; alias zero reserves the first actual epoch's alias one. */
int wn_direct_carrier_defer(struct wn_direct_carrier *, struct wnc_carrier *, uint8_t role,
                            int64_t (*now)(void *), void *clock_arg,
                            uint16_t (*open)(void *, uint32_t, struct wn_direct_request),
                            void *open_arg);
