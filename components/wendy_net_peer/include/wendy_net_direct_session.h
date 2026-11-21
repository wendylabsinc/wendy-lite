#pragma once
#include "wendy_net_direct_flows.h"
#include "wendy_net_direct_exchange.h"

#define WN_DIRECT_CARRIER_LOST 2
struct wn_direct_session_config {
    struct wn_direct_flows *flows;
    uint8_t identity_digest[32], role;
    uint32_t selected;
    int64_t deadline, recovery_us;
    int (*random)(void *, uint8_t *, size_t);
    void *random_arg;
    /* Called by the actor; policy/config/key invalidation returns an error.
     * Deadline may only shorten and is independent of carrier TLS resumption. */
    int (*check)(void *, int64_t now, int64_t *deadline);
    void *check_arg;
    /* Each record array has 2*flow slots, plan has 4*flow slots. Charge all to
     * the network ledger before advertising capability or accepting an OFFER. */
    struct wn_direct_recovery_record *local, *remote, *scratch;
    struct wn_direct_recovery_step *plan;
};
struct wn_direct_session {
    struct wn_direct_session_config cfg;
    struct wn_direct_session_binding binding;
    struct wn_direct_generation gate;
    struct wn_direct_exchange exchange;
    wn_direct_exporter exporter;
    void *export_arg;
    void *carrier_owner; /* Actor-owned exclusive framed adapter for this token. */
    uint64_t token, last_token;
    uint32_t alias;
    enum wn_direct_mode mode;
    uint8_t nonce[16], wire[WN_DIRECT_MAX_FRAME];
    size_t wire_size;
    int64_t now, security_deadline, outage_deadline, setup_deadline, promotion_deadline;
    /* exchanging means the exchange object exists; it remains true after ACK.
     * Use frozen() below to decide whether flow mutation must wait. */
    bool promotion_initiator; /* Trusted local physical dial direction. */
    bool retired;             /* Orderly bilateral idle, distinct from terminal closure. */
    bool initialized, closed, attached, active, exchanging, peer_known, output_control;
};
static inline bool wn_direct_session_frozen(const struct wn_direct_session *s)
{
    return s->attached && !s->active;
}
int wn_direct_session_init(struct wn_direct_session *, const struct wn_direct_session_config *,
                           int64_t now);
/* Called only after authenticated hello, duplicate selection and BLE eligibility.
 * Token is strictly increasing per logical session, even for resumed TLS. Alias
 * is nonzero and never reused on that TLS incarnation. Exporter must belong to
 * this admitted TLS connection; tickets are never logical session authority. */
int wn_direct_session_attach(struct wn_direct_session *, uint64_t token, uint32_t alias,
                             const uint8_t identity_digest[32], uint32_t selected, int64_t deadline,
                             wn_direct_exporter, void *, int64_t now);
/* Fence and join the old carrier worker before lost, including its pending
 * writer references. Retains sockets, capability and nonextending outage bound. */
void wn_direct_session_lost(struct wn_direct_session *, uint64_t token, int64_t now);
void wn_direct_session_close(struct wn_direct_session *);
/* Called by the upper adapter only after its record and ciphertext output has
 * drained. Returns1 for orderly bilateral idle retirement,0 while still busy. */
int wn_direct_session_retire(struct wn_direct_session *);
/* tick: >=0 progress/idle, CARRIER_LOST means caller must tear down/fence the
 * expired candidate then call lost; negative is terminal logical failure. */
int wn_direct_session_tick(struct wn_direct_session *, int64_t now);
/* next: 1=immutable complete record,0=idle,negative=terminal. accepted follows
 * writer COPY ownership, before processing input, never TLS write completion. */
int wn_direct_session_next(struct wn_direct_session *, int64_t now, const uint8_t **, size_t *);
int wn_direct_session_accepted(struct wn_direct_session *);
int wn_direct_session_receive(struct wn_direct_session *, uint64_t token, const uint8_t *, size_t,
                              int64_t now, uint32_t *fresh_id);
/* Complete a backend operation in one actor turn. CAPACITY while negotiating
 * means retain/retry the completion, without closing/redialling the backend.
 * A successful result takes fd ownership only on return0; a refusal uses fd=-1. */
int wn_direct_session_complete(struct wn_direct_session *, uint32_t id, uint16_t result, int fd);
/* Authorized actor-owned memory endpoint. Caller retains its backend lifetime
 * by peer serial+flow ID and services the lane buffers without a socket. */
int wn_direct_session_complete_memory(struct wn_direct_session *, uint32_t id);

/* Upper admission is authenticated independently of the carrier. Caller first
 * fences/joins the old direct worker and calls lost, preserving the underlay.
 * Exporter is from the actual upper control TLS; identity and selected mode
 * are locally validated, never taken from untrusted OFFER fields.
 * initiator is the local transport dial direction. A preferred competing dial
 * may supersede an uncommitted control; callers must fence pumps by token. */
int wn_direct_session_promote(struct wn_direct_session *, uint64_t token, uint32_t alias,
                              const uint8_t identity_digest[32], uint32_t selected,
                              int64_t deadline, wn_direct_exporter, void *, bool initiator,
                              int64_t now);
/* Exclusively claim one successfully opened flow for its upper handshake.
 * Storage is caller-owned/ledger-charged and must remain live until commit or
 * flow/session reset. Pending backend result returns CAPACITY. Export callback
 * must use the actual per-flow upper TLS and the requested promotion label. */
int wn_direct_session_start_binding(
    struct wn_direct_session *, uint32_t id, struct wn_direct_promoted_binding *, int initiator,
    int (*exporter)(void *, const char *, const uint8_t[32], uint8_t[32]), void *, int64_t now);
/* Consumes upper ownership only on success, after the claimed handshake is
 * done. Failure after binding.commit_possible requires terminating the flow,
 * never attaching it again as a fresh BLE stream. */
int wn_direct_session_commit_flow(struct wn_direct_session *, uint32_t id,
                                  struct wn_direct_promoted_binding *,
                                  const struct wn_direct_upper *, int64_t now);
