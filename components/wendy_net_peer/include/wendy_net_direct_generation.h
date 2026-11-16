#pragma once
#include <stdbool.h>
#include <stdint.h>
enum wn_direct_mode { WN_DIRECT_BLE, WN_DIRECT_PROMOTED };
enum wn_direct_phase {
    WN_DIRECT_ACTIVE,
    WN_DIRECT_SUSPENDED,
    WN_DIRECT_NEGOTIATING,
    WN_DIRECT_PREPARING,
    WN_DIRECT_READY,
    WN_DIRECT_COMMITTING,
    WN_DIRECT_CLOSED
};
/* Actor-owned fence. Tokens identify authenticated TLS connections locally;
 * resumed TLS must get a fresh token. Proof, authorization, resources and all
 * flow reconciliation must succeed before READY. Old I/O workers must be
 * fenced/joined before FROZEN and before capture of snapshot/context. */
struct wn_direct_generation {
    enum wn_direct_phase phase;
    enum wn_direct_mode mode, pending_mode;
    bool promotion, initialized;
    uint64_t generation, reserved, token, pending_generation, pending_token;
    uint8_t context[32];
};
/* First attachment reserves generation1 and cannot carry bytes before ACK. */
int wn_direct_generation_init_pending(struct wn_direct_generation *);
int wn_direct_generation_init(struct wn_direct_generation *, uint64_t generation, uint64_t token,
                              enum wn_direct_mode);
bool wn_direct_generation_next(const struct wn_direct_generation *, uint64_t *);
bool wn_direct_generation_allows(const struct wn_direct_generation *, uint64_t token,
                                 uint64_t generation);
int wn_direct_generation_frozen(struct wn_direct_generation *, uint64_t token);
/* Burn before OFFER: nonce/view-dependent context is bound later by begin. */
int wn_direct_generation_reserve(struct wn_direct_generation *, uint64_t token, uint64_t generation,
                                 enum wn_direct_mode);
int wn_direct_generation_begin(struct wn_direct_generation *, uint64_t token, uint64_t generation,
                               enum wn_direct_mode, const uint8_t context[32]);
int wn_direct_generation_ready(struct wn_direct_generation *, uint64_t token, uint64_t generation);
/* Record before attempting coordinator COMMIT write, or upon validated COMMIT
 * receipt. An ambiguous write must never roll back a reserved generation. */
int wn_direct_generation_commit(struct wn_direct_generation *, uint64_t token, uint64_t generation);
/* Coordinator: after COMMIT_ACK. Participant: after ordered writer owns ACK.
 * Independent upper readers hold/backpressure early data until activation. */
int wn_direct_generation_activate(struct wn_direct_generation *, uint64_t token,
                                  uint64_t generation);
/* Connection death, NOT mere underlay outage. Promoted death after COMMIT is
 * terminal because bare app bytes may have escaped custom replay retention. */
bool wn_direct_generation_lost(struct wn_direct_generation *, uint64_t token);
/* Timeout, trust invalidation or owner shutdown: terminal, callback-fenced. */
void wn_direct_generation_close(struct wn_direct_generation *);
