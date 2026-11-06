/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_net_peer_protocol.h"
#include "wendy_net_route_handoff.h"
#include "wendy_pki_operator.h"

#define WNO_ARTIFACT_MAX (WENDY_PKI_OPERATOR_ENVELOPE_MAX + 1024)
#define WNO_DIRECTORY_MAX 64
#define WNO_UNSUPPORTED 5
/* Immutable borrowed wire views. Keep the input alive throughout the worker
 * loan. The v4 router manifest owns all services; this typed operator projection
 * creates no additional gossip type or signed artifact. No borrowed data is copied. */
struct wno_manifest {
    const char *principal;
    size_t principal_size;
    const uint8_t *envelope;
    size_t envelope_size;
    const uint8_t *body, *signature;
    size_t body_size, signature_size;
    uint8_t instance[16], address[16];
    struct wn_origin origin;
    uint64_t revision;
    int64_t issued, expires;
    bool withdraw;
    const uint8_t *hashes[16];
    unsigned hash_count;
};
int wno_manifest_read(const void *, size_t, const char *tenant, struct wno_manifest *);
int wno_address(const char *principal, size_t, const uint8_t instance[16], uint8_t out[16]);
bool wno_in_pool(const uint8_t address[16]);

struct wno_entry {
    struct wno_entry *next;
#if WN_ROUTE_HANDOFF_ENABLED
    struct wn_route_handoff *handoff;
#endif
    uint8_t instance[16], address[16], digest[32];
    struct wn_origin origin;
    uint64_t revision;
    int64_t deadline_us, lease_deadline_us;
    time_t claim_not_before, claim_issuer_not_before, claim_expires;
    /* Availability hint only; losing bytes does not revoke the verified route. */
    uint8_t gossip_hash[32];
    bool gossip_cached, gossip_retired;
    size_t principal_size;
    char principal[];
};
struct wno_directory {
#if WN_ROUTE_HANDOFF_ENABLED
    time_t route_policy_base;
    int64_t route_policy_monotonic;
    bool route_policy_set, route_policy_uncertain;
#endif
    struct wno_entry *entries;
    struct wno_receipt *receipts;
    char tenant[37];
    unsigned count, limit;
    size_t receipt_count;
};
struct wno_receipt {
    struct wno_receipt *next;
    uint8_t instance[16], digest[32];
    uint64_t revision;
    int64_t receipt_deadline_us;
    bool withdrawn;
    size_t principal_size;
    char principal[];
};
const struct wno_receipt *wno_receipt_find(const struct wno_directory *, const char *principal,
                                          size_t, const uint8_t instance[16], int64_t monotonic_us);
int wno_init(struct wno_directory *, const char *tenant, unsigned limit);
void wno_deinit(struct wno_directory *);
/* Call only after primary chain AND this exact signature completed on crypto
 * worker. Independently checks identity, signed interval, revision and lease.
 * The signed duration starts once in monotonic time, with a separate dynamic
 * 10x compact receipt. Equal/lower revisions never restart either deadline.
 * No flash: all foreign proofs/receipts are bounded RAM, released mesh OFF.
 * Returns0 accepted/idempotent,1 stale/expired,3 capacity,-1 invalid. */
int wno_accept_manifest_verified(struct wno_directory *, const struct wno_manifest *,
                                 const struct wendy_pki_operator_peer *, int64_t unix_ms,
                                 int64_t monotonic_us);
bool wno_authorizes(const struct wno_directory *, const uint8_t address[16], uint64_t router,
                    uint16_t seqno, int64_t monotonic_us);
bool wno_live_address(const struct wno_directory *, const uint8_t address[16],
                      int64_t monotonic_us);
void wno_expire(struct wno_directory *, int64_t monotonic_us);
int64_t wno_next_deadline(const struct wno_directory *, int64_t monotonic_us);
size_t wno_memory(const struct wno_directory *);

/* Detached routing authority; current tuple is pending until actual Babel promotion. */
bool wno_pending_handoff(const struct wno_directory *, unsigned, int64_t, uint8_t[16], struct wn_origin *);
bool wno_complete_handoff(struct wno_directory *, const uint8_t[16], const struct wn_origin *, int64_t);
void wno_refresh_route_policy(struct wno_directory *, time_t, int64_t, bool);
bool wno_route_signature_current(const struct wno_entry *);
bool wno_handoff_request_needed(const struct wno_directory *, const uint8_t[16], const struct wn_origin *, int64_t);
void wno_handoff_requested(struct wno_directory *, const uint8_t[16], const struct wn_origin *, int64_t);
int64_t wno_route_deadline(const struct wno_directory *, const uint8_t[16], uint64_t, uint16_t, int64_t);

/* Cache-only transaction prelude: no authorization pruning or output. The
 * caller must fully refresh after admission success/failure before routing. */
void wno_cache_route_policy(struct wno_directory *, time_t, int64_t, bool);
