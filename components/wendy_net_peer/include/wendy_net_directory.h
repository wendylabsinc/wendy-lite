/* SPDX-License-Identifier: Apache-2.0
 * Sparse signed v4 route directory for full native routers. Single owner.
 */
#pragma once
#include "wendy_net_peer_protocol.h"
#include "wendy_net_route_handoff.h"
#include "wendy_pki_mesh.h"
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif
#if defined(ESP_PLATFORM) && CONFIG_WENDY_NET_CONSTRAINED_PROFILE
#define WND_ORIGINS_MAX 32
#else
#define WND_ORIGINS_MAX 128
#endif
#define WND_RECEIPTS_MAX (8 + 65 * WND_ORIGINS_MAX)
#define WND_UNSUPPORTED 5
struct wnd_manifest {
    uint8_t device[16];
    struct wn_origin origin;
    uint64_t revision;
    int64_t issued, expires;
    /* Local verifier metadata, never encoded in the signed announcement. */
    time_t certificate_not_before, certificate_issuer_not_before, certificate_expires;
    uint16_t agent_port, tls_app_port, quic_app_port;
    bool withdraw, agent_mtls, platform_lite, sensors;
};
struct wnd_entry {
    struct wnd_entry *next;
#if WN_ROUTE_HANDOFF_ENABLED
    struct wn_route_handoff *handoff;
#endif
    /* Owns exactly peer.spki_size public DER bytes, allocated on identity admission. */
    struct wendy_pki_mesh_key peer;
    uint8_t device[16], address[16], body_hash[32];
    struct wnd_manifest manifest;
    uint64_t revision;
    int64_t deadline_us, lease_deadline_us;
    /* Adapter's latest artifact hint; not authorization or durable history. */
    uint8_t gossip_hash[32];
    bool gossip_cached;
    bool gossip_retired;
    bool pending_receipt; /* Adapter-owned pending publication marker. */
    /* Adapter cache for an independently verified exact public chain in this
     * boot/trust epoch. Not persisted as identity or route authorization. */
    uint8_t certificate_chain_hash[32], certificate_leaf_hash[32];
    int64_t certificate_chain_until;
    uint64_t key_serial;
    bool key_pinned;
};
struct wnd_directory {
#if WN_ROUTE_HANDOFF_ENABLED
    time_t route_policy_base;
    int64_t route_policy_monotonic;
    bool route_policy_set, route_policy_uncertain;
#endif
    struct wnd_entry *entries;
    struct wnd_receipt *receipts;
    char tenant[37];
    uint8_t self[16], self_address[16];
    unsigned count;
    unsigned key_count, key_limit;
    uint64_t key_serial;
    size_t receipt_count;
};
/* Separate from bounded active/key projections. A floor lives for ten signed
 * durations from first admission, never refreshed by an equal/lower revision. */
struct wnd_receipt {
    struct wnd_receipt *next;
    uint8_t device[16], body_hash[32];
    uint64_t revision;
    int64_t receipt_deadline_us;
    bool withdrawn;
};
/* Endpoint-only verified projections. Entries grow on demand; no blob, key,
 * chain, route candidate or maximum-capacity array is retained here. */
#define WNE_ENDPOINTS_MAX 64
struct wne_entry {
    struct wne_entry *next;
    uint8_t device[16], body_hash[32], artifact_hash[32];
    uint64_t revision;
    int64_t deadline_us;
    time_t certificate_not_before, certificate_issuer_not_before, certificate_expires;
    uint16_t app_port, agent_port;
    bool agent_mtls, withdraw;
};
struct wne_cache {
    struct wne_entry *entries;
    unsigned count;
};
void wne_clear(struct wne_cache *);
void wne_reap(struct wne_cache *, int64_t now);
/* Input is a projection of an independently verified manifest, with validity
 * already bounded by its certificate path. Updates preserve entry allocation.
 * 0 accepted;1 older;2 same revision with different body;3 allocation pressure. */
int wne_update(struct wne_cache *, const struct wnd_manifest *, const uint8_t hash[32],
               int64_t deadline, int64_t now);
bool wne_endpoint(const struct wne_cache *, const uint8_t device[16], bool agent, int64_t now,
                  uint16_t *port);
void wnd_forget_keyless(struct wnd_directory *);
/* Manifest-specific extensible metadata reader. Original signed body remains
 * the artifact; the projection never replaces bytes used for hashes/gossip. */
int wnd_manifest_read(const struct wn_doc *, unsigned body, struct wnd_manifest *);
int wnd_init(struct wnd_directory *, const char *tenant, const char *self);
void wnd_deinit(struct wnd_directory *);
/* Idle owner hook: clear 1x-expired projections and sweep 10x-expired floors. */
void wnd_expire(struct wnd_directory *, int64_t monotonic_us);
int64_t wnd_next_deadline(const struct wnd_directory *, int64_t monotonic_us);
const struct wnd_receipt *wnd_receipt_find(const struct wnd_directory *, const uint8_t device[16],
                                          int64_t monotonic_us);
/* Call only after independently anchoring this exact identity's full chain. */
int wnd_identity(struct wnd_directory *, const struct wendy_pki_mesh_peer *);
/* May also trim a live cache. Never evicts pinned next-hop keys; returns3 if
 * pins prevent the requested trim. Key eviction preserves verified projections
 * and revision receipts; a later update needs its key fetched/verified again.
 * Attached next hops can be pinned. Async crypto owns independent key copies. */
int wnd_key_limit(struct wnd_directory *, unsigned limit);
int wnd_key_pin(struct wnd_directory *, const uint8_t device[16], bool pinned);
/* Expects SignedManifest itself, without a control envelope. Expires-Issued
 * starts once at admission in this RAM epoch, with a 10x compact receipt.
 * Certificate policy is independently verified. Static signed bounds use the
 * signing leaf's NotBefore and accepted path's minimum NotAfter; local claim
 * metadata preserves leaf/issuer dates for the owner's current-clock checks.
 * unix_ms is ABI-only. Equal/lower revisions never restart either deadline.
 * Returns 0 for
 * accepted/idempotent;1 stale/expired;2 identity needed;-1 invalid;3 full.
 * Device receipts grow on demand in RAM; allocation pressure returns3 without
 * evicting another floor. No flash operation occurs. */
int wnd_accept(struct wnd_directory *, const void *, size_t, int64_t unix_ms, int64_t monotonic_us);
bool wnd_authorizes(const struct wnd_directory *, const uint8_t address[16], uint64_t router,
                    uint16_t seqno, int64_t monotonic_us);
bool wnd_address(const struct wnd_directory *, const uint8_t address[16], int64_t monotonic_us);
/* Optional portable RAM snapshot helpers, never firmware persistence. Restore
 * retains revision receipts only, never live identities or routes. The caller
 * keeps the snapshot in the same tenant/device/trust epoch. */
/* out=NULL queries exact required bytes without allocation or mutation. */
int wnd_save(const struct wnd_directory *, void *, size_t);
int wnd_restore(struct wnd_directory *, const void *, size_t);
size_t wnd_memory(const struct wnd_directory *);

/* Runtime continuation only: exact immutable bytes have completed their
 * signature future. Still checks identity/lease/revision and derives expiry. */
int wnd_accept_verified(struct wnd_directory *, const void *, size_t, int64_t, int64_t);

/* Detached routing authority; current tuple is pending until actual Babel promotion. */
bool wnd_pending_handoff(const struct wnd_directory *, unsigned, int64_t, uint8_t[16], struct wn_origin *);
bool wnd_complete_handoff(struct wnd_directory *, const uint8_t[16], const struct wn_origin *, int64_t);
void wnd_refresh_route_policy(struct wnd_directory *, time_t, int64_t, bool);
bool wnd_route_signature_current(const struct wnd_entry *);
bool wnd_handoff_request_needed(const struct wnd_directory *, const uint8_t[16], const struct wn_origin *, int64_t);
void wnd_handoff_requested(struct wnd_directory *, const uint8_t[16], const struct wn_origin *, int64_t);
int64_t wnd_route_deadline(const struct wnd_directory *, const uint8_t[16], uint64_t, uint16_t, int64_t);

/* Full-router adapter only (gateway builds return false without mutation).
 * Only after this exact newly verified withdrawn body/signature is retained
 * as the relay wire. Never use new dates while retaining an older signature. */
bool wnd_withdraw_wire_committed(struct wnd_directory *, const uint8_t device[16], uint64_t,
                                  const uint8_t body_hash[32], const struct wendy_pki_mesh_key *,
                                  int64_t monotonic_us);

/* Cache-only transaction prelude: no authorization pruning or output. The
 * caller must fully refresh after admission success/failure before routing. */
void wnd_cache_route_policy(struct wnd_directory *, time_t, int64_t, bool);
