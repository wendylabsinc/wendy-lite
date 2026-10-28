/* SPDX-License-Identifier: Apache-2.0
 * Sparse signed v4 route directory for full native routers. Single owner.
 */
#pragma once
#include "wendy_net_peer_protocol.h"
#include "wendy_pki_mesh.h"
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif
#if defined(ESP_PLATFORM) && CONFIG_WENDY_NET_CONSTRAINED_PROFILE
#define WND_ORIGINS_MAX 32
#else
#define WND_ORIGINS_MAX 128
#endif
#define WND_RECEIPTS_MAX (6 + 56 * WND_ORIGINS_MAX)
#define WND_UNSUPPORTED 5
struct wnd_manifest
{
    uint8_t device[16];
    struct wn_origin origin;
    uint64_t revision;
    int64_t issued, expires;
    uint16_t agent_port, tls_app_port, quic_app_port;
    bool withdraw, agent_mtls, platform_lite, sensors;
};
struct wnd_entry
{
    struct wnd_entry *next;
    /* Owns exactly peer.spki_size public DER bytes, allocated on identity admission. */
    struct wendy_pki_mesh_key peer;
    uint8_t device[16], address[16], body_hash[32];
    struct wnd_manifest manifest;
    uint64_t revision;
    int64_t deadline_us;
    /* Adapter's latest artifact hint; not authorization or durable history. */
    uint8_t gossip_hash[32];
    bool gossip_cached;
    bool gossip_retired;
    bool pending_receipt; /* Adapter-owned pending publication marker. */
    /* Adapter cache for an independently verified exact public chain in this
     * boot/trust epoch. Not persisted as identity or route authorization. */
    uint8_t certificate_chain_hash[32],certificate_leaf_hash[32];
    int64_t certificate_chain_until;
    uint64_t key_serial;
    bool key_pinned;
};
struct wnd_directory
{
    struct wnd_entry *entries;
    char tenant[37];
    uint8_t self[16], self_address[16];
    unsigned count;
    unsigned key_count,key_limit;
    uint64_t key_serial;
};
/* Endpoint-only verified projections. Entries grow on demand; no blob, key,
 * chain, route candidate or maximum-capacity array is retained here. */
#define WNE_ENDPOINTS_MAX 64
struct wne_entry {
    struct wne_entry *next;
    uint8_t device[16], body_hash[32], artifact_hash[32];
    uint64_t revision;
    int64_t deadline_us;
    uint16_t app_port, agent_port;
    bool agent_mtls, withdraw;
};
struct wne_cache {struct wne_entry *entries;unsigned count;};
void wne_clear(struct wne_cache *);
void wne_reap(struct wne_cache *,int64_t now);
/* Input is a projection of an independently verified manifest, with validity
 * already bounded by its certificate path. Updates preserve entry allocation.
 * 0 accepted;1 older;2 same revision with different body;3 allocation pressure. */
int wne_update(struct wne_cache *,const struct wnd_manifest *,const uint8_t hash[32],int64_t deadline,int64_t now);
bool wne_endpoint(const struct wne_cache *,const uint8_t device[16],bool agent,int64_t now,uint16_t *port);
void wnd_forget_keyless(struct wnd_directory *);
/* Manifest-specific extensible metadata reader. Original signed body remains
 * the artifact; the projection never replaces bytes used for hashes/gossip. */
int wnd_manifest_read(const struct wn_doc *,unsigned body,struct wnd_manifest *);
int wnd_init(struct wnd_directory *, const char *tenant, const char *self);
void wnd_deinit(struct wnd_directory *);
/* Call only after independently anchoring this exact identity's full chain. */
int wnd_identity(struct wnd_directory *, const struct wendy_pki_mesh_peer *);
/* May also trim a live cache. Never evicts pinned next-hop keys; returns3 if
 * pins prevent the requested trim. Key eviction preserves verified projections
 * and revision receipts; a later update needs its key fetched/verified again.
 * Attached next hops can be pinned. Async crypto owns independent key copies. */
int wnd_key_limit(struct wnd_directory *,unsigned limit);
int wnd_key_pin(struct wnd_directory *,const uint8_t device[16],bool pinned);
/* Expects SignedManifest itself, without a control envelope. Returns 0 for
 * accepted/idempotent;1 stale/expired;2 identity needed;-1 invalid;3 full.
 * Device adapters retain receipts in bounded RAM; no flash operation occurs. */
int wnd_accept(struct wnd_directory *, const void *, size_t, int64_t unix_ms,
               int64_t monotonic_us);
bool wnd_authorizes(const struct wnd_directory *, const uint8_t address[16],
                    uint64_t router, uint16_t seqno, int64_t monotonic_us);
bool wnd_address(const struct wnd_directory *, const uint8_t address[16],
                 int64_t monotonic_us);
/* Optional portable RAM snapshot helpers, never firmware persistence. Restore
 * retains revision receipts only, never live identities or routes. The caller
 * keeps the snapshot in the same tenant/device/trust epoch. */
/* out=NULL queries exact required bytes without allocation or mutation. */
int wnd_save(const struct wnd_directory *, void *, size_t);
int wnd_restore(struct wnd_directory *, const void *, size_t);
size_t wnd_memory(const struct wnd_directory *);

/* Runtime continuation only: exact immutable bytes have completed their
 * signature future. Still checks identity/lease/revision and derives expiry. */
int wnd_accept_verified(struct wnd_directory *,const void *,size_t,int64_t,int64_t);
