/* SPDX-License-Identifier: Apache-2.0
 * Single-owner routing transaction adapter. No sockets, tasks or maximum-size
 * allocations at idle. The caller serializes access, including packet lookup.
 */
#pragma once
#include "wendy_babel.h"
#include "wendy_net_directory.h"

#define WNR_JOURNAL_HEADER 84
#define WNR_JOURNAL_MAX                                                        \
    (WNR_JOURNAL_HEADER + WB_HISTORY_MAX + WND_RECEIPTS_MAX + 32)
#define WNR_LAN_COST 128
#define WNR_BLE_COST 8192

struct wnr_config
{
    const char *tenant, *device;
    uint8_t trust_hash[32];
    uint64_t router, seed;
    /* Single-carrier SRAM profile still uses ordinary authorized routing for
     * local VIP traffic but never forwards packets between remote endpoints. */
    bool non_transit;
    /* Single authenticated neighbour is the gateway for mesh addresses.
     * Retain local origin publication, not a remote per-origin routing table. */
    bool endpoint_gateway;
    void *context;
    /* Optional checkpoint adapter for portable fixtures. NULL commits only to
     * bounded live RAM without allocating serialized history. Firmware uses
     * NULL and starts each new runtime with a fresh Babel router ID. */
    int (*persist)(void *, const void *, size_t);
    /* Publish the signed exact local origin BEFORE its Babel updates. Called
     * on first attachment, sequence changes and at least every five minutes.
     * The caller reserves manifest revisions durably and admits gossip only
     * after signing successfully. These callbacks must not reenter the core. */
    int (*publish)(void *, const struct wn_origin *, int64_t unix_ms,
                   int64_t monotonic_us);
    int (*send)(void *, uint64_t link, const void *, size_t);
};
struct wnr_core
{
    struct wb_engine babel;
    struct wnd_directory directory;
    struct wne_cache endpoints;
    struct wnr_config config;
    uint8_t scope[76], saved_hash[32];
    int64_t epoch_us, now_us, unix_ms, published_us;
    uint16_t published_seqno;
    bool saved, published, ready, stopped, started,durable,publication_dirty,publication_pending;
    /* Borrowed diagnostic label; no heap storage or protocol fields. */
    const char *stop_stage;
    int stop_error;
    size_t checkpoint_bytes;
    uint8_t *checkpoint;
    size_t checkpoint_capacity;
    uint64_t detaching[WB_LINKS];
};

/* First call requires a zeroed core; deinit before reuse. Journal restoration
 * requires exact tenant, UUID, trust hash and router ID. Corruption fails
 * closed. Restore never restores live routes/identities. All times are supplied
 * by an independently verified clock. The monotonic epoch restarts Babel hold
 * times after reboot instead of treating system uptime as elapsed checkpoint
 * time. */
int wnr_init(struct wnr_core *, const struct wnr_config *, int64_t monotonic_us,
             const void *journal, size_t journal_size);
void wnr_deinit(struct wnr_core *);
/* Originate only this device's UUID-derived /128. Must precede other events. */
int wnr_start(struct wnr_core *, int64_t unix_ms, int64_t monotonic_us);
int wnr_identity(struct wnr_core *, const struct wendy_pki_mesh_peer *,
                 int64_t unix_ms, int64_t monotonic_us);
/* Same return values as wnd_accept for rejected/stale/unknown proofs. */
int wnr_manifest(struct wnr_core *, const void *, size_t, int64_t unix_ms,
                 int64_t monotonic_us);
/* Call attach only after same-tenant TLS and exact peer hello validation. */
int wnr_attach(struct wnr_core *, const char *peer, uint16_t cost,
               int64_t unix_ms, int64_t monotonic_us, uint64_t *link);
int wnr_detach(struct wnr_core *, uint64_t link, int64_t unix_ms,
               int64_t monotonic_us);
int wnr_receive(struct wnr_core *, uint64_t link, const void *, size_t,
                int64_t unix_ms, int64_t monotonic_us);
int wnr_tick(struct wnr_core *, int64_t unix_ms, int64_t monotonic_us);
/* Copies only a committed, presently authorized IPv6 /128 route. */
bool wnr_lookup(const struct wnr_core *, const uint8_t address[16],
                int64_t monotonic_us, struct wb_route *);
/* Only a current signed TLS capability with a live authorized route is usable.
 * Never infer an app transport/port from a discovery hint or device class. */
bool wnr_app_endpoint(const struct wnr_core *, const uint8_t device[16],
                      int64_t monotonic_us, uint16_t *port);
/* Signed mtls-v1 agent capability. The returned TCP stream carries the
 * operator's end-to-end TLS; no outer application TLS is required. */
bool wnr_agent_endpoint(const struct wnr_core *, const uint8_t device[16],
                        int64_t monotonic_us, uint16_t *port);
/* Returns 0 for a local packet, 1 for permitted transit (decrements hop limit),
 * -1 for invalid/unauthorized/unroutable and -2 for hop-limit expiry. Caller
 * generates ICMPv6 errors as appropriate; no packet is injected by this core.
 */
int wnr_packet(const struct wnr_core *, uint64_t incoming, void *packet,
               size_t size, int64_t monotonic_us, uint64_t *outgoing);
size_t wnr_memory(const struct wnr_core *);

int wnr_manifest_verified(struct wnr_core *,const void *,size_t,int64_t,int64_t);

bool wnr_busy(const struct wnr_core *);
