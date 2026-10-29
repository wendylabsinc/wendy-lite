/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_net_peer_protocol.h"
#include "wendy_pki_operator.h"

#define WNO_ARTIFACT_MAX (WENDY_PKI_OPERATOR_ENVELOPE_MAX + 1024)
#define WNO_DIRECTORY_MAX 64
#define WNO_UNSUPPORTED 5
/* Immutable borrowed wire views. Keep the input alive throughout the worker
 * loan. The v4 router manifest owns all services; this typed operator projection
 * creates no additional gossip type or signed artifact. No borrowed data is copied. */
struct wno_manifest {
    const char *principal;size_t principal_size;
    const uint8_t *envelope;size_t envelope_size;
    const uint8_t *body,*signature;size_t body_size,signature_size;
    uint8_t instance[16],address[16];
    struct wn_origin origin;
    uint64_t revision;int64_t issued,expires;bool withdraw;
    const uint8_t *hashes[16];unsigned hash_count;
};
int wno_manifest_read(const void *,size_t,const char *tenant,struct wno_manifest *);
int wno_address(const char *principal,size_t,const uint8_t instance[16],uint8_t out[16]);
bool wno_in_pool(const uint8_t address[16]);

struct wno_entry {
    struct wno_entry *next;
    uint8_t instance[16],address[16],digest[32];
    struct wn_origin origin;uint64_t revision;
    int64_t deadline_us,retain_until_us;
    /* Availability hint only; losing bytes does not revoke the verified route. */
    uint8_t gossip_hash[32];bool gossip_cached,gossip_retired;
    size_t principal_size;
    char principal[];
};
struct wno_directory {
    struct wno_entry *entries;
    char tenant[37];unsigned count,limit;
};
int wno_init(struct wno_directory *,const char *tenant,unsigned limit);
void wno_deinit(struct wno_directory *);
/* Call only after primary chain AND this exact signature completed on crypto
 * worker. Independently checks identity, time, revision, collision and lease.
 * No flash: all foreign proofs/receipts are bounded RAM, released mesh OFF.
 * Returns0 accepted/idempotent,1 stale/expired,3 capacity,-1 invalid. */
int wno_accept_manifest_verified(struct wno_directory *,const struct wno_manifest *,
    const struct wendy_pki_operator_peer *,int64_t unix_ms,int64_t monotonic_us);
bool wno_authorizes(const struct wno_directory *,const uint8_t address[16],
    uint64_t router,uint16_t seqno,int64_t monotonic_us);
bool wno_live_address(const struct wno_directory *,const uint8_t address[16],int64_t monotonic_us);
void wno_expire(struct wno_directory *,int64_t monotonic_us);
size_t wno_memory(const struct wno_directory *);
