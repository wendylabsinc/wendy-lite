/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "certificate_fetch.h"
#include "wendy_pki_mesh.h"

struct wncs_part;
struct wncs_descriptor;
struct wncs_store {
    struct wncs_part *first,*last;
    struct wncs_descriptor *chains_first,*chains_last;
    /* bytes includes retained payload and entry/descriptor metadata. Allocator
     * prefix/alignment overhead is additionally charged by the runtime ledger. */
    size_t bytes,limit;
    unsigned count,chains,part_limit,chain_limit;
    bool opened;
    void *baseline_context;
    int (*baseline_read)(void *,const uint8_t hash[32],size_t,uint8_t out[WNCF_CHUNK],size_t *);
    struct wendy_pki_mesh_public_index baseline_index;
    bool baseline_index_enabled;
    bool (*baseline_current)(void *,const struct wendy_pki_mesh_public_index *);
};
/* A loan pins immutable bytes independently of the store lifetime. Close/off
 * drops only the cache reference; an active worker/transfer releases its loan
 * after completing, so the runtime ledger cannot report drained prematurely. */
struct wncs_loan {
    unsigned count;
    /* NULL part/entry with nonzero size denotes a local baseline part. The
     * independent PKI worker resolves it under its copied identity snapshot. */
    const uint8_t *parts[WNCF_CHAIN_MAX];
    size_t sizes[WNCF_CHAIN_MAX];
    struct wncs_part *entries[WNCF_CHAIN_MAX];
};
/* RAM only, allocation-free while empty. FIFO admission skips active loans.
 * A cache miss is ordinary: callers may re-fetch public DER from another peer. */
int wncs_open(struct wncs_store *,size_t limit);
int wncs_open_limits(struct wncs_store *,size_t limit,unsigned parts,unsigned chains);
void wncs_close(struct wncs_store *);
/* Drop all unloaned foreign DER and every foreign descriptor, without flash
 * work. Pinned active fetch/worker parts remain until release and a later trim.
 * Returns payload+metadata cache bytes released (ledger headers are additional). */
size_t wncs_trim(struct wncs_store *);
/* Read-only local public identity/issuer source. Same read result convention;
 * -2 means retry while identity is busy. Never supplies a trust assertion. */
void wncs_set_baseline(struct wncs_store *,void *,
    int (*)(void *,const uint8_t[32],size_t,uint8_t[WNCF_CHUNK],size_t *));
/* Once enabled, all local size/availability queries use only this copied RAM
 * index and its RAM-only currency callback, including misses/empty indexes.
 * Actual DER output still uses baseline_read. Index has store/node lifetime;
 * worker loans copy sizes and never borrow the index or store. */
void wncs_set_baseline_index(struct wncs_store *,const struct wendy_pki_mesh_public_index *,
    bool (*)(void *,const struct wendy_pki_mesh_public_index *));
int wncs_read(void *,const uint8_t hash[32],size_t offset,
               uint8_t out[WNCF_CHUNK],size_t *total);
/* RAM-resident foreign data only; never falls back to a local DER reader. */
int wncs_read_resident(struct wncs_store *,const uint8_t hash[32],size_t offset,
    uint8_t out[WNCF_CHUNK],size_t *total);
int wncs_put(void *,const uint8_t hash[32],const void *,size_t);
/* Owned full DER uses wendy_net_free on ESP (host libc remains compatible). */
int wncs_load(struct wncs_store *,const uint8_t hash[32],uint8_t **,size_t *);
int wncs_load_into(struct wncs_store *,const uint8_t hash[32],uint8_t *,size_t capacity,size_t *);
/* 0 success, 1 missing/busy, negative invalid input. No partial loan escapes. */
int wncs_pin_chain(struct wncs_store *,const struct wncf_chain *,struct wncs_loan *);
int wncs_pin_hashes(struct wncs_store *,const uint8_t hashes[][32],unsigned,
    struct wncs_loan *);
int wncs_pin_part(struct wncs_store *,const uint8_t hash[32],struct wncs_loan *);
void wncs_unpin(struct wncs_loan *);
/* Generic fetch retention adapters; release is safe after store close. */
void *wncs_retain(void *,const uint8_t hash[32]);
void wncs_release(void *);
/* Descriptor metadata survives payload eviction while bounded by the same
 * FIFO byte quota. Only call put after full identity/path verification. */
int wncs_chain_put(struct wncs_store *,const struct wncf_chain *,int64_t expires);
int wncs_chain_get(struct wncs_store *,const char *principal,int64_t now,
                    struct wncf_chain *);
