/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_net_service_protocol.h"
/* Single actor-owned, sparse service records/high-waters. No tables or payload
 * buffers are reserved for absent records. Admission/identity/freshness are
 * supplied by the catalogue runtime, not inferred from receipt storage. */
struct wns_entry {
    struct wns_entry *next;
    char *wire;
    size_t wire_size;
    uint8_t device[16],hash[32];
    uint8_t artifact_hash[32]; /* Local scheduling receipt, not authority. */
    uint64_t generation;
    int64_t issued,expires;
    uint16_t port;
    int listener; /* Volatile local ownership handle; absent after restart. */
    bool own,withdraw,unavailable,gateway,summary_verified,body_retired,artifact_known;
    char key[]; /* NUL-terminated app ID, service ID, then service type. */
};
struct wns_store {
    struct wns_entry *entries;
    size_t count,bytes,limit,byte_limit;
};
void wns_store_init(struct wns_store *,size_t entries,size_t bytes);
void wns_store_clear(struct wns_store *);
void wns_store_remove_origin(struct wns_store *,const uint8_t device[16]);
const char *wns_entry_service(const struct wns_entry *);
const char *wns_entry_type(const struct wns_entry *);
/* Only after the shared gossip cache has excluded active transfers. Keeps
 * verified browse fields and receipts; exact generation is not refilled. */
bool wns_store_retire_wire(struct wns_store *,const void *wire);
/* Actor-owned immutable storage. A transfer may retain wire bytes across
 * record replacement, pruning or store teardown. */
void wns_wire_retain(const void *);
void wns_wire_release(const void *);
struct wns_entry *wns_store_find(const struct wns_store *,const uint8_t device[16],
    const char *app,const char *service);
/* Only call with a fully verified record bound to its exact certificate and
 * current tenant. Does not confer projection readiness. 0 changed, 1 same or
 * older, 2 bounded capacity, -2 allocation, -1 inconsistent generation. */
int wns_store_put(struct wns_store *,const struct wns_record *,const void *wire,
    size_t wire_size,bool own);
/* Release expired payloads, retaining generation/hash receipts. */
void wns_store_prune(struct wns_store *,int64_t unix_ms);