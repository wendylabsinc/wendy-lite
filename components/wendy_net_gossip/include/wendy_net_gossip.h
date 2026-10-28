/* SPDX-License-Identifier: Apache-2.0
 * Bounded, single-owner native counterpart of WendyOS
 * go/internal/agent/netgossip. This layer schedules untrusted bytes; the caller
 * verifies signed artifacts.
 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WG_CHUNK 1024
#define WG_OBJECT_MAX (40 * 1024)
#define WG_IDLE_MS 30000
#define WG_HINT_MS 120000
#define WG_DEFER 2 /* Completed body remains in its bounded download slot. */
#define WG_RESUME_MISSING 3 /* Exact owned completed body is no longer present. */
/* GONE withdraws this session's HAVE for an exact digest without withdrawing
 * the origin's signed record. Prototype peers must support this extension. */
enum wg_op { WG_HAVE, WG_WANT, WG_UNAVAILABLE, WG_DATA, WG_GONE };
struct wg_id {
  uint8_t type, hash[32];
};
struct wg_message {
  struct wg_id id;
  enum wg_op op;
  uint64_t request;
  uint32_t offset, total;
  const uint8_t *data;
  size_t size;
};
struct wg_config {
  /* Exact Go Identify preimage: domain including NUL, type, u32BE length,
   * bytes. The adapter supplies the platform's SHA-256 implementation. */
  int (*identify)(void *, uint8_t, const void *, size_t, uint8_t[32]);
  void *context;
  size_t objects, pending, bytes;
  /* Optional type-1 route hint reserve within pending. Type-2 service hints
   * cannot consume these slots while their downloads wait for local demand. */
  size_t route_pending_reserve;
  /* Optional start gate. HAVE metadata stays bounded by pending; already
   * started transfers finish even if a later scheduling window closes. */
  bool (*want_object)(void *,const struct wg_id *,uint64_t now_ms);
  /* Node-wide limits shared by all carriers and all artifact types.
   * Zero keeps the legacy protocol-library bounds (16 global/4 per session). */
  size_t downloads, uploads;
  /* Optional route share WITHIN downloads. Non-route bodies cannot occupy
   * these slots while their own certificate repair is pending. */
  size_t route_download_reserve;
  /* Optional FIFO payload cache. Metadata/retirement receipts still obey
   * objects; category quotas and bytes include active receive buffers. */
  bool fifo;
  size_t type_bytes[3];
  /* Keep room for fresh local route proofs despite relay receipt churn.
   * Noncritical objects cannot consume these metadata slots. */
  size_t reserve_objects;
  bool (*critical_object)(void *,const struct wg_id *);
  /* A verified adapter receipt may outlive this pool's payload/metadata row. */
  bool (*known_object)(void *,const struct wg_id *);
  bool (*protected_object)(void *,const struct wg_id *);
  /* Notification runs before releasing the pool's immutable payload ref.
   * Adapters must drop their matching cache ref and preserve verified indexes.
   * Do not reenter this pool or allocate a replacement body here. */
  void (*evicted)(void *,const struct wg_id *,const void *,size_t);
};
struct wg_object;
struct wg_fetch;
struct wg_transfer;
struct wg_pool {
  struct wg_config config;
  struct wg_object *objects;
  struct wg_fetch *pending;
  uint64_t next_owner, next_request;
  size_t object_count, pending_count, payload_bytes, metadata_bytes, serving;
  size_t type_payload[3];
  uint64_t next_object, withdrawal;
};
struct wg_session {
  struct wg_pool *pool;
  struct wg_transfer *out;
  uint64_t owner;
  uint8_t type;
  size_t serving;
  uint64_t withdrawal;
};
/* 0 queued, positive temporarily busy (retry without consuming progress),
 * negative transport error. The normal session owner polls after busy. */
typedef int (*wg_emit)(void *, const struct wg_message *);
/* Callback receives a complete digest-checked, still unauthenticated artifact.
 * Call wg_offer ONLY after independent signature/tenant/lifetime verification.
 * Bytes remain valid only for the duration of this callback. Return WG_DEFER
 * to retain the existing receive allocation and download admission slot;
 * poll retries completion without another WANT/DATA transfer. Other positive
 * returns retain their historical meaning. */
typedef int (*wg_complete)(void *, const struct wg_id *, const void *, size_t);
int wg_init(struct wg_pool *, const struct wg_config *);
void wg_deinit(struct wg_pool *);
int wg_open(struct wg_pool *, struct wg_session *, uint8_t type);
void wg_close(struct wg_session *);
/* Drop an owned unverified body without a receipt; alternate suppliers remain. */
void wg_discard(struct wg_session *,const struct wg_id *);
int wg_validate(const struct wg_message *);
int wg_offer(struct wg_pool *, uint8_t type, const void *, size_t,
             uint64_t expires_ms, uint64_t now_ms, struct wg_id *);
/* Offers return 2 for an exact digest retired by capacity eviction. It is not
 * refilled or made available again while its bounded receipt remains live. */
/* Immutable bytes retained by another actor-owned cache. Retain runs only
 * when a new object is admitted; release follows its last transfer/expiry
 * reference. Re-observation does not take another reference. */
int wg_offer_shared(struct wg_pool *, uint8_t, const void *, size_t,
                    uint64_t expires_ms, uint64_t now_ms, struct wg_id *,
                    void (*retain)(const void *), void (*release)(const void *));
/* Superseded signed versions need no idle payload RAM. Active transfers get
 * UNAVAILABLE at their next poll; referenced storage is freed after release. */
void wg_forget(struct wg_pool *,const struct wg_id *);
/* Actor-owned pressure relief: retire oldest optional payloads until at least
 * wanted bytes are released, or only protected/upload-pinned bodies remain.
 * Includes ordinary GONE/sticky retirement; never refills or cancels downloads.
 * Returns payload bytes released, which may exceed wanted by the last blob. */
size_t wg_reclaim(struct wg_pool *,size_t wanted);

/* HAVE adds a bounded supplier hint. One shared fetch owns each digest across
 * sessions. DATA requires the exact owner/request and contiguous chunks. */
int wg_receive(struct wg_session *, const struct wg_message *, uint64_t now_ms,
               wg_emit, wg_complete, void *);
/* Drive pending claims and serving once per routing tick. At most one DATA
 * chunk per call; it is advanced only after successful queue admission. */
int wg_poll(struct wg_session *, uint64_t now_ms, wg_emit, void *);
/* Pruning releases expired objects and abandoned fetch buffers. Sessions
 * must be closed before pool teardown. No maximum-sized arrays exist. */
void wg_prune(struct wg_pool *, uint64_t now_ms);
/* Charged pool bytes include shared payloads. Shared cache charges overlap
 * their owner's accounting; they are not additional physical heap usage. */
size_t wg_memory(const struct wg_pool *);
/* Read-only bounded driver diagnostics, indexed by artifact type minus one. */
struct wg_progress {size_t hints[3],active[3],complete[3],bytes[3];};
void wg_progress(const struct wg_pool *,struct wg_progress *);

int wg_resume(struct wg_session *,wg_complete,void *);
/* Finish the immutable body owning a CPU future before a later completed
 * download at the shared queue head. Same results as resume, or MISSING. */
int wg_resume_id(struct wg_session *,const struct wg_id *,wg_complete,void *);
