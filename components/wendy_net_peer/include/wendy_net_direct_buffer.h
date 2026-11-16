#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Actor-owned, bounded payload slabs. The caller allocates/charges storage using
 * the networking memory ledger, choosing internal RAM or PSRAM by local policy.
 * No pointer into a recyclable chunk may escape to an asynchronous writer. */
#define WN_DIRECT_CHUNK 256
#define WN_DIRECT_NONE UINT32_MAX
enum { WN_DIRECT_OK = 0, WN_DIRECT_BOUNDS = -1, WN_DIRECT_CAPACITY = -2 };
struct wn_direct_slot {
    uint8_t *bytes;
    uint32_t next;
};
struct wn_direct_pool {
    struct wn_direct_slot *slots;
    void *(*allocate)(size_t);
    void (*release)(void *);
    uint32_t count, free, available;
};
struct wn_direct_buffer {
    struct wn_direct_pool *pool;
    uint32_t head, tail;
    uint64_t start, end, limit;
};
struct wn_direct_sender {
    struct wn_direct_buffer buffer;
    uint64_t offered, remote_limit, final;
    bool finished;
};
struct wn_direct_receiver {
    struct wn_direct_buffer buffer;
    uint64_t final;
    bool finished;
};
/* Slots are caller-owned metadata; payload is allocated before a reservation
 * succeeds and released only when its credit/data ownership is discharged.
 * Allocator callbacks must charge the same bounded networking owner. */
int wn_direct_pool_init_dynamic(struct wn_direct_pool *, struct wn_direct_slot *, uint32_t count,
                                void *(*allocate)(size_t), void (*release)(void *));
void wn_direct_buffer_init(struct wn_direct_buffer *, struct wn_direct_pool *);
/* Reserve rounds upward to whole chunks; failure is atomic. Previously
 * promised receive capacity is never withdrawn by a smaller policy target. */
int wn_direct_reserve(struct wn_direct_buffer *, uint64_t through);
int wn_direct_append(struct wn_direct_buffer *, const void *, size_t);
int wn_direct_copy(const struct wn_direct_buffer *, uint64_t offset, void *, size_t, size_t *);
int wn_direct_release(struct wn_direct_buffer *, uint64_t through);
/* Requires fenced attachment and resolved/reset logical stream. */
void wn_direct_close(struct wn_direct_buffer *);
/* Release reserved suffix chunks containing no retained bytes. Only legal once
 * old receive credits have been fenced and discharged by promotion/reset;
 * never withdraw a live BLE receive promise. Preserves absolute byte offsets. */
int wn_direct_trim(struct wn_direct_buffer *);
int wn_direct_send_accept(struct wn_direct_sender *, const void *, size_t, uint64_t window);
/* Publishes offered high-water before carrier I/O; copies into writer-owned
 * memory so an early ACK cannot recycle an outstanding worker's bytes. */
int wn_direct_send_offer(struct wn_direct_sender *, uint64_t offset, void *, size_t, size_t *);
int wn_direct_send_state(struct wn_direct_sender *, uint64_t received, uint64_t limit);
uint64_t wn_direct_send_finish(struct wn_direct_sender *);
int wn_direct_receive(struct wn_direct_receiver *, const void *, size_t);
int wn_direct_receive_finish(struct wn_direct_receiver *, uint64_t final);
bool wn_direct_receive_eof(const struct wn_direct_receiver *);
