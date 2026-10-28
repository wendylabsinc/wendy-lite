#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#else
#include <pthread.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Placement is strict: EXTERNAL never silently consumes internal SRAM. */
typedef enum {
    WENDY_NET_MEMORY_INTERNAL = 0,
    WENDY_NET_MEMORY_EXTERNAL = 1,
    WENDY_NET_MEMORY_RTC = 2, /* RTC-capable internal RAM; strict, no fallback. */
} wendy_net_memory_placement_t;

typedef struct {
    size_t limit_bytes;
    size_t current_bytes;       /* Allocations (including prefix) + reservations. */
    size_t high_water_bytes;    /* Includes admitted allocations still in flight. */
    size_t internal_bytes;
    size_t external_bytes;
    size_t allocation_count;
    size_t reservation_bytes;
    size_t reservation_count;
    uint64_t failed_admissions;
    bool accepting;
    bool external_enabled;
} wendy_net_memory_snapshot_t;

/* Caller-owned, stable until all allocations/reservations have been returned.
 * Do not copy or directly access fields. Initialize statically with the macro.
 * The ledger allocates no arena, mutex or other dynamic state. */
typedef struct wendy_net_memory {
#ifdef ESP_PLATFORM
    portMUX_TYPE lock;
#else
    pthread_mutex_t lock;
#endif
    wendy_net_memory_snapshot_t state;
} wendy_net_memory_t;

#ifdef ESP_PLATFORM
#define WENDY_NET_MEMORY_INITIALIZER { .lock = portMUX_INITIALIZER_UNLOCKED }
#else
#define WENDY_NET_MEMORY_INITIALIZER { .lock = PTHREAD_MUTEX_INITIALIZER }
#endif

/* Caller owns each token exclusively; initialize to {0}, do not copy a live
 * token. Reserve before creating separately allocated tasks/SDK state; release
 * only after that state is destroyed. The ledger does not allocate it. */
typedef struct {
    wendy_net_memory_t *owner;
    size_t bytes;
    wendy_net_memory_placement_t placement;
} wendy_net_memory_reservation_t;

/* Open/reset only succeeds while closed and drained. On ESP, requesting
 * EXTERNAL support also requires a registered SPIRAM heap. Host emulates it.
 * Closing blocks new allocations/reservations but permits outstanding frees.
 * Do not reopen until all users of the previous generation have stopped. */
bool wendy_net_memory_open(wendy_net_memory_t *memory, size_t limit_bytes,
                           bool external_enabled);
void wendy_net_memory_close(wendy_net_memory_t *memory);
void wendy_net_memory_snapshot(wendy_net_memory_t *memory,
                               wendy_net_memory_snapshot_t *out);
bool wendy_net_memory_drained(wendy_net_memory_t *memory);

/* Requested payload plus max_align_t-aligned ownership prefix is charged.
 * Heap implementation bookkeeping is not included: see design notes.
 * Zero-sized allocation returns NULL. Free is valid across tasks and after
 * close. Only pointers returned by this helper may be freed/reallocated here.
 * Caller must exclusively own the pointer while resizing/freeing it. */
size_t wendy_net_memory_charge(size_t payload_bytes);
void *wendy_net_memory_malloc(wendy_net_memory_t *memory, size_t bytes,
                             wendy_net_memory_placement_t placement);
void *wendy_net_memory_calloc(wendy_net_memory_t *memory, size_t count,
                             size_t bytes, wendy_net_memory_placement_t placement);
void wendy_net_memory_free(void *ptr);
/* Both old and new blocks count during copy; failure leaves old unchanged.
 * NULL uses malloc and explicit placement; non-NULL preserves its original
 * owner and placement, requiring memory to match its original owner.
 * size=0 frees ptr (even after close). No fallback or uncharged realloc path. */
void *wendy_net_memory_realloc(wendy_net_memory_t *memory, void *ptr, size_t bytes,
                              wendy_net_memory_placement_t placement);

/* Optional universal calloc/free callbacks for context-less library hooks.
 * Install once before any library allocations; never swap hooks at mesh off.
 * Every returned pointer has a prefix, even outside a charged scope. Never mix
 * these frees with libc/library pointers allocated before hook installation.
 * Scopes are task-local, not inherited by newly created tasks. Restore the
 * previous scope on all exits; a borrowed TLS context retains its mesh owner.
 * An uncharged scope (owner=NULL) follows the platform default heap placement.
 * Entering a closed charged scope does not bypass admission: allocations fail. */
typedef struct {
    wendy_net_memory_t *owner;
    wendy_net_memory_placement_t placement;
} wendy_net_memory_scope_t;
wendy_net_memory_scope_t wendy_net_memory_scope_enter(
    wendy_net_memory_t *owner, wendy_net_memory_placement_t placement);
void wendy_net_memory_scope_leave(wendy_net_memory_scope_t previous);
wendy_net_memory_scope_t wendy_net_memory_scope_current(void);
/* Universal uncharged allocation for pre-scheduler library startup: no task-local
 * state is read, and its matching free still uses the normal owner prefix. */
void *wendy_net_memory_unscoped_calloc(size_t count, size_t bytes);
/* Explicit uncharged pool selection, with the same prefix and no fallback.
 * Intended for library baseline policy; never use to bypass a charged scope. */
void *wendy_net_memory_unscoped_calloc_in(size_t count, size_t bytes,
                                        wendy_net_memory_placement_t placement);
void *wendy_net_memory_scoped_calloc(size_t count, size_t bytes);
void wendy_net_memory_scoped_free(void *ptr);

bool wendy_net_memory_reserve(wendy_net_memory_t *memory,
                              wendy_net_memory_reservation_t *token,
                              size_t bytes, wendy_net_memory_placement_t placement);
void wendy_net_memory_release(wendy_net_memory_reservation_t *token);

#ifdef __cplusplus
}
#endif
