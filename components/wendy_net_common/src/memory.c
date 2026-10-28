#include "wendy_net_memory.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_heap_caps.h"
#endif

/* The union gives every returned payload malloc-compatible alignment. */
typedef union {
    max_align_t alignment;
    struct {
        wendy_net_memory_t *owner;
        size_t payload_bytes;
        size_t charged_bytes;
        wendy_net_memory_placement_t placement;
    } value;
} allocation_header_t;

/* ESP-IDF supports compiler TLS for native FreeRTOS tasks as well as pthreads.
 * It occupies sizeof(scope) bytes in every task's TLS/stack reservation. */
#ifdef ESP_PLATFORM
static __thread wendy_net_memory_scope_t current_scope;
#else
static _Thread_local wendy_net_memory_scope_t current_scope;
#endif

static void ledger_lock(wendy_net_memory_t *memory)
{
#ifdef ESP_PLATFORM
    portENTER_CRITICAL(&memory->lock);
#else
    int result = pthread_mutex_lock(&memory->lock);
    assert(result == 0);
    (void)result;
#endif
}

static void ledger_unlock(wendy_net_memory_t *memory)
{
#ifdef ESP_PLATFORM
    portEXIT_CRITICAL(&memory->lock);
#else
    int result = pthread_mutex_unlock(&memory->lock);
    assert(result == 0);
    (void)result;
#endif
}

static bool placement_valid(wendy_net_memory_placement_t placement)
{
    return placement == WENDY_NET_MEMORY_INTERNAL ||
           placement == WENDY_NET_MEMORY_EXTERNAL || placement == WENDY_NET_MEMORY_RTC;
}

bool wendy_net_memory_open(wendy_net_memory_t *memory, size_t limit_bytes,
                           bool external_enabled)
{
    if (!memory || !limit_bytes) return false;
#ifdef ESP_PLATFORM
    if (external_enabled && heap_caps_get_total_size(MALLOC_CAP_SPIRAM) == 0)
        return false;
#endif
    ledger_lock(memory);
    bool ready = !memory->state.accepting &&
                 !memory->state.allocation_count &&
                 !memory->state.reservation_count;
    if (ready) {
        memset(&memory->state, 0, sizeof(memory->state));
        memory->state.limit_bytes = limit_bytes;
        memory->state.external_enabled = external_enabled;
        memory->state.accepting = true;
    }
    ledger_unlock(memory);
    return ready;
}

void wendy_net_memory_close(wendy_net_memory_t *memory)
{
    if (!memory) return;
    ledger_lock(memory);
    memory->state.accepting = false;
    ledger_unlock(memory);
}

void wendy_net_memory_snapshot(wendy_net_memory_t *memory,
                               wendy_net_memory_snapshot_t *out)
{
    if (!memory || !out) return;
    ledger_lock(memory);
    *out = memory->state;
    ledger_unlock(memory);
}

bool wendy_net_memory_drained(wendy_net_memory_t *memory)
{
    if (!memory) return true;
    wendy_net_memory_snapshot_t state;
    wendy_net_memory_snapshot(memory, &state);
    return !state.allocation_count && !state.reservation_count;
}

size_t wendy_net_memory_charge(size_t payload_bytes)
{
    if (!payload_bytes || payload_bytes > SIZE_MAX - sizeof(allocation_header_t))
        return 0;
    return payload_bytes + sizeof(allocation_header_t);
}

static void admission_failed(wendy_net_memory_t *memory)
{
    if (!memory) return;
    ledger_lock(memory);
    ++memory->state.failed_admissions;
    ledger_unlock(memory);
}

static bool admit(wendy_net_memory_t *memory, size_t charge,
                  wendy_net_memory_placement_t placement, bool reservation)
{
    if (!memory) return false;
    ledger_lock(memory);
    wendy_net_memory_snapshot_t *state = &memory->state;
    bool allowed = charge && placement_valid(placement) && state->accepting &&
        (placement != WENDY_NET_MEMORY_EXTERNAL || state->external_enabled) &&
        charge <= state->limit_bytes - state->current_bytes;
    if (allowed) {
        state->current_bytes += charge;
        if (state->current_bytes > state->high_water_bytes)
            state->high_water_bytes = state->current_bytes;
        if (placement == WENDY_NET_MEMORY_EXTERNAL) state->external_bytes += charge;
        else state->internal_bytes += charge;
        if (reservation) {
            state->reservation_bytes += charge;
            ++state->reservation_count;
        } else ++state->allocation_count;
    } else ++state->failed_admissions;
    ledger_unlock(memory);
    return allowed;
}

static void retire(wendy_net_memory_t *memory, size_t charge,
                   wendy_net_memory_placement_t placement, bool reservation)
{
    ledger_lock(memory);
    wendy_net_memory_snapshot_t *state = &memory->state;
    assert(state->current_bytes >= charge);
    state->current_bytes -= charge;
    if (placement == WENDY_NET_MEMORY_EXTERNAL) state->external_bytes -= charge;
    else state->internal_bytes -= charge;
    if (reservation) {
        assert(state->reservation_count && state->reservation_bytes >= charge);
        state->reservation_bytes -= charge;
        --state->reservation_count;
    } else {
        assert(state->allocation_count);
        --state->allocation_count;
    }
    ledger_unlock(memory);
}

static void *allocate_in(wendy_net_memory_t *memory, size_t bytes,
                         wendy_net_memory_placement_t placement, bool strict_placement)
{
    if (!bytes) return NULL;
    size_t charge = wendy_net_memory_charge(bytes);
    if (!charge) {
        admission_failed(memory);
        return NULL;
    }
    if (memory && !admit(memory, charge, placement, false)) return NULL;
#ifdef ESP_PLATFORM
    unsigned caps = MALLOC_CAP_8BIT;
    if (memory || strict_placement) caps |= placement == WENDY_NET_MEMORY_EXTERNAL ? MALLOC_CAP_SPIRAM :
        placement == WENDY_NET_MEMORY_RTC ? MALLOC_CAP_RTCRAM : MALLOC_CAP_INTERNAL;
    allocation_header_t *header = heap_caps_aligned_alloc(_Alignof(max_align_t), charge, caps);
#else
    (void)strict_placement;
    allocation_header_t *header = malloc(charge);
#endif
    if (!header) {
        if (memory) retire(memory, charge, placement, false);
        admission_failed(memory);
        return NULL;
    }
    header->value.owner = memory;
    header->value.payload_bytes = bytes;
    header->value.charged_bytes = charge;
    header->value.placement = placement;
    return header + 1;
}

static void *allocate(wendy_net_memory_t *memory, size_t bytes,
                      wendy_net_memory_placement_t placement)
{
    return allocate_in(memory, bytes, placement, false);
}

void *wendy_net_memory_malloc(wendy_net_memory_t *memory, size_t bytes,
                             wendy_net_memory_placement_t placement)
{
    return memory ? allocate(memory, bytes, placement) : NULL;
}

void *wendy_net_memory_calloc(wendy_net_memory_t *memory, size_t count,
                             size_t bytes, wendy_net_memory_placement_t placement)
{
    if (bytes && count > SIZE_MAX / bytes) {
        admission_failed(memory);
        return NULL;
    }
    size_t total = count * bytes;
    void *ptr = wendy_net_memory_malloc(memory, total, placement);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

void wendy_net_memory_free(void *ptr)
{
    if (!ptr) return;
    allocation_header_t *header = (allocation_header_t *)ptr - 1;
    wendy_net_memory_t *owner = header->value.owner;
    size_t charge = header->value.charged_bytes;
    wendy_net_memory_placement_t placement = header->value.placement;
    /* Retain the charge until the backing storage has actually been freed. */
#ifdef ESP_PLATFORM
    heap_caps_free(header);
#else
    free(header);
#endif
    if (owner) retire(owner, charge, placement, false);
}

void *wendy_net_memory_realloc(wendy_net_memory_t *memory, void *ptr, size_t bytes,
                              wendy_net_memory_placement_t placement)
{
    if (!ptr) return wendy_net_memory_malloc(memory, bytes, placement);
    allocation_header_t *header = (allocation_header_t *)ptr - 1;
    if (memory != header->value.owner) {
        admission_failed(memory);
        return NULL;
    }
    if (!bytes) {
        wendy_net_memory_free(ptr);
        return NULL;
    }
    void *replacement = wendy_net_memory_malloc(memory, bytes, header->value.placement);
    if (!replacement) return NULL;
    size_t copied = bytes < header->value.payload_bytes ? bytes : header->value.payload_bytes;
    memcpy(replacement, ptr, copied);
    wendy_net_memory_free(ptr);
    return replacement;
}

wendy_net_memory_scope_t wendy_net_memory_scope_enter(
    wendy_net_memory_t *owner, wendy_net_memory_placement_t placement)
{
    wendy_net_memory_scope_t previous = current_scope;
    current_scope = (wendy_net_memory_scope_t){ .owner = owner, .placement = placement };
    return previous;
}

void wendy_net_memory_scope_leave(wendy_net_memory_scope_t previous)
{
    current_scope = previous;
}

wendy_net_memory_scope_t wendy_net_memory_scope_current(void)
{
    return current_scope;
}

void *wendy_net_memory_unscoped_calloc(size_t count, size_t bytes)
{
    if (bytes && count > SIZE_MAX / bytes) return NULL;
    size_t total = count * bytes;
    void *ptr = allocate(NULL, total, WENDY_NET_MEMORY_INTERNAL);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

void *wendy_net_memory_unscoped_calloc_in(size_t count, size_t bytes,
                                        wendy_net_memory_placement_t placement)
{
    if (!placement_valid(placement) || (bytes && count > SIZE_MAX / bytes)) return NULL;
    size_t total = count * bytes;
    void *ptr = allocate_in(NULL, total, placement, true);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

void *wendy_net_memory_scoped_calloc(size_t count, size_t bytes)
{
    if (bytes && count > SIZE_MAX / bytes) {
        admission_failed(current_scope.owner);
        return NULL;
    }
    size_t total = count * bytes;
    void *ptr = allocate(current_scope.owner, total, current_scope.placement);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

void wendy_net_memory_scoped_free(void *ptr)
{
    wendy_net_memory_free(ptr);
}

bool wendy_net_memory_reserve(wendy_net_memory_t *memory,
                              wendy_net_memory_reservation_t *token,
                              size_t bytes, wendy_net_memory_placement_t placement)
{
    if (!token || token->owner) return false;
    if (!admit(memory, bytes, placement, true)) return false;
    token->owner = memory;
    token->bytes = bytes;
    token->placement = placement;
    return true;
}

void wendy_net_memory_release(wendy_net_memory_reservation_t *token)
{
    if (!token || !token->owner) return;
    retire(token->owner, token->bytes, token->placement, true);
    memset(token, 0, sizeof(*token));
}
