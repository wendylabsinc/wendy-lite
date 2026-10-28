#include "wendy_net_memory.h"

#include <assert.h>
#include <stdalign.h>
#include <stdio.h>
#include <string.h>

static void test_budget_and_lifecycle(void)
{
    wendy_net_memory_t memory = WENDY_NET_MEMORY_INITIALIZER;
    const size_t block_charge = wendy_net_memory_charge(128);
    assert(block_charge > 128);
    assert(wendy_net_memory_open(&memory, block_charge * 2, true));

    unsigned char *a = wendy_net_memory_calloc(&memory, 16, 8, WENDY_NET_MEMORY_EXTERNAL);
    assert(a && (uintptr_t)a % alignof(max_align_t) == 0);
    for (size_t i = 0; i < 128; ++i) assert(a[i] == 0);
    memset(a, 42, 128);
    void *b = wendy_net_memory_malloc(&memory, 128, WENDY_NET_MEMORY_INTERNAL);
    assert(b);
    /* Normal admission/backpressure when our two-buffer quota is occupied. */
    assert(!wendy_net_memory_malloc(&memory, 1, WENDY_NET_MEMORY_EXTERNAL));
    assert(!wendy_net_memory_realloc(&memory, a, 140, WENDY_NET_MEMORY_EXTERNAL));
    for (size_t i = 0; i < 128; ++i) assert(a[i] == 42);

    wendy_net_memory_snapshot_t state;
    wendy_net_memory_snapshot(&memory, &state);
    assert(state.current_bytes == 2 * block_charge);
    assert(state.internal_bytes == block_charge && state.external_bytes == block_charge);
    assert(state.allocation_count == 2 && state.failed_admissions == 2);
    wendy_net_memory_free(b);
    b = wendy_net_memory_malloc(&memory, 128, WENDY_NET_MEMORY_INTERNAL);
    assert(b); /* Released capacity can immediately be reused. */

    wendy_net_memory_close(&memory);
    assert(!wendy_net_memory_drained(&memory));
    assert(!wendy_net_memory_open(&memory, 4096, true));
    assert(!wendy_net_memory_malloc(&memory, 1, WENDY_NET_MEMORY_INTERNAL));
    wendy_net_memory_free(a);
    wendy_net_memory_free(b);
    assert(wendy_net_memory_drained(&memory));
    wendy_net_memory_snapshot(&memory, &state);
    assert(!state.accepting && state.current_bytes == 0 && !state.allocation_count);
    assert(state.high_water_bytes == 2 * block_charge);
    assert(wendy_net_memory_open(&memory, 4096, false));
    assert(!wendy_net_memory_malloc(&memory, 16, WENDY_NET_MEMORY_EXTERNAL));
    wendy_net_memory_close(&memory);
}

static void test_resizing_and_reservations(void)
{
    wendy_net_memory_t memory = WENDY_NET_MEMORY_INITIALIZER;
    wendy_net_memory_reservation_t task = {0};
    assert(wendy_net_memory_open(&memory, 16384, true));
    void *rtc = wendy_net_memory_malloc(&memory,128,WENDY_NET_MEMORY_RTC);
    assert(rtc);
    wendy_net_memory_free(rtc);
    assert(wendy_net_memory_reserve(&memory, &task, 8192, WENDY_NET_MEMORY_INTERNAL));
    unsigned char *data = wendy_net_memory_malloc(&memory, 128, WENDY_NET_MEMORY_EXTERNAL);
    assert(data);
    memset(data, 77, 128);
    data = wendy_net_memory_realloc(&memory, data, 1024, WENDY_NET_MEMORY_INTERNAL);
    assert(data);
    for (size_t i = 0; i < 128; ++i) assert(data[i] == 77);
    wendy_net_memory_snapshot_t state;
    wendy_net_memory_snapshot(&memory, &state);
    assert(state.external_bytes == wendy_net_memory_charge(1024));
    assert(state.internal_bytes == 8192); /* Realloc preserves original placement. */
    assert(state.high_water_bytes == 8192 + wendy_net_memory_charge(128) +
                                           wendy_net_memory_charge(1024));
    data = wendy_net_memory_realloc(&memory, data, 32, WENDY_NET_MEMORY_EXTERNAL);
    assert(data);
    for (size_t i = 0; i < 32; ++i) assert(data[i] == 77);
    assert(!wendy_net_memory_realloc(&memory, data, 0, WENDY_NET_MEMORY_EXTERNAL));
    wendy_net_memory_close(&memory);
    assert(!wendy_net_memory_drained(&memory));
    wendy_net_memory_release(&task);
    wendy_net_memory_release(&task); /* Cleared token is safe to release again. */
    assert(wendy_net_memory_drained(&memory));
    wendy_net_memory_snapshot(&memory, &state);
    assert(!state.reservation_bytes && !state.reservation_count && !state.current_bytes);
}

typedef struct {
    wendy_net_memory_t *memory;
    void *lent;
    unsigned value;
} worker_t;

static void *worker(void *argument)
{
    worker_t *job = argument;
    assert(!wendy_net_memory_scope_current().owner); /* No scope inheritance. */
    wendy_net_memory_scope_t previous = wendy_net_memory_scope_enter(
        job->memory, WENDY_NET_MEMORY_EXTERNAL);
    /* A context/buffer allocated by the actor can be freed by its worker. */
    unsigned char *lent = job->lent;
    for (size_t i = 0; i < 96; ++i) assert(lent[i] == job->value);
    wendy_net_memory_free(lent);
    for (size_t pass = 0; pass < 2000; ++pass) {
        size_t size = 32 + (pass % 256);
        unsigned char *scratch = wendy_net_memory_scoped_calloc(1, size);
        assert(scratch);
        memset(scratch, (int)job->value, size);
        assert(scratch[size - 1] == job->value);
        wendy_net_memory_free(scratch);
    }
    wendy_net_memory_scope_leave(previous);
    return NULL;
}

static void test_actor_worker_ownership(void)
{
    wendy_net_memory_t memory = WENDY_NET_MEMORY_INITIALIZER;
    assert(wendy_net_memory_open(&memory, 16384, true));
    wendy_net_memory_scope_t previous = wendy_net_memory_scope_enter(
        &memory, WENDY_NET_MEMORY_INTERNAL);
    enum { WORKERS = 4 };
    pthread_t threads[WORKERS];
    worker_t jobs[WORKERS];
    for (unsigned i = 0; i < WORKERS; ++i) {
        jobs[i] = (worker_t){ .memory = &memory, .value = i + 1,
            .lent = wendy_net_memory_malloc(&memory, 96, WENDY_NET_MEMORY_EXTERNAL) };
        assert(jobs[i].lent);
        memset(jobs[i].lent, (int)jobs[i].value, 96);
        assert(!pthread_create(&threads[i], NULL, worker, &jobs[i]));
    }
    for (unsigned i = 0; i < WORKERS; ++i) assert(!pthread_join(threads[i], NULL));
    wendy_net_memory_snapshot_t state;
    wendy_net_memory_snapshot(&memory, &state);
    assert(!state.current_bytes && !state.allocation_count && !state.failed_admissions);
    assert(state.high_water_bytes <= state.limit_bytes);
    assert(wendy_net_memory_scope_current().owner == &memory);
    wendy_net_memory_scope_leave(previous);
    wendy_net_memory_close(&memory);
    assert(wendy_net_memory_drained(&memory));
}

static void test_universal_hooks_and_nested_scopes(void)
{
    wendy_net_memory_t memory = WENDY_NET_MEMORY_INITIALIZER;
    assert(wendy_net_memory_open(&memory, 4096, true));
    /* Management TLS may live before, during and after mesh ownership. */
    void *management = wendy_net_memory_unscoped_calloc(1, 300);
    assert(management && wendy_net_memory_drained(&memory));
    wendy_net_memory_scope_t outer = wendy_net_memory_scope_enter(
        &memory, WENDY_NET_MEMORY_EXTERNAL);
    void *baseline = wendy_net_memory_unscoped_calloc_in(1,100,WENDY_NET_MEMORY_EXTERNAL);
    assert(baseline);
    wendy_net_memory_scoped_free(baseline);
    unsigned char *mesh = wendy_net_memory_scoped_calloc(4, 64);
    assert(mesh);
    for (size_t i = 0; i < 256; ++i) assert(!mesh[i]);
    wendy_net_memory_scope_t nested = wendy_net_memory_scope_enter(
        NULL, WENDY_NET_MEMORY_INTERNAL);
    void *other_management = wendy_net_memory_scoped_calloc(1, 200);
    assert(other_management);
    wendy_net_memory_scope_leave(nested);
    assert(wendy_net_memory_scope_current().owner == &memory);
    wendy_net_memory_scoped_free(management); /* Free follows original owner. */
    wendy_net_memory_snapshot_t state;
    wendy_net_memory_snapshot(&memory, &state);
    assert(state.current_bytes == wendy_net_memory_charge(256));
    assert(state.external_bytes == state.current_bytes && !state.internal_bytes);
    wendy_net_memory_close(&memory);
    assert(!wendy_net_memory_scoped_calloc(1, 8)); /* Closed scope cannot bypass cap. */
    wendy_net_memory_scope_leave(outer);
    assert(!wendy_net_memory_scope_current().owner);
    wendy_net_memory_scoped_free(mesh); /* Loan completes outside original scope. */
    assert(wendy_net_memory_drained(&memory));
    assert(wendy_net_memory_open(&memory, 4096, false));
    wendy_net_memory_scoped_free(other_management); /* Survives mesh generation. */
    assert(wendy_net_memory_drained(&memory));
    wendy_net_memory_close(&memory);
}

int main(void)
{
    test_budget_and_lifecycle();
    test_resizing_and_reservations();
    test_actor_worker_ownership();
    test_universal_hooks_and_nested_scopes();
    puts("Wendy Net memory: accounting, quota reuse, resize, shutdown and task ownership passed");
    return 0;
}
