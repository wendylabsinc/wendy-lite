#include "wendy_net_alloc.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
#ifdef WENDY_NET_MEMORY_HOST_BUDGET_TEST
    /* Run the firmware wrapper branch on host with strict internal placement. */
    assert(!wendy_net_malloc(64)); /* Disabled has no uncharged fallback. */
    assert(wendy_net_runtime_memory_open());
    assert(!wendy_net_runtime_memory_open());
    wendy_net_memory_snapshot_t state;
    wendy_net_runtime_memory_snapshot(&state);
    assert(state.accepting && state.limit_bytes == WENDY_NET_RUNTIME_INTERNAL_MEMORY_LIMIT);
    assert(!state.external_enabled && !state.current_bytes);
    /* Exercise the same ordinary queue/loan lifecycle at both the C6 ceiling
     * and the larger host profile, rather than assuming a one-MiB budget. */
    size_t state_bytes = state.limit_bytes * 5 / 8;
    size_t transfer_bytes = state.limit_bytes * 5 / 16;
    unsigned char *state_buffer = wendy_net_calloc(1, state_bytes);
    void *transfer = wendy_net_malloc(transfer_bytes);
    assert(state_buffer && transfer);
    for (size_t i = 0; i < state_bytes; ++i) assert(!state_buffer[i]);
    assert(!wendy_net_malloc(state.limit_bytes * 3 / 32)); /* Ordinary bounded queue admission. */
    char *name = wendy_net_strdup("mesh neighbour");
    assert(name && !strcmp(name, "mesh neighbour"));
    wendy_net_memory_reservation_t stack = {0};
    assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(), &stack,
                                   8192, WENDY_NET_MEMORY_INTERNAL));
    void *task_state = wendy_net_internal_calloc(1, 256);
    assert(task_state);
    wendy_net_memory_scope_t previous = wendy_net_runtime_scope_enter();
    void *library_state = wendy_net_memory_scoped_calloc(1, 1024);
    assert(library_state);
    wendy_net_memory_scope_leave(previous);
    wendy_net_runtime_memory_snapshot(&state);
    assert(state.current_bytes <= state.limit_bytes && state.allocation_count == 5);
    assert(state.internal_bytes == state.current_bytes && !state.external_bytes);
    assert(state.reservation_bytes == 8192 && state.failed_admissions == 1);
    wendy_net_free(transfer);
    name = wendy_net_realloc(name, 128);
    assert(name && !strcmp(name, "mesh neighbour"));
    wendy_net_runtime_memory_close();
    assert(!wendy_net_runtime_memory_drained());
    assert(!wendy_net_calloc(1, 16));
    assert(!wendy_net_internal_malloc(16));
    wendy_net_free(name);
    wendy_net_free(state_buffer);
    wendy_net_free(task_state);
    wendy_net_memory_scoped_free(library_state);
    wendy_net_memory_release(&stack);
    assert(wendy_net_runtime_memory_drained());
    wendy_net_runtime_memory_snapshot(&state);
    assert(!state.current_bytes && !state.accepting);
    assert(wendy_net_runtime_memory_open());
    wendy_net_runtime_memory_close();
    puts("Runtime budget: bounded admission, scopes and complete shutdown passed");
#else
    /* Existing host component APIs retain libc ownership without startup. */
    char *copy = wendy_net_strdup("portable host");
    assert(copy && !strcmp(copy, "portable host"));
    free(copy);
    char *plain = malloc(64);
    assert(plain);
    strcpy(plain, "host ABI");
    plain = wendy_net_realloc(plain, 128);
    assert(plain && !strcmp(plain, "host ABI"));
    wendy_net_free(plain);
    void *zeroed = wendy_net_internal_calloc(1, 32);
    assert(zeroed);
    free(zeroed);
    puts("Runtime host wrappers retain libc allocation ownership");
#endif
    return 0;
}
