#include "wendy_net_direct_buffer.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
static unsigned live_payloads;
static int allocations_left;
static void *allocate_payload(size_t size)
{
    assert(size == WN_DIRECT_CHUNK);
    if (!allocations_left)
        return NULL;
    allocations_left--;
    void *p = malloc(size);
    assert(p);
    live_payloads++;
    return p;
}
static void release_payload(void *p)
{
    assert(p && live_payloads);
    /* Failed reservations need not contain initialized data. */
    live_payloads--;
    free(p);
}
static void dynamic_reservations(void)
{
    for (int fail = 0; fail < 2; fail++) {
        struct wn_direct_slot slots[4];
        struct wn_direct_pool pool;
        struct wn_direct_buffer a, b;
        assert(!wn_direct_pool_init_dynamic(&pool, slots, 4, allocate_payload, release_payload));
        assert(!live_payloads && pool.available == 4);
        wn_direct_buffer_init(&a, &pool);
        wn_direct_buffer_init(&b, &pool);
        allocations_left = 4;
        assert(!wn_direct_reserve(&a, 512));
        unsigned char data[400], got[400];
        for (unsigned i = 0; i < sizeof data; i++)
            data[i] = (unsigned char)(i * 37);
        assert(!wn_direct_append(&a, data, sizeof data));
        assert(!wn_direct_release(&a, 128));
        uint32_t free_before = pool.free, tail_before = a.tail;
        allocations_left = fail;
        assert(wn_direct_reserve(&a, 1024) == WN_DIRECT_CAPACITY);
        assert(pool.free == free_before && pool.available == 2 && live_payloads == 2);
        assert(a.start == 128 && a.end == 400 && a.limit == 512 && a.tail == tail_before);
        size_t copied;
        assert(!wn_direct_copy(&a, 128, got, sizeof got, &copied));
        assert(copied == 272 && !memcmp(got, data + 128, copied));
        allocations_left = 4;
        assert(!wn_direct_reserve(&a, 1024) && live_payloads == 4);
        assert(wn_direct_reserve(&b, 1) == WN_DIRECT_CAPACITY && !b.limit);
        /* Promotion trim releases unneeded suffix, but keeps partial data. */
        assert(!wn_direct_trim(&a) && a.limit == 512 && live_payloads == 2);
        assert(!wn_direct_release(&a, 256) && live_payloads == 1);
        assert(!wn_direct_reserve(&b, 512) && live_payloads == 3);
        assert(!wn_direct_copy(&a, 256, got, sizeof got, &copied));
        assert(copied == 144 && !memcmp(got, data + 256, copied));
        wn_direct_close(&a);
        wn_direct_close(&b);
        assert(!live_payloads && pool.available == 4);
        for (unsigned i = 0; i < 4; i++)
            assert(!slots[i].bytes);
    }
}
int main(void)
{
    dynamic_reservations();
    return 0;
}
