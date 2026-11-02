/* Receiver-monotonic expiry releases bodies even when an upload is stalled. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct observation {
    unsigned evicted, data, unavailable, shared_refs;
    bool busy;
};
static struct observation *shared_owner;
static void retain(const void *bytes)
{
    assert(bytes && shared_owner);
    shared_owner->shared_refs++;
}
static void release(const void *bytes)
{
    assert(bytes && shared_owner && shared_owner->shared_refs);
    shared_owner->shared_refs--;
}
static void evicted(void *context, const struct wg_id *id, const void *bytes, size_t size)
{
    struct observation *seen = context;
    assert(id && bytes && size);
    seen->evicted++;
}
static int emit(void *context, const struct wg_message *message)
{
    struct observation *seen = context;
    seen->data += message->op == WG_DATA;
    seen->unavailable += message->op == WG_UNAVAILABLE;
    return seen->busy ? 1 : 0;
}
static int ignore(void *context, const struct wg_id *id, const void *bytes, size_t size)
{
    (void)context;
    (void)id;
    (void)bytes;
    (void)size;
    return 0;
}
static struct wg_config config(struct observation *seen, bool fifo)
{
    return (struct wg_config){.identify = identify,
                              .context = seen,
                              .objects = 8,
                              .pending = 4,
                              .bytes = 4096,
                              .fifo = fifo,
                              .evicted = evicted};
}
static void idle_cycles(bool fifo)
{
    struct observation seen = {0};
    struct wg_pool pool;
    struct wg_config cfg = config(&seen, fifo);
    assert(!wg_init(&pool, &cfg));
    size_t baseline = wg_memory(&pool);
    for (unsigned cycle = 0; cycle < 128; ++cycle) {
        uint64_t now = 1000 + (uint64_t)cycle * 1000;
        uint8_t bytes[1024] = {0};
        bytes[0] = (uint8_t)cycle;
        struct wg_id id, again;
        assert(!wg_offer(&pool, 1, bytes, sizeof bytes, now + 10, now, &id));
        assert(!wg_offer(&pool, 1, bytes, sizeof bytes, now + 900000, now + 1, &again));
        assert(!memcmp(id.hash, again.hash, 32));
        wg_prune(&pool, now + 9);
        assert(pool.object_count == 1 && pool.payload_bytes == sizeof bytes);
        /* No receive, poll or export is needed to expire an idle body. */
        wg_prune(&pool, now + 10);
        assert(!pool.object_count && !pool.payload_bytes && !pool.type_payload[0]);
        assert(wg_memory(&pool) == baseline);
    }
    assert(seen.evicted == 128);
    wg_deinit(&pool);
}
static void stalled_uploads(void)
{
    struct observation seen = {0};
    shared_owner = &seen;
    struct wg_pool pool;
    struct wg_session session;
    struct wg_config cfg = config(&seen, true);
    assert(!wg_init(&pool, &cfg) && !wg_open(&pool, &session, 1));
    size_t baseline = wg_memory(&pool);
    for (unsigned cycle = 0; cycle < 64; ++cycle) {
        uint64_t now = 1000 + (uint64_t)cycle * 1000;
        uint8_t bytes[2048] = {0};
        bytes[0] = (uint8_t)cycle;
        struct wg_id id, again;
        assert(!wg_offer_shared(&pool, 1, bytes, sizeof bytes, now + 10, now, &id,
                                retain, release));
        struct wg_message want = {.op = WG_WANT, .id = id, .request = cycle + 1};
        assert(!wg_receive(&session, &want, now + 1, emit, ignore, &seen));
        assert(pool.serving == 1 && seen.shared_refs == 1);
        /* The output queue never admits a DATA chunk before the lease ends. */
        seen.busy = true;
        assert(wg_poll(&session, now + 2, emit, &seen) == 1);
        wg_prune(&pool, now + 10);
        assert(!pool.payload_bytes && !pool.type_payload[0] && !seen.shared_refs);
        assert(pool.object_count == 1 && pool.serving == 1); /* Compact refs only. */
        unsigned attempts = seen.data;
        for (unsigned blocked = 0; blocked < 4; ++blocked)
            assert(wg_poll(&session, now + 11 + blocked, emit, &seen) == 1);
        assert(seen.data == attempts && !pool.payload_bytes && seen.evicted == cycle + 1);
        assert(wg_offer(&pool, 1, bytes, sizeof bytes, now + 900000, now + 20, &again) == 2);
        seen.busy = false;
        assert(!wg_poll(&session, now + 21, emit, &seen));
        assert(!pool.serving && !session.serving);
        wg_prune(&pool, now + 21);
        assert(!pool.object_count && !pool.payload_bytes && wg_memory(&pool) == baseline);
    }
    /* Explicit supersession has the same immediate payload-release behavior. */
    uint8_t bytes[2048] = {1};
    struct wg_id id;
    assert(!wg_offer_shared(&pool, 1, bytes, sizeof bytes, 1000000, 100000, &id,
                            retain, release));
    struct wg_message want = {.op = WG_WANT, .id = id, .request = 1000};
    assert(!wg_receive(&session, &want, 100001, emit, ignore, &seen));
    wg_forget(&pool, &id);
    assert(!pool.payload_bytes && !seen.shared_refs && pool.serving == 1);
    assert(!wg_poll(&session, 100002, emit, &seen) && !pool.serving);
    wg_prune(&pool, 100002);
    assert(wg_memory(&pool) == baseline);
    wg_close(&session);
    wg_deinit(&pool);
    shared_owner = NULL;
}
static void retired_digests(void)
{
    struct observation seen = {0};
    struct wg_pool pool;
    struct wg_config cfg = config(&seen, true);
    assert(!wg_init(&pool, &cfg));
    size_t baseline = wg_memory(&pool);
    for (unsigned cycle = 0; cycle < 64; ++cycle) {
        uint64_t now = 1000 + (uint64_t)cycle * (WG_HINT_MS + 1000);
        uint8_t bytes[1024] = {0};
        bytes[0] = (uint8_t)cycle;
        struct wg_id id, again;
        assert(!wg_offer(&pool, 1, bytes, sizeof bytes, now + 10, now, &id));
        assert(wg_reclaim(&pool, 1) == sizeof bytes);
        wg_prune(&pool, now + 10);
        assert(pool.object_count == 1 && !pool.payload_bytes);
        assert(wg_offer(&pool, 1, bytes, sizeof bytes, now + 900000, now + 11, &again) == 2);
        /* Digest-only fallback is bounded by the original lease + hint TTL;
         * repeated offers do not extend its retention. */
        wg_prune(&pool, now + 10 + WG_HINT_MS);
        assert(!pool.object_count && wg_memory(&pool) == baseline);
    }
    wg_deinit(&pool);
}
static void owner_expires_retired_digests(void)
{
    struct observation seen = {0};
    struct wg_pool pool;
    struct wg_config cfg = config(&seen, true);
    assert(!wg_init(&pool, &cfg));
    size_t baseline = wg_memory(&pool);
    for (unsigned cycle = 0; cycle < 128; ++cycle) {
        uint64_t now = 1000 + (uint64_t)cycle * 1000;
        uint8_t bytes[1024] = {0};
        bytes[0] = (uint8_t)cycle;
        struct wg_id id, again;
        assert(!wg_offer(&pool, 1, bytes, sizeof bytes, now + 10, now, &id));
        assert(wg_reclaim(&pool, 1) == sizeof bytes);
        wg_forget(&pool, &id); /* Ordinary forget preserves sticky retirement. */
        assert(wg_offer(&pool, 1, bytes, sizeof bytes, now + 900000, now + 1, &again) == 2);
        wg_prune(&pool, now + 10);
        assert(pool.object_count == 1 && !pool.payload_bytes);
        /* The owner knows the verified artifact's local lease ended. Its
         * separate watermark, rather than gossip hint retention, owns replay. */
        wg_expire(&pool, &id);
        assert(!pool.object_count && !pool.payload_bytes && wg_memory(&pool) == baseline);
        wg_expire(&pool, &id); /* Idempotent after the row is gone. */
    }
    assert(seen.evicted == 128);
    wg_deinit(&pool);
}
struct borrowed {
    struct wg_pool *pool;
    struct wg_message want;
};
static int borrow_emit(void *context, const struct wg_message *message)
{
    ((struct borrowed *)context)->want = *message;
    return 0;
}
static int borrowed_complete(void *context, const struct wg_id *id, const void *bytes, size_t size)
{
    struct borrowed *borrowed = context;
    struct wg_id actual;
    assert(!wg_offer(borrowed->pool, id->type, bytes, size, 1010, 1000, &actual));
    /* An offer may prune at a later sampled time while this callback still
     * owns the adopted immutable view. It must not free the borrowed bytes. */
    uint8_t other[64] = {9};
    assert(wg_offer(borrowed->pool, id->type, other, sizeof other, 2000, 1010, &actual) == 1);
    for (size_t i = 0; i < size; ++i)
        assert(((const uint8_t *)bytes)[i] == 7);
    return 0;
}
static void accepting_callback(void)
{
    struct wg_pool pool;
    struct wg_session session;
    struct wg_config cfg = {.identify = identify, .objects = 2, .pending = 2, .bytes = 64};
    assert(!wg_init(&pool, &cfg) && !wg_open(&pool, &session, 1));
    size_t baseline = wg_memory(&pool);
    struct borrowed borrowed = {.pool = &pool};
    uint8_t bytes[64];
    memset(bytes, 7, sizeof bytes);
    struct wg_message have = {.op = WG_HAVE, .id.type = 1};
    assert(!identify(NULL, 1, bytes, sizeof bytes, have.id.hash));
    assert(!wg_receive(&session, &have, 1000, borrow_emit, borrowed_complete, &borrowed));
    struct wg_message data = borrowed.want;
    data.op = WG_DATA;
    data.data = bytes;
    data.size = data.total = sizeof bytes;
    assert(!wg_receive(&session, &data, 1000, borrow_emit, borrowed_complete, &borrowed));
    assert(pool.payload_bytes == sizeof bytes && pool.object_count == 1);
    wg_prune(&pool, 1010);
    assert(!pool.payload_bytes && !pool.object_count && wg_memory(&pool) == baseline);
    wg_close(&session);
    wg_deinit(&pool);
}
int main(void)
{
    idle_cycles(false);
    idle_cycles(true);
    stalled_uploads();
    retired_digests();
    owner_expires_retired_digests();
    accepting_callback();
    puts("idle TTL, stalled uploads, borrowed callbacks and digest retirement release payloads");
    return 0;
}
