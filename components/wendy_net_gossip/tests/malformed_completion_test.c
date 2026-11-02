/* Rejected complete DATA must never enter the deferred completion path. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct state {
    struct wg_message want;
    unsigned wants, completed;
    bool fail_identify;
};
static int guarded_identify(void *context, uint8_t type, const void *bytes, size_t size,
                            uint8_t digest[32])
{
    struct state *s = context;
    return s->fail_identify ? -1 : identify(NULL, type, bytes, size, digest);
}
static int emit(void *context, const struct wg_message *m)
{
    struct state *s = context;
    if (m->op == WG_WANT) {
        s->want = *m;
        s->wants++;
    }
    return 0;
}
static int complete(void *context, const struct wg_id *id, const void *bytes, size_t size)
{
    struct state *s = context;
    (void)id;
    const unsigned char *data = bytes;
    for (size_t i = 0; i < size; ++i)
        assert(data[i] == 7);
    s->completed++;
    return WG_DEFER;
}
static void rejected_complete(bool digest_failure, bool alternate)
{
    struct state state = {0};
    struct wg_pool pool;
    struct wg_session first, other;
    struct wg_config config = {.identify = guarded_identify,
                               .context = &state,
                               .objects = 4,
                               .pending = 4,
                               .bytes = 4096,
                               .downloads = 1};
    assert(!wg_init(&pool, &config));
    assert(!wg_open(&pool, &first, 2) && !wg_open(&pool, &other, 2));
    unsigned char bytes[1500];
    memset(bytes, 7, sizeof bytes);
    struct wg_message have = {.op = WG_HAVE, .id.type = 2};
    assert(!identify(NULL, 2, bytes, sizeof bytes, have.id.hash));
    assert(!wg_receive(&first, &have, 1000, emit, complete, &state));
    if (alternate)
        assert(!wg_receive(&other, &have, 1001, emit, complete, &state));
    struct wg_message data = state.want;
    data.op = WG_DATA;
    data.data = bytes;
    data.total = sizeof bytes;
    data.size = WG_CHUNK;
    assert(!wg_receive(&first, &data, 1002, emit, complete, &state));
    if (!digest_failure)
        bytes[1499] ^= 1;
    state.fail_identify = digest_failure;
    data.offset = WG_CHUNK;
    data.data = bytes + WG_CHUNK;
    data.size = sizeof bytes - WG_CHUNK;
    assert(wg_receive(&first, &data, 1003, emit, complete, &state) < 0);
    /* Both resume entry points must ignore the rejected body, even if the
     * driver elects to recover without immediately closing the session. */
    assert(!wg_resume(&first, complete, &state));
    assert(wg_resume_id(&first, &have.id, complete, &state) == WG_RESUME_MISSING);
    assert(!state.completed && !pool.payload_bytes);
    assert(pool.pending_count == (size_t)alternate);
    if (alternate) {
        state.fail_identify = false;
        memset(bytes, 7, sizeof bytes);
        assert(!wg_poll(&other, 1004, emit, &state) && state.wants == 2);
        data = state.want;
        data.op = WG_DATA;
        data.data = bytes;
        data.total = sizeof bytes;
        data.size = WG_CHUNK;
        assert(!wg_receive(&other, &data, 1005, emit, complete, &state));
        data.offset = WG_CHUNK;
        data.data = bytes + WG_CHUNK;
        data.size = sizeof bytes - WG_CHUNK;
        assert(!wg_receive(&other, &data, 1006, emit, complete, &state));
        assert(state.completed == 1);
        wg_discard(&other, &have.id);
    }
    wg_close(&first);
    wg_close(&other);
    assert(!pool.pending_count && !pool.payload_bytes && !pool.metadata_bytes);
    wg_deinit(&pool);
}
int main(void)
{
    rejected_complete(false, false);
    rejected_complete(false, true);
    rejected_complete(true, false);
    rejected_complete(true, true);
    puts("Rejected complete bodies cannot resume; alternate suppliers retain progress");
    return 0;
}
