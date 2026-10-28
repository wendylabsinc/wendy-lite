/* Ordinary queue, expiry and verified receive ownership lifecycle regressions. */
#include "wendy_net_gossip.h"
#include "test_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct state {
  struct wg_pool *pool;
  struct wg_message last;
  unsigned wants, completed, data, gone;
  bool demand, accept, defer;
  uint64_t now;
  const void *accepted;
};
static bool want(void *context, const struct wg_id *id, uint64_t now) {
  (void)id; (void)now;
  return ((struct state *)context)->demand;
}
static bool critical(void *context, const struct wg_id *id) {
  (void)context;
  return id->type == 1;
}
static int emit(void *context, const struct wg_message *m) {
  struct state *s = context;
  s->last = *m;
  s->wants += m->op == WG_WANT;
  s->data += m->op == WG_DATA;
  s->gone += m->op == WG_GONE;
  if (m->op == WG_DATA && s->accepted)
    assert(m->data == (const uint8_t *)s->accepted + m->offset);
  return 0;
}
static int complete(void *context, const struct wg_id *id, const void *bytes,
                    size_t size) {
  struct state *s = context;
  s->completed++;
  if (s->accept && !s->defer) {
    struct wg_id actual;
    assert(!wg_offer(s->pool, id->type, bytes, size, s->now + 10000,
                     s->now, &actual));
    assert(!memcmp(actual.hash, id->hash, sizeof id->hash));
    assert(s->pool->payload_bytes == size);
    s->accepted = bytes;
    /* Re-observation and another offer cannot evict the callback's borrowed
     * view even though it now belongs to the cache. */
    assert(!wg_offer(s->pool, id->type, bytes, size, s->now + 10000,
                     s->now, &actual));
    uint8_t other[1024] = {99};
    assert(size <= sizeof other);
    assert(wg_offer(s->pool, id->type, other, size, s->now + 10000,
                    s->now, &actual) == 1);
    assert(((const uint8_t *)bytes)[0] == 7);
  }
  return s->defer ? WG_DEFER : 0;
}
static struct wg_message hint(uint8_t type, uint8_t value, size_t size) {
  uint8_t bytes[1024];
  assert(size <= sizeof bytes);
  memset(bytes, value, size);
  struct wg_message m = {.op = WG_HAVE, .id.type = type};
  assert(!identify(NULL, type, bytes, size, m.id.hash));
  return m;
}
static void receive_body(struct wg_session *session, struct state *state,
                         uint8_t value, size_t size) {
  uint8_t bytes[1024];
  assert(size <= sizeof bytes);
  memset(bytes, value, size);
  struct wg_message data = state->last;
  data.op = WG_DATA;
  data.data = bytes;
  data.size = data.total = (uint32_t)size;
  assert(!wg_receive(session, &data, state->now, emit, complete, state));
}
static void fifo_receive_and_unknown(void) {
  struct wg_pool pool;
  struct wg_session session;
  struct wg_config config = {.identify = identify, .objects = 8, .pending = 8,
      .bytes = 4096, .downloads = 1};
  assert(!wg_init(&pool, &config) && !wg_open(&pool, &session, 2));
  struct state state = {.pool = &pool, .now = 1000};
  struct wg_message first = hint(2, 1, 100), second = hint(2, 2, 100),
                    third = hint(2, 3, 100);
  assert(!wg_receive(&session, &first, 1000, emit, complete, &state));
  assert(!wg_receive(&session, &second, 1000, emit, complete, &state));
  receive_body(&session, &state, 1, 100);
  assert(state.wants == 1 && pool.pending_count == 1);
  /* A normal new HAVE before the next tick cannot overtake older hints. */
  assert(!wg_receive(&session, &third, 1001, emit, complete, &state));
  assert(state.wants == 2 && !memcmp(state.last.id.hash, second.id.hash, 32));
  uint64_t request = state.last.request;
  size_t memory = wg_memory(&pool);
  struct wg_message future = {.op = (enum wg_op)99, .id.type = 77,
      .request = request, .offset = 3, .total = 1, .size = 7};
  assert(!wg_validate(&future));
  assert(!wg_receive(&session, &future, UINT64_MAX, emit, complete, &state));
  assert(wg_memory(&pool) == memory && state.wants == 2 &&
         state.last.request == request && !pool.payload_bytes);
  /* Known operation field checks still apply. */
  future.op = WG_DATA;
  assert(wg_validate(&future) < 0);
  state.now = 1002;
  receive_body(&session, &state, 2, 100);
  assert(!wg_poll(&session, 1003, emit, &state));
  assert(state.wants == 3 && !memcmp(state.last.id.hash, third.id.hash, 32));
  state.now = 1004;
  receive_body(&session, &state, 3, 100);
  assert(state.completed == 3 && !pool.pending_count && !pool.payload_bytes);
  wg_close(&session);
  wg_deinit(&pool);
}
static void active_hint_expiry(void) {
  struct wg_pool pool;
  struct wg_session session;
  struct state state = {.pool = &pool};
  struct wg_config config = {.identify = identify, .context = &state,
      .objects = 4, .pending = 4, .bytes = 4096, .downloads = 1,
      .want_object = want};
  assert(!wg_init(&pool, &config) && !wg_open(&pool, &session, 1));
  struct wg_message have = hint(1, 7, 100);
  assert(!wg_receive(&session, &have, 0, emit, complete, &state));
  state.demand = true;
  assert(!wg_poll(&session, WG_HINT_MS - 1, emit, &state));
  assert(state.wants == 1);
  state.now = WG_HINT_MS;
  receive_body(&session, &state, 7, 100);
  assert(state.completed == 1 && !pool.pending_count);
  /* An inactive hint still expires; an admitted but idle fetch also expires
   * once its original hint is stale. Neither leaves a body or download slot. */
  state.demand = false;
  assert(!wg_receive(&session, &have, 2 * WG_HINT_MS, emit, complete, &state));
  wg_prune(&pool, 3 * WG_HINT_MS);
  assert(!pool.pending_count);
  assert(!wg_receive(&session, &have, 4 * WG_HINT_MS, emit, complete, &state));
  state.demand = true;
  assert(!wg_poll(&session, 5 * WG_HINT_MS - 1, emit, &state));
  wg_prune(&pool, 5 * WG_HINT_MS + WG_IDLE_MS);
  assert(!pool.pending_count && !pool.payload_bytes);
  wg_close(&session);
  wg_deinit(&pool);
}
static void reserved_capacity_and_receipts(void) {
  struct wg_pool pool;
  struct wg_config config = {.identify = identify, .objects = 3, .pending = 4,
      .bytes = 1024, .reserve_objects = 1, .critical_object = critical,
      .fifo = true};
  assert(!wg_init(&pool, &config));
  uint8_t body[256] = {1};
  struct wg_id id, retired;
  assert(!wg_offer(&pool, 1, body, sizeof body, 10000, 1000, &id));
  assert(!wg_offer(&pool, 2, body, sizeof body, 10000, 1000, &retired));
  body[0] = 2;
  assert(!wg_offer(&pool, 2, body, sizeof body, 10000, 1000, &id));
  assert(pool.object_count == 3);
  assert(wg_reclaim(&pool, 1024) == 768);
  /* Retired rows continue to consume their own category's metadata share. */
  body[0] = 3;
  assert(wg_offer(&pool, 2, body, sizeof body, 10000, 1001, &id) == 1);
  body[0] = 1;
  assert(wg_offer(&pool, 2, body, sizeof body, 1000000, 2000, &id) == 2);
  wg_forget(&pool, &retired);
  assert(wg_offer(&pool, 2, body, sizeof body, 1000000, 3000, &id) == 2);
  wg_prune(&pool, 10000 + WG_HINT_MS);
  assert(!pool.object_count && !pool.payload_bytes);
  /* Receipt expiry permits an explicit later offer; no automatic refill. */
  assert(!wg_offer(&pool, 2, body, sizeof body, 1000000,
                   10000 + WG_HINT_MS, &id));
  wg_deinit(&pool);
}
static void verified_full_budget_handoff(bool defer) {
  struct wg_pool pool;
  struct wg_session session;
  struct wg_config config = {.identify = identify, .objects = 4, .pending = 4,
      .bytes = 1024, .downloads = 1, .fifo = true, .type_bytes = {1024}};
  assert(!wg_init(&pool, &config) && !wg_open(&pool, &session, 1));
  struct state state = {.pool = &pool, .now = 1000, .accept = true, .defer = defer};
  struct wg_message have = hint(1, 7, 1024);
  assert(!wg_receive(&session, &have, 1000, emit, complete, &state));
  receive_body(&session, &state, 7, 1024);
  if (defer) {
    assert(pool.pending_count == 1 && pool.payload_bytes == 1024);
    state.defer = false;
    assert(wg_resume_id(&session, &have.id, complete, &state) == 1);
  }
  assert(!pool.pending_count && pool.object_count == 1 && pool.payload_bytes == 1024);
  struct wg_message request = {.op = WG_WANT, .id = have.id, .request = 10};
  assert(!wg_receive(&session, &request, 1001, emit, complete, &state));
  assert(!wg_poll(&session, 1002, emit, &state) && state.data == 1);
  /* The adopted allocation has one ordinary cache owner after completion. */
  wg_forget(&pool, &have.id);
  assert(!pool.object_count && !pool.payload_bytes);
  wg_close(&session);
  wg_deinit(&pool);
}
static void critical_download_reserve(void) {
  struct wg_pool pool;
  struct wg_session route;
  struct wg_config config = {.identify = identify, .objects = 3, .pending = 4,
      .bytes = 4096, .reserve_objects = 1, .critical_object = critical,
      .fifo = true};
  assert(!wg_init(&pool, &config) && !wg_open(&pool, &route, 1));
  uint8_t body[100] = {1};
  struct wg_id id;
  assert(!wg_offer(&pool, 2, body, sizeof body, 10000, 1000, &id));
  body[0] = 2;
  assert(!wg_offer(&pool, 2, body, sizeof body, 10000, 1000, &id));
  struct state state = {.pool = &pool, .now = 1001};
  struct wg_message have = hint(1, 7, 100);
  assert(!wg_receive(&route, &have, 1001, emit, complete, &state));
  assert(state.wants == 1); /* The reserved row can receive a critical body. */
  receive_body(&route, &state, 7, 100);
  assert(state.completed == 1 && !pool.pending_count);
  wg_close(&route);
  wg_deinit(&pool);
}
static void pinned_pressure_progress(void) {
  struct wg_pool pool;
  struct wg_session session;
  struct wg_config config = {.identify = identify, .objects = 4, .pending = 4,
      .bytes = 1024, .downloads = 1, .uploads = 1, .fifo = true};
  assert(!wg_init(&pool, &config) && !wg_open(&pool, &session, 2));
  struct state state = {.pool = &pool, .now = 1001};
  uint8_t body[1024] = {1};
  struct wg_id original;
  assert(!wg_offer(&pool, 2, body, sizeof body, 10000, 1000, &original));
  struct wg_message upload = {.op = WG_WANT, .id = original, .request = 11};
  assert(!wg_receive(&session, &upload, 1001, emit, complete, &state));
  struct wg_message have = hint(2, 7, 1024);
  assert(!wg_receive(&session, &have, 1001, emit, complete, &state));
  receive_body(&session, &state, 7, 1024);
  assert(!state.completed && !pool.pending_count && pool.serving == 1 &&
         pool.object_count == 1 && pool.payload_bytes == 1024);
  /* The existing upload completes normally; a later announcement can then
   * retire its idle body and admit another full-budget verified body. */
  assert(!wg_poll(&session, 1002, emit, &state) && state.data == 1 && !pool.serving);
  assert(!wg_receive(&session, &have, 1003, emit, complete, &state));
  state.accept = true;
  state.now = 1003;
  receive_body(&session, &state, 7, 1024);
  assert(state.completed == 1 && !pool.pending_count && pool.object_count == 2 &&
         pool.payload_bytes == 1024);
  assert(!wg_poll(&session, 1004, emit, &state) && state.gone == 1);
  assert(!memcmp(state.last.id.hash, original.hash, 32));
  wg_close(&session);
  wg_deinit(&pool);
}
static void unavailable_handoff(void) {
  struct wg_pool pool;
  struct wg_session first, other;
  struct wg_config config = {.identify = identify, .objects = 4, .pending = 4,
      .bytes = 4096, .downloads = 1};
  assert(!wg_init(&pool, &config) && !wg_open(&pool, &first, 2) &&
         !wg_open(&pool, &other, 2));
  struct state a = {0}, b = {0};
  struct wg_message have = hint(2, 1, 100);
  assert(!wg_receive(&first, &have, 1000, emit, complete, &a));
  assert(!wg_receive(&other, &have, 1001, emit, complete, &b));
  struct wg_message unavailable = {.op = WG_UNAVAILABLE, .id = have.id,
                                   .request = a.last.request};
  assert(!wg_receive(&first, &unavailable, 1002, emit, complete, &a));
  assert(!wg_poll(&other, 1003, emit, &b) && b.wants == 1);
  unavailable.request = b.last.request;
  assert(!wg_receive(&other, &unavailable, 1004, emit, complete, &b));
  assert(!pool.pending_count && !pool.metadata_bytes && !pool.payload_bytes);
  wg_close(&first);
  wg_close(&other);
  wg_deinit(&pool);
}
int main(void) {
  fifo_receive_and_unknown();
  active_hint_expiry();
  reserved_capacity_and_receipts();
  verified_full_budget_handoff(false);
  verified_full_budget_handoff(true);
  critical_download_reserve();
  pinned_pressure_progress();
  unavailable_handoff();
  puts("FIFO hints, future operations, active leases, reservations and full-budget verified ownership progress");
  return 0;
}
