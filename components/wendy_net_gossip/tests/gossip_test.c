/* Test transfer ownership, resource bounds and cross-neighbour recovery. */
#include "wendy_net_gossip.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_sha256.h"
static struct wg_pool new_pool(void) {
  struct wg_pool p = {0};
  struct wg_config c = {
      .identify = identify, .objects = 32, .pending = 16, .bytes = 128 * 1024};
  assert(!wg_init(&p, &c));
  return p;
}
struct endpoint {
  struct wg_pool *pool;
  struct wg_message message;
  uint8_t bytes[WG_CHUNK];
  unsigned emitted, completed;
  bool fail, accept;
  size_t size;
  uint8_t body[WG_OBJECT_MAX];
  uint64_t now;
};
static int emit(void *ctx, const struct wg_message *m) {
  struct endpoint *e = ctx;
  if (e->fail)
    return -1;
  e->message = *m;
  e->emitted++;
  if (m->size) {
    memcpy(e->bytes, m->data, m->size);
    e->message.data = e->bytes;
  }
  return 0;
}
static int complete(void *ctx, const struct wg_id *id, const void *bytes,
                    size_t size) {
  struct endpoint *e = ctx;
  struct wg_id actual;
  e->completed++;
  memcpy(e->body, bytes, size);
  e->size = size;
  if (e->accept) {
    assert(!wg_offer(e->pool, id->type, bytes, size, e->now + 60000, e->now,
                     &actual));
    assert(!memcmp(actual.hash, id->hash, 32));
  }
  return 0;
}
static void receive(struct wg_session *s, const struct wg_message *m,
                    uint64_t now, struct endpoint *e) {
  e->now = now;
  assert(!wg_receive(s, m, now, emit, complete, e));
}
static void transfer_and_recovery(void) {
  struct wg_pool origin = new_pool(), destination = new_pool();
  size_t idle = wg_memory(&destination);
  assert(idle == sizeof destination);
  struct wg_session sender = {0}, first = {0}, second = {0};
  assert(!wg_open(&origin, &sender, 1));
  assert(!wg_open(&destination, &first, 1));
  assert(!wg_open(&destination, &second, 1));
  uint8_t data[2500];
  for (unsigned i = 0; i < sizeof data; i++)
    data[i] = (uint8_t)(i * 37);
  struct wg_id id;
  assert(!wg_offer(&origin, 1, data, sizeof data, 100000, 100, &id));
  struct endpoint a = {.pool = &origin},
                  b = {.pool = &destination, .accept = true};
  struct wg_message have = {.op = WG_HAVE, .id = id};
  receive(&first, &have, 100, &b);
  assert(b.message.op == WG_WANT);
  uint64_t obsolete = b.message.request;
  receive(&sender, &b.message, 100, &a);
  unsigned emitted = b.emitted;
  receive(&second, &have, 101, &b);
  assert(b.emitted == emitted);
  assert(!wg_poll(&sender, 102, emit, &a));
  assert(a.message.op == WG_DATA && a.message.size == 1024);
  receive(&first, &a.message, 102, &b);
  assert(destination.payload_bytes == 2500 && !b.completed);
  wg_close(&first);
  assert(!destination.payload_bytes);
  assert(!wg_poll(&second, 103, emit, &b));
  assert(b.message.op == WG_WANT && b.message.request != obsolete);
  struct wg_message want = b.message;
  /* Bytes from the closed incarnation cannot complete the replacement. */
  receive(&second, &a.message, 104, &b);
  assert(!b.completed);
  /* Close/reopen the supplier too, so a fresh session cannot inherit output. */
  wg_close(&sender);
  assert(!wg_open(&origin, &sender, 1));
  receive(&sender, &want, 105, &a);
  for (unsigned i = 0; i < 3; i++) {
    assert(!wg_poll(&sender, 106 + i, emit, &a));
    receive(&second, &a.message, 106 + i, &b);
  }
  assert(b.completed == 1 && b.size == sizeof data &&
         !memcmp(data, b.body, sizeof data));
  emitted = b.emitted;
  receive(&second, &have, 110, &b);
  assert(b.emitted == emitted);
  wg_close(&sender);
  wg_close(&second);
  wg_prune(&destination, 70000);
  assert(wg_memory(&destination) == idle);
  wg_deinit(&origin);
  wg_deinit(&destination);
}
static void invalid_and_expiry(void) {
  struct wg_pool p = new_pool();
  struct wg_session s = {0};
  assert(!wg_open(&p, &s, 1));
  struct endpoint e = {.pool = &p};
  uint8_t data[1200] = {7};
  struct wg_id id;
  assert(!wg_offer(&p, 1, data, sizeof data, 50000, 1, &id));
  struct wg_message want = {.op = WG_WANT, .id = id, .request = 3};
  receive(&s, &want, 2, &e);
  e.fail = true;
  assert(wg_poll(&s, 3, emit, &e) < 0);
  e.fail = false;
  assert(!wg_poll(&s, 4, emit, &e));
  assert(e.message.offset == 0);
  assert(!wg_offer(&p, 1, data, sizeof data, 100000, 5, &id));
  /* Re-offering cannot extend the verified original expiry; mid-transfer
   * expiry produces UNAVAILABLE instead of serving stale signed bytes. */
  assert(!wg_poll(&s, 50000, emit, &e));
  assert(e.message.op == WG_UNAVAILABLE);
  wg_prune(&p, 50001);
  assert(!p.payload_bytes && !p.object_count);
  struct wg_message have = {.op = WG_HAVE, .id = id};
  receive(&s, &have, 50002, &e);
  struct wg_message chunk = {.op = WG_DATA,
                             .id = id,
                             .request = e.message.request,
                             .total = 1200,
                             .offset = 1024,
                             .data = data,
                             .size = 176};
  assert(wg_receive(&s, &chunk, 50003, emit, complete, &e) < 0);
  chunk.offset = 0;
  chunk.size = 1024;
  receive(&s, &chunk, 50004, &e);
  chunk.offset = 1024;
  chunk.size = 176;
  chunk.data = data + 1024;
  /* Corrupt content must fail before the adapter sees a completed object. */
  data[1100] ^= 1;
  assert(wg_receive(&s, &chunk, 50005, emit, complete, &e) < 0);
  assert(!e.completed);
  wg_close(&s);
  wg_deinit(&p);
}
static void idle_failover_and_limits(void) {
  struct wg_pool p = new_pool();
  p.config.pending = 1;
  p.config.bytes = 1024;
  struct wg_session a = {0}, b = {0};
  assert(!wg_open(&p, &a, 1));
  assert(!wg_open(&p, &b, 1));
  struct endpoint e = {.pool = &p};
  struct wg_message m = {.op = WG_HAVE, .id = {.type = 1, .hash = {1}}};
  receive(&a, &m, 1, &e);
  uint64_t old = e.message.request;
  receive(&b, &m, 2, &e);
  m.id.hash[0] = 2;
  assert(wg_receive(&a, &m, 3, emit, complete, &e) == 1);
  assert(!wg_poll(&b, 30001, emit, &e));
  assert(e.message.op == WG_WANT && e.message.request != old);
  m = (struct wg_message){.op = WG_DATA,
                          .id = {.type = 1, .hash = {1}},
                          .request = e.message.request,
                          .total = 1025,
                          .size = 1024,
                          .data = e.bytes};
  /* Over-quota DATA is consumed by dropping its supplier, without a payload
   * allocation or retrying the same frame. The carrier remains healthy. */
  assert(wg_receive(&b, &m, 30002, emit, complete, &e) == 0);
  assert(!p.payload_bytes);
  wg_close(&a);
  wg_close(&b);
  assert(wg_memory(&p) == sizeof p);
  wg_deinit(&p);
  assert(wg_validate(&(struct wg_message){.op = WG_DATA,
                                          .id.type = 1,
                                          .request = 1,
                                          .total = WG_OBJECT_MAX + 1,
                                          .data = e.bytes,
                                          .size = 1024}) < 0);
}
static void forget_superseded(void) {
  struct wg_pool p=new_pool();struct wg_session session={0};
  struct endpoint e={.pool=&p};assert(!wg_open(&p,&session,1));
  uint8_t data[2500]={1};struct wg_id first,second;
  assert(!wg_offer(&p,1,data,sizeof data,60000,1,&first));
  data[0]=2;assert(!wg_offer(&p,1,data,sizeof data,60000,1,&second));
  struct wg_message want={.op=WG_WANT,.id=first,.request=1};
  receive(&session,&want,1,&e);
  assert(p.serving==1 && p.payload_bytes==5000);
  wg_forget(&p,&first);assert(p.payload_bytes==5000);
  assert(!wg_poll(&session,2,emit,&e) && e.message.op==WG_UNAVAILABLE);
  wg_prune(&p,2);assert(p.payload_bytes==2500 && p.object_count==1);
  wg_forget(&p,&second);assert(!p.payload_bytes && !p.object_count);
  wg_close(&session);wg_deinit(&p);
}
int main(void) {
  forget_superseded();
  transfer_and_recovery();
  invalid_and_expiry();
  idle_failover_and_limits();
  printf("native gossip idle pool=%zu session=%zu chunk=%u\n",
         sizeof(struct wg_pool), sizeof(struct wg_session), WG_CHUNK);
  return 0;
}
