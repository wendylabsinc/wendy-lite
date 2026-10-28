/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_gossip.h"
#include "wendy_net_alloc.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct wg_object {
  struct wg_object *next;
  struct wg_id id;
  uint64_t expires, born, withdrawal;
  uint8_t *data;
  size_t size, refs;
  bool critical;
  void (*release)(const void *);
};
struct supplier {
  struct supplier *next;
  uint64_t owner, until;
};
struct wg_fetch {
  struct wg_fetch *next;
  struct wg_id id;
  struct supplier *suppliers;
  struct wg_object *accepted; /* Pins an adopted callback body until return. */
  uint64_t owner, request, progress, avoid;
  uint8_t *data;
  size_t size, total;
};
struct wg_transfer {
  struct wg_transfer *next;
  struct wg_object *object;
  uint64_t request;
  size_t offset;
};
static bool same(const struct wg_id *a, const struct wg_id *b) {
  return a->type == b->type && !memcmp(a->hash, b->hash, 32);
}
static void release_payload(struct wg_object *o) {
  if (!o->data)
    return;
  if (o->release)
    o->release(o->data);
  else
    wendy_net_free(o->data);
}
static void *meta(struct wg_pool *p, size_t n) {
  void *r = wendy_net_calloc(1, n);
  if (r)
    p->metadata_bytes += n;
  return r;
}
static void unmeta(struct wg_pool *p, void *v, size_t n) {
  if (v) {
    wendy_net_free(v);
    p->metadata_bytes -= n;
  }
}
static void drop_fetch(struct wg_pool *p, struct wg_fetch **at) {
  struct wg_fetch *f = *at;
  *at = f->next;
  while (f->suppliers) {
    struct supplier *q = f->suppliers;
    f->suppliers = q->next;
    unmeta(p, q, sizeof *q);
  }
  if (f->data) {
    p->payload_bytes -= f->total;
    p->type_payload[f->id.type-1] -= f->total;
    wendy_net_free(f->data);
  }
  unmeta(p, f, sizeof *f);
  p->pending_count--;
}
static void reset_fetch(struct wg_pool *p, struct wg_fetch *f) {
  if (f->data) {
    p->payload_bytes -= f->total;
    p->type_payload[f->id.type-1] -= f->total;
    wendy_net_free(f->data);
  }
  f->data = NULL;
  f->size = f->total = 0;
  f->avoid = f->owner;
  f->owner = 0;
}
static void drop_supplier(struct wg_pool *p,struct wg_fetch *f,uint64_t owner) {
  if(f->owner==owner)reset_fetch(p,f);
  for(struct supplier **at=&f->suppliers;*at;)
    if((*at)->owner==owner){struct supplier *q=*at;*at=q->next;unmeta(p,q,sizeof *q);}
    else at=&(*at)->next;
  if(!f->suppliers)
    for(struct wg_fetch **at=&p->pending;*at;at=&(*at)->next)
      if(*at==f){drop_fetch(p,at);break;}
}
static struct wg_object *find_object(struct wg_pool *p,
                                     const struct wg_id *id) {
  for (struct wg_object *o = p->objects; o; o = o->next)
    if (same(&o->id, id))
      return o;
  return NULL;
}
static struct wg_fetch *find_fetch(struct wg_pool *p, const struct wg_id *id) {
  for (struct wg_fetch *f = p->pending; f; f = f->next)
    if (same(&f->id, id))
      return f;
  return NULL;
}
void wg_forget(struct wg_pool *p,const struct wg_id *id) {
  if(!p || !id)return;
  for(struct wg_object **at=&p->objects;*at;at=&(*at)->next) {
    struct wg_object *o=*at;
    if(!same(&o->id,id))continue;
    if(p->config.fifo && !o->data)return; /* Keep the bounded retirement receipt. */
    o->expires=0;
    if(!o->refs) {
      *at=o->next;p->payload_bytes-=o->size;p->type_payload[o->id.type-1]-=o->size;release_payload(o);
      unmeta(p,o,sizeof *o);p->object_count--;
    }
    return;
  }
}
int wg_init(struct wg_pool *p, const struct wg_config *c) {
  if (!p || !c || !c->identify || !c->objects || !c->pending || !c->bytes ||
      c->reserve_objects>=c->objects || c->route_pending_reserve>=c->pending ||
      c->route_download_reserve>=(c->downloads ? c->downloads:16))
    return -1;
  *p = (struct wg_pool){.config = *c};
  return 0;
}
void wg_deinit(struct wg_pool *p) {
  if (!p)
    return;
  /* A live transfer references its object. Refuse use-after-free teardown. */
  if (p->serving)
    return;
  while (p->objects) {
    struct wg_object *o = p->objects;
    p->objects = o->next;
    release_payload(o);
    wendy_net_free(o);
  }
  while (p->pending)
    drop_fetch(p, &p->pending);
  memset(p, 0, sizeof *p);
}
int wg_open(struct wg_pool *p, struct wg_session *s, uint8_t type) {
  if (!p || !s || (type != 1 && type != 2 && type != 3) || p->next_owner == UINT64_MAX)
    return -1;
  *s = (struct wg_session){.pool = p, .owner = ++p->next_owner, .type = type,
      .withdrawal=p->withdrawal};
  return 0;
}
void wg_close(struct wg_session *s) {
  if (!s || !s->pool)
    return;
  struct wg_pool *p = s->pool;
  while (s->out) {
    struct wg_transfer *t = s->out;
    s->out = t->next;
    t->object->refs--;
    p->serving--;
    unmeta(p, t, sizeof *t);
  }
  for (struct wg_fetch **at = &p->pending; *at;) {
    struct wg_fetch *f = *at;
    for (struct supplier **q = &f->suppliers; *q;) {
      if ((*q)->owner == s->owner) {
        struct supplier *gone = *q;
        *q = gone->next;
        unmeta(p, gone, sizeof *gone);
      } else
        q = &(*q)->next;
    }
    if (f->owner == s->owner)
      reset_fetch(p, f);
    if (!f->suppliers)
      drop_fetch(p, at);
    else
      at = &f->next;
  }
  memset(s, 0, sizeof *s);
}
void wg_discard(struct wg_session *s,const struct wg_id *id) {
  if(!s || !s->pool || !id)return;
  for(struct wg_fetch *f=s->pool->pending;f;f=f->next)
    if(same(&f->id,id) && f->owner==s->owner){drop_supplier(s->pool,f,s->owner);return;}
}
static bool known_op(enum wg_op op) {
  switch (op) {
  case WG_HAVE: case WG_WANT: case WG_UNAVAILABLE: case WG_DATA: case WG_GONE:
    return true;
  default:
    return false;
  }
}
int wg_validate(const struct wg_message *m) {
  if (!m)
    return -1;
  /* Future operations have their own fields and semantics. Do not interpret
   * their envelopes as one of today's DATA/control messages. */
  if (!known_op(m->op))
    return 0;
  if (m->id.type != 1 && m->id.type != 2 && m->id.type != 3)
    return -1;
  if (m->op == WG_HAVE || m->op == WG_GONE)
    return m->request || m->offset || m->total || m->size ? -1 : 0;
  if (m->op == WG_WANT || m->op == WG_UNAVAILABLE)
    return !m->request || m->offset || m->total || m->size ? -1 : 0;
  if (m->op != WG_DATA || !m->request || !m->total ||
      m->total > WG_OBJECT_MAX || m->offset >= m->total ||
      m->offset % WG_CHUNK || !m->data)
    return -1;
  size_t n = m->total - m->offset;
  if (n > WG_CHUNK)
    n = WG_CHUNK;
  return m->size == n ? 0 : -1;
}
void wg_prune(struct wg_pool *p, uint64_t now) {
  for (struct wg_object **at = &p->objects; *at;) {
    struct wg_object *o = *at;
    if (o->expires <= now && !o->refs) {
      *at = o->next;
      p->payload_bytes -= o->size;
      p->type_payload[o->id.type-1] -= o->size;
      release_payload(o);
      unmeta(p, o, sizeof *o);
      p->object_count--;
    } else
      at = &o->next;
  }
  for (struct wg_fetch **at = &p->pending; *at;) {
    struct wg_fetch *f = *at;
    if (f->owner && now >= f->progress && now - f->progress >= WG_IDLE_MS)
      reset_fetch(p, f);
    for (struct supplier **q = &f->suppliers; *q;) {
      /* A recent WANT/DATA owns this supplier independently of its old HAVE
       * lease. Only idle transfers revert to expiring hint metadata. */
      if ((*q)->until <= now && (*q)->owner != f->owner) {
        struct supplier *gone = *q;
        *q = gone->next;
        unmeta(p, gone, sizeof *gone);
      } else
        q = &(*q)->next;
    }
    if (!f->suppliers)
      drop_fetch(p, at);
    else
      at = &f->next;
  }
}
/* Capacity eviction and explicit pressure reclamation share retirement rules. */
static struct wg_object *oldest_payload(struct wg_pool *p,uint8_t type) {
  struct wg_object *oldest=NULL;
  for(struct wg_object *o=p->objects;o;o=o->next) {
    if(!o->data || o->refs || (type && o->id.type!=type) ||
       (p->config.protected_object && p->config.protected_object(p->config.context,&o->id)))continue;
    if(!oldest || o->born<oldest->born)oldest=o;
  }
  return oldest;
}
static size_t retire_payload(struct wg_pool *p,struct wg_object *o) {
  size_t size=o->size;
  if(p->config.evicted)p->config.evicted(p->config.context,&o->id,o->data,size);
  p->payload_bytes-=size;p->type_payload[o->id.type-1]-=size;
  release_payload(o);o->data=NULL;o->size=0;o->release=NULL;
  o->withdrawal=++p->withdrawal;
  /* Exact digests stay forgotten through their lease plus stale-hint lifetime. */
  o->expires=o->expires>UINT64_MAX-WG_HINT_MS ? UINT64_MAX:o->expires+WG_HINT_MS;
  return size;
}
size_t wg_reclaim(struct wg_pool *p,size_t wanted) {
  if(!p || !p->config.fifo)return 0;
  size_t released=0;
  while(released<wanted && p->withdrawal!=UINT64_MAX) {
    struct wg_object *o=oldest_payload(p,0);
    if(!o)break;
    released+=retire_payload(p,o);
  }
  return released;
}
static int room(struct wg_pool *p,uint8_t type,size_t size,uint64_t now) {
  (void)now;
  size_t category=p->config.type_bytes[type-1];
  if(!category)category=p->config.bytes;
  if(size>category || size>p->config.bytes)return 1;
  while(size>p->config.bytes-p->payload_bytes ||
        size>category-p->type_payload[type-1]) {
    if(!p->config.fifo || p->withdrawal==UINT64_MAX)return 1;
    bool same_type=size>category-p->type_payload[type-1];
    struct wg_object *o=oldest_payload(p,same_type ? type:0);
    if(!o)return 1;
    retire_payload(p,o);
  }
  return 0;
}
static bool object_full(struct wg_pool *p, bool critical) {
  if (p->object_count >= p->config.objects)
    return true;
  if (!critical && p->config.reserve_objects) {
    size_t ordinary = 0;
    for (struct wg_object *o = p->objects; o; o = o->next)
      ordinary += !o->critical;
    return ordinary >= p->config.objects - p->config.reserve_objects;
  }
  return false;
}
static int offer(struct wg_pool *p, uint8_t type, const void *bytes, size_t size,
                 uint64_t expires, uint64_t now, struct wg_id *id,
                 void (*retain)(const void *), void (*release)(const void *)) {
  if (!p || !bytes || !size || size > WG_OBJECT_MAX || expires <= now || !id ||
      (type != 1 && type != 2 && type != 3))
    return -1;
  id->type = type;
  if (p->config.identify(p->config.context, type, bytes, size, id->hash))
    return -1;
  wg_prune(p, now);
  struct wg_object *o = find_object(p, id);
  if(o && !o->data)return 2;
  if (o) { /* Re-observation must not extend the original verified lease. */
    if (expires < o->expires)
      o->expires = expires;
    for (struct wg_fetch **at = &p->pending; *at; at = &(*at)->next)
      if (same(&(*at)->id, id)) {
        drop_fetch(p, at);
        break;
      }
    return 0;
  }
  bool critical=p->config.critical_object && p->config.critical_object(p->config.context,id);
  struct wg_fetch *received = p->delivering;
  bool adopt = !retain && received && received->data == bytes &&
      received->size == size && same(&received->id, id);
  if (object_full(p, critical) || p->next_object==UINT64_MAX ||
      (!adopt && room(p,type,size,now)))
    return 1;
  o = meta(p, sizeof *o);
  if (!o)
    return 1;
  if (adopt) {
    /* Verification accepted this exact receive allocation. Move its existing
     * byte charge, and pin it until the callback's borrowed view ends. */
    o->data = received->data;
    received->data = NULL;
    received->accepted = o;
    o->refs++;
  } else if (retain) {
    retain(bytes);
    o->data = (uint8_t *)bytes;
    o->release = release;
  } else {
    o->data = wendy_net_malloc(size);
    if (!o->data) {
      unmeta(p, o, sizeof *o);
      return 1;
    }
    memcpy(o->data, bytes, size);
  }
  o->id = *id;
  o->critical = critical;
  o->size = size;
  o->expires = expires;
  o->born=++p->next_object;
  o->next = p->objects;
  p->objects = o;
  p->object_count++;
  if (!adopt) {
    p->payload_bytes += size;
    p->type_payload[type-1] += size;
  }
  /* Resolve an in-flight download only after the adapter verified it. */
  for (struct wg_fetch **at = &p->pending; *at; at = &(*at)->next)
    if (same(&(*at)->id, id)) {
      drop_fetch(p, at);
      break;
    }
  return 0;
}
int wg_offer(struct wg_pool *p, uint8_t type, const void *bytes, size_t size,
             uint64_t expires, uint64_t now, struct wg_id *id) {
  return offer(p, type, bytes, size, expires, now, id, NULL, NULL);
}
int wg_offer_shared(struct wg_pool *p, uint8_t type, const void *bytes, size_t size,
                    uint64_t expires, uint64_t now, struct wg_id *id,
                    void (*retain)(const void *), void (*release)(const void *)) {
  if (!retain || !release)
    return -1;
  return offer(p, type, bytes, size, expires, now, id, retain, release);
}
static int claim(struct wg_session *s, struct wg_fetch *f, uint64_t now,
                 wg_emit emit, void *ctx) {
  struct wg_pool *p = s->pool;
  if (f->owner || f->id.type != s->type)
    return 0;
  /* A shared pool contains every carrier/category's hints. Establish that
   * this session can actually fetch it before scanning node-wide admission
   * counts or consulting the category's demand policy. */
  bool mine = false, other = false;
  for (struct supplier *q = f->suppliers; q; q = q->next) {
    mine |= q->owner == s->owner;
    other |= q->owner != s->owner;
  }
  if (!mine || (f->avoid == s->owner && other))
    return 0;
  if(p->config.want_object && !p->config.want_object(p->config.context,&f->id,now))
    return 0;
  bool critical = p->config.critical_object &&
      p->config.critical_object(p->config.context, &f->id);
  if (p->config.fifo && object_full(p, critical))
    return 0;
  unsigned active = 0, all = 0, nonroute = 0;
  for (struct wg_fetch *q = p->pending; q; q = q->next){
    active += q->owner == s->owner;all += q->owner != 0;
    nonroute += q->owner && q->id.type!=1;
  }
  size_t limit=p->config.downloads ? p->config.downloads:16;
  if (active >= 4 || all >= limit ||
      (f->id.type!=1 && nonroute>=limit-p->config.route_download_reserve) ||
      p->next_request == UINT64_MAX)
    return 0;
  struct wg_message m = {
      .id = f->id, .op = WG_WANT, .request = ++p->next_request};
  int sent=emit(ctx,&m);
  if(sent)return sent<0 ? -1:1;
  f->owner = s->owner;
  f->request = m.request;
  f->progress = now;
  return 0;
}
static int claim_pending(struct wg_session *s, uint64_t now, wg_emit emit, void *ctx) {
  for (struct wg_fetch *f = s->pool->pending; f; f = f->next) {
    int r = claim(s, f, now, emit, ctx);
    if (r)
      return r;
  }
  return 0;
}
/* Temporarily unlink the complete fetch: an accepting callback may offer
 * the same digest. Keep its byte/download accounting until actual admission. */
static int deliver(struct wg_session *s,struct wg_fetch *f,wg_complete complete,void *ctx)
{
    struct wg_pool *p=s->pool;
    struct wg_fetch **at=&p->pending;while(*at && *at!=f)at=&(*at)->next;
    if(!*at)return -1;
    *at=f->next;f->next=NULL;
    p->delivering=f;
    int r=complete(ctx,&f->id,f->data,f->size);
    p->delivering=NULL;
    f->next=p->pending;p->pending=f;
    if(f->accepted) {
      f->accepted->refs--;
      if(r==WG_DEFER)r=0; /* Already admitted; no unverified body remains. */
    } else if(r==WG_DEFER)return WG_DEFER;
    drop_fetch(p,&p->pending);return r;
}
int wg_receive(struct wg_session *s, const struct wg_message *m, uint64_t now,
               wg_emit emit, wg_complete complete, void *ctx) {
  if (!s || !s->pool || !emit || !complete || wg_validate(m))
    return -1;
  if (!known_op(m->op))
    return 0;
  if (m->id.type != s->type || now > UINT64_MAX - WG_HINT_MS)
    return -1;
  struct wg_pool *p = s->pool;
  wg_prune(p, now);
  struct wg_object *o = find_object(p, &m->id);
  struct wg_fetch *f = find_fetch(p, &m->id);
  if (m->op == WG_GONE) {
    /* Proactive supplier withdrawal, including a WANT queued before GONE.
     * Other suppliers and already verified local objects remain usable. */
    if (!f)
      return 0;
    if (f->owner == s->owner)
      reset_fetch(p, f);
    for (struct supplier **at = &f->suppliers; *at;)
      if ((*at)->owner == s->owner) {
        struct supplier *q = *at;
        *at = q->next;
        unmeta(p, q, sizeof *q);
      } else
        at = &(*at)->next;
    if (!f->suppliers)
      for (struct wg_fetch **at = &p->pending; *at; at = &(*at)->next)
        if (*at == f) {
          drop_fetch(p, at);
          break;
        }
    return 0;
  }
  if (m->op == WG_HAVE) {
    if ((o && o->expires > now) ||
        (p->config.known_object && p->config.known_object(p->config.context,&m->id))) {
      return 0;
    }
    if (!f) {
      size_t limit=p->config.pending-(m->id.type==2 ? p->config.route_pending_reserve:0);
      if(m->id.type!=2 && p->config.route_pending_reserve && p->pending_count>=limit){
        /* Route authorization must progress even after a burst filled its
         * reserve. Retire one idle service hint, never an admitted transfer. */
        for(struct wg_fetch **at=&p->pending;*at;at=&(*at)->next)
          if((*at)->id.type==2 && !(*at)->owner){drop_fetch(p,at);break;}
      }
      if (p->pending_count >= limit)
        return 1;
      f = meta(p, sizeof *f);
      if (!f)
        return 1;
      f->id = m->id;
      /* FIFO hints: newly announced objects cannot jump ahead of an older
       * waiting digest. Hint metadata is separate from active body buffers. */
      struct wg_fetch **tail=&p->pending;
      while(*tail)tail=&(*tail)->next;
      *tail=f;
      p->pending_count++;
    }
    struct supplier *q = f->suppliers;
    unsigned suppliers = 0;
    for (; q && q->owner != s->owner; q = q->next)
      suppliers++;
    if (!q) {
      if (suppliers >= 4)
        return 1;
      q = meta(p, sizeof *q);
      if (!q)
        return 1;
      q->owner = s->owner;
      q->next = f->suppliers;
      f->suppliers = q;
    }
    q->until = now + WG_HINT_MS;
    return claim_pending(s, now, emit, ctx);
  }
  if (m->op == WG_WANT) {
    for (struct wg_transfer *t = s->out; t; t = t->next)
      if (t->request == m->request)
        return 0;
    size_t limit=p->config.uploads ? p->config.uploads:16;
    if (!o || !o->data || o->expires <= now || s->serving >= 4 || p->serving >= limit) {
      struct wg_message reply = {
          .id = m->id, .op = WG_UNAVAILABLE, .request = m->request};
      return emit(ctx, &reply);
    }
    struct wg_transfer *t = meta(p, sizeof *t);
    if (!t)
      return 1;
    t->object = o;
    t->request = m->request;
    o->refs++;
    s->serving++;
    p->serving++;
    struct wg_transfer **at = &s->out;
    while (*at)
      at = &(*at)->next;
    *at = t;
    return 0;
  }
  if (!f || f->owner != s->owner || f->request != m->request)
    return 0;
  if (m->op == WG_UNAVAILABLE) {
    drop_supplier(p, f, s->owner);
    return 0;
  }
  if (m->offset != f->size || (f->total && f->total != m->total))
    return -1;
  if (!f->data) {
    if (room(p,m->id.type,m->total,now)) {
      drop_supplier(p,f,s->owner);
      return 0;
    }
    f->data = wendy_net_malloc(m->total);
    if (!f->data) {
      drop_supplier(p,f,s->owner);
      return 0;
    }
    f->total = m->total;
    p->payload_bytes += f->total;
    p->type_payload[f->id.type-1] += f->total;
  }
  memcpy(f->data + f->size, m->data, m->size);
  f->size += m->size;
  f->progress = now;
  if (f->size == f->total) {
    uint8_t digest[32];
    if (p->config.identify(p->config.context, f->id.type, f->data, f->size,
                           digest) ||
        memcmp(digest, f->id.hash, 32))
      return -1;
    int r=deliver(s,f,complete,ctx);
    return r==WG_DEFER ? 0:r;
  }
  return 0;
}
int wg_poll(struct wg_session *s, uint64_t now, wg_emit emit, void *ctx) {
  if (!s || !s->pool || !emit)
    return -1;
  struct wg_pool *p = s->pool;
  wg_prune(p, now);
  /* Withdraw stale supplier hints promptly, before starting more downloads.
   * One small message per poll, with progress committed only after enqueue.
   * Sessions opened later never advertised these objects and need no GONE. */
  struct wg_object *gone=NULL;
  for(struct wg_object *o=p->objects;o;o=o->next)
    if(o->id.type==s->type && o->withdrawal>s->withdrawal &&
       (!gone || o->withdrawal<gone->withdrawal))gone=o;
  if(gone) {
    struct wg_message m={.op=WG_GONE,.id=gone->id};
    int sent=emit(ctx,&m);if(sent)return sent<0 ? -1:1;
    s->withdrawal=gone->withdrawal;
    return 0;
  }
  int claimed = claim_pending(s, now, emit, ctx);
  if (claimed)
    return claimed;
  struct wg_transfer *t = s->out;
  if (!t)
    return 0;
  struct wg_object *o = t->object;
  if (o->expires <= now) {
    struct wg_message m = {
        .id = o->id, .op = WG_UNAVAILABLE, .request = t->request};
    int sent=emit(ctx,&m);
    if(sent)return sent<0 ? -1:1;
    s->out = t->next;
    o->refs--;
    s->serving--;
    p->serving--;
    unmeta(p, t, sizeof *t);
    return 0;
  }
  size_t n = o->size - t->offset;
  if (n > WG_CHUNK)
    n = WG_CHUNK;
  struct wg_message m = {.id = o->id,
                         .op = WG_DATA,
                         .request = t->request,
                         .offset = t->offset,
                         .total = o->size,
                         .data = o->data + t->offset,
                         .size = n};
  int sent=emit(ctx,&m);
  if(sent)return sent<0 ? -1:1;
  t->offset += n;
  s->out = t->next;
  if (t->offset == o->size) {
    o->refs--;
    s->serving--;
    p->serving--;
    unmeta(p, t, sizeof *t);
  } else {
    struct wg_transfer **at = &s->out;
    while (*at)
      at = &(*at)->next;
    t->next = NULL;
    *at = t;
  }
  return 0;
}
size_t wg_memory(const struct wg_pool *p) {
  return sizeof *p + p->metadata_bytes + p->payload_bytes;
}

int wg_resume(struct wg_session *s,wg_complete complete,void *ctx)
{
    if(!s || !s->pool || !complete)return -1;
    for(struct wg_fetch *f=s->pool->pending;f;f=f->next)
        if(f->owner==s->owner && f->data && f->total && f->size==f->total){
            int r=deliver(s,f,complete,ctx);return r==WG_DEFER ? 0:r<0 ? -1:1;
        }
    return 0;
}
int wg_resume_id(struct wg_session *s,const struct wg_id *id,wg_complete complete,void *ctx)
{
    if(!s || !s->pool || !id || !complete)return -1;
    for(struct wg_fetch *f=s->pool->pending;f;f=f->next)
        if(f->owner==s->owner && same(&f->id,id) && f->data && f->total && f->size==f->total){
            int r=deliver(s,f,complete,ctx);return r==WG_DEFER ? 0:r<0 ? -1:1;
        }
    return WG_RESUME_MISSING;
}

void wg_progress(const struct wg_pool *p,struct wg_progress *out)
{
    if(!out)return;
    memset(out,0,sizeof *out);
    if(!p)return;
    for(const struct wg_fetch *f=p->pending;f;f=f->next){
        if(f->id.type<1 || f->id.type>3)continue;
        unsigned i=f->id.type-1;
        out->hints[i]++;out->active[i]+=f->owner!=0;
        out->complete[i]+=f->data && f->total && f->size==f->total;
        out->bytes[i]+=f->size;
    }
}
