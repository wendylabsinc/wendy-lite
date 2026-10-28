/* SPDX-License-Identifier: Apache-2.0
 * Native, bounded port of WendyOS go/babel/engine.go. No sockets.
 */
#include "storage.h"
#include "wendy_babel.h"
#include <string.h>

static bool newer(uint16_t a, uint16_t b)
{
    uint16_t d = (uint16_t)(a - b);
    return d && d < 32768;
}
static bool at_least(uint16_t a, uint16_t b) { return a == b || newer(a, b); }
static uint16_t add_cost(uint16_t a, uint16_t b)
{
    uint32_t n = (uint32_t)a + b;
    return n >= WB_INFINITY ? WB_INFINITY : (uint16_t)n;
}
static uint64_t hold(uint64_t n) { return n * 7 / 2; }
static bool zero(const uint8_t *a, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (a[i])
            return false;
    return true;
}
static int prefix_cmp(const struct wb_prefix *a, const struct wb_prefix *b)
{
    if (a->family != b->family)
        return a->family < b->family ? -1 : 1;
    int c = memcmp(a->bytes, b->bytes, 16);
    return c ? c : (int)a->bits - (int)b->bits;
}
static bool routable(const struct wb_prefix *p)
{
    if (!wb_prefix_valid(p))
        return false;
    if (p->family == 6)
    {
        if ((p->bytes[0] == 0xfe && (p->bytes[1] & 0xc0) == 0x80) || p->bytes[0] == 0xff)
            return false;
        if (zero(p->bytes, 15) && p->bytes[15] == 1)
            return false;
        if (zero(p->bytes, 10) && p->bytes[10] == 0xff && p->bytes[11] == 0xff)
            return false;
    }
    else if (p->bytes[0] == 127 || (p->bytes[0] == 169 && p->bytes[1] == 254) ||
             (p->bytes[0] & 0xf0) == 0xe0)
        return false;
    return !(zero(p->bytes, 16) && p->bits == (p->family == 4 ? 32 : 128));
}
static struct wb_link_state *link_for(struct wb_engine *e, uint64_t id)
{
    for (size_t i = 0; i < e->links_capacity; i++)
        if (e->links[i].config.id == id)
            return &e->links[i];
    return NULL;
}
static struct wb_source *source_for(struct wb_engine *e, const struct wb_prefix *p, uint64_t router)
{
    for (size_t i = 0; i < e->sources_capacity; i++)
        if (e->sources[i].used && e->sources[i].router == router &&
            wb_prefix_equal(&e->sources[i].prefix, p))
            return &e->sources[i];
    return NULL;
}
static struct wb_route *route_for(struct wb_engine *e, const struct wb_prefix *p)
{
    for (size_t i = 0; i < e->route_count; i++)
        if (wb_prefix_equal(&e->routes[i].prefix, p))
            return &e->routes[i];
    return NULL;
}
static struct wb_local *local_for(struct wb_engine *e, const struct wb_prefix *p)
{
    for (size_t i = 0; i < e->local_capacity; i++)
        if (e->local[i].used && wb_prefix_equal(&e->local[i].prefix, p))
            return &e->local[i];
    return NULL;
}
/* The route bound counts distinct prefixes, including retained suppression.
 * Alternate carriers have their own WB_CANDIDATES ceiling. */
static bool prefix_admitted(const struct wb_engine *e, const struct wb_prefix *p)
{
    for (size_t i = 0; i < e->candidates_capacity; i++)
        if (e->candidates[i].used && wb_prefix_equal(&e->candidates[i].route.prefix, p))
            return true;
    for (size_t i = 0; i < e->local_capacity; i++)
        if (e->local[i].used && wb_prefix_equal(&e->local[i].prefix, p))
            return true;
    for (size_t i = 0; i < e->drops_capacity; i++)
        if (e->drops[i].used && wb_prefix_equal(&e->drops[i].prefix, p))
            return true;
    return false;
}
static unsigned admission_count(const struct wb_engine *e)
{
    unsigned n = 0;
    for (size_t i = 0; i < e->candidates_capacity; i++)
        if (e->candidates[i].used)
        {
            bool seen = false;
            for (size_t j = 0; j < i; j++)
                seen |= e->candidates[j].used &&
                        wb_prefix_equal(&e->candidates[i].route.prefix, &e->candidates[j].route.prefix);
            n += !seen;
        }
    for (size_t i = 0; i < e->local_capacity; i++)
        if (e->local[i].used)
        {
            bool seen = false;
            for (size_t j = 0; j < e->candidates_capacity; j++)
                seen |= e->candidates[j].used &&
                        wb_prefix_equal(&e->local[i].prefix, &e->candidates[j].route.prefix);
            n += !seen;
        }
    for (size_t i = 0; i < e->drops_capacity; i++)
        if (e->drops[i].used)
        {
            bool seen = false;
            for (size_t j = 0; j < e->candidates_capacity; j++)
                seen |= e->candidates[j].used &&
                        wb_prefix_equal(&e->drops[i].prefix, &e->candidates[j].route.prefix);
            for (size_t j = 0; j < e->local_capacity; j++)
                seen |= e->local[j].used &&
                        wb_prefix_equal(&e->drops[i].prefix, &e->local[j].prefix);
            n += !seen;
        }
    return n;
}
static uint32_t hello_ms(const struct wb_engine *e, const struct wb_link_state *l)
{
    return l->config.hello_ms ? l->config.hello_ms : e->config.hello_ms;
}
static uint16_t cost(const struct wb_engine *e, const struct wb_link_state *l)
{
    if (!l || l->ihu_expires <= e->now || l->tx == WB_INFINITY ||
        (l->hello_expires[0] <= e->now && l->hello_expires[1] <= e->now))
        return WB_INFINITY;
    return l->config.cost > l->tx ? l->config.cost : (l->tx ? l->tx : 1);
}
static bool allowed(struct wb_engine *e, const struct wb_candidate *r)
{
    return !e->config.allow ||
           e->config.allow(e->config.context, r->route.router, &r->route.prefix, r->route.seqno);
}
static uint16_t metric(struct wb_engine *e, const struct wb_candidate *r)
{
    return allowed(e, r) ? add_cost(r->advertised, cost(e, link_for(e, r->route.link)))
                         : WB_INFINITY;
}
static bool feasible(struct wb_engine *e, const struct wb_candidate *r)
{
    struct wb_source *s = source_for(e, &r->route.prefix, r->route.router);
    return r->advertised == WB_INFINITY || !s || newer(r->route.seqno, s->seqno) ||
           (r->route.seqno == s->seqno && r->advertised < s->metric);
}
static uint64_t jitter(struct wb_engine *e, uint64_t maximum)
{
    e->rng ^= e->rng << 13;
    e->rng ^= e->rng >> 7;
    e->rng ^= e->rng << 17;
    return e->rng % (maximum + 1);
}
static void trigger(struct wb_engine *e, bool repeat)
{
    if (!e->trigger)
    {
        e->trigger = true;
        e->trigger_at = e->now + jitter(e, 50);
    }
    if (repeat)
        e->repeats = 2;
}
static void queue(struct wb_engine *e, uint64_t id, const struct wb_message *m)
{
    if (!link_for(e, id))
        return;
    if (e->message_count == WB_MESSAGES)
    {
        e->counters.queue_drops++;
        return;
    }
    if (!wb_reserve_messages(e, e->message_count + 1))
    {
        e->counters.queue_drops++;
        return;
    }
    e->messages[e->message_count++] = (struct wb_queued){.link = id, .message = *m};
}
static void advertise(struct wb_engine *e, uint64_t id, const struct wb_prefix *prefix,
                      bool explicit)
{
    struct wb_link_state *l = link_for(e, id);
    if (!l)
        return;
    struct wb_route *r = route_for(e, prefix);
    struct wb_message m = {.type = WB_UPDATE,
                           .prefix = *prefix,
                           .metric = WB_INFINITY,
                           .interval = (uint16_t)(e->config.update_ms / 10)};
    if (!r || r->unreachable)
    {
        queue(e, id, &m);
        return;
    }
    if (!explicit && r->link == id)
        return;
    m.router = r->router;
    m.seqno = r->seqno;
    m.metric = r->metric;
    if (prefix->family == 4)
    {
        if (!zero(l->config.ipv4, 4))
        {
            m.address_family = 4;
            memcpy(m.address, l->config.ipv4, 4);
        }
        else if (e->config.ipv4_via_ipv6)
            m.via6 = true;
        else
            return;
    }
    struct wb_source *s = source_for(e, prefix, r->router);
    if (!s)
    {
        for (size_t i = 0; i < e->sources_capacity; i++)
            if (!e->sources[i].used)
            {
                s = &e->sources[i];
                break;
            }
        if (!s)
        {
            size_t slot = e->sources_capacity;
            if (wb_reserve_sources(e, slot + 1))
                s = &e->sources[slot];
        }
        if (!s)
        {
            e->counters.rejected++;
            return;
        }
        *s = (struct wb_source){.used = true,
                                .prefix = *prefix,
                                .router = r->router,
                                .seqno = r->seqno,
                                .metric = r->metric};
    }
    if (newer(r->seqno, s->seqno) || (r->seqno == s->seqno && r->metric < s->metric))
    {
        s->seqno = r->seqno;
        s->metric = r->metric;
    }
    s->expires = e->now + e->config.source_ms;
    queue(e, id, &m);
}
static void dump(struct wb_engine *e, uint64_t id, bool explicit)
{
    for (size_t i = 0; i < e->route_count; i++)
        advertise(e, id, &e->routes[i].prefix, explicit);
}
static void request(struct wb_engine *e, const struct wb_prefix *p, uint64_t router, uint16_t seq,
                    const uint64_t *targets, unsigned count, uint64_t from, uint8_t hops)
{
    struct wb_request_state *q = NULL, *free_slot = NULL;
    for (size_t i = 0; i < e->requests_capacity; i++)
    {
        if (!e->requests[i].used)
        {
            if (!free_slot)
                free_slot = &e->requests[i];
        }
        else if (e->requests[i].message.router == router &&
                 wb_prefix_equal(&e->requests[i].message.prefix, p))
        {
            q = &e->requests[i];
            break;
        }
    }
    if (q && at_least(q->message.seqno, seq))
        return;
    if (!q)
        q = free_slot;
    if (!q)
    {
        size_t slot = e->requests_capacity;
        if (wb_reserve_requests(e, slot + 1))
            q = &e->requests[slot];
    }
    if (!q)
    {
        e->counters.rejected++;
        return;
    }
    *q = (struct wb_request_state){
        .used = true,
        .from = from,
        .next = e->now + 1000,
        .expires = e->now + 4000,
        .remaining = 2,
        .message = {
            .type = WB_SEQ_REQUEST, .prefix = *p, .router = router, .seqno = seq, .hops = hops}};
    for (unsigned i = 0; i < count && i < WB_LINKS; i++)
    {
        bool seen = false;
        for (unsigned j = 0; j < q->target_count; j++)
            seen |= q->targets[j] == targets[i];
        if (!seen)
        {
            q->targets[q->target_count++] = targets[i];
            queue(e, targets[i], &q->message);
        }
    }
}
static void drop_route(struct wb_engine *e, const struct wb_prefix *p)
{
    struct wb_drop *d = NULL;
    for (size_t i = 0; i < e->drops_capacity; i++)
        if (e->drops[i].used && wb_prefix_equal(&e->drops[i].prefix, p))
        {
            d = &e->drops[i];
            break;
        }
    if (!d)
        for (size_t i = 0; i < e->drops_capacity; i++)
            if (!e->drops[i].used)
            {
                d = &e->drops[i];
                break;
            }
    if (!d)
    {
        size_t slot = e->drops_capacity;
        if (wb_reserve_drops(e, slot + 1))
            d = &e->drops[slot];
    }
    /* At most WB_ROUTES selected prefixes can need simultaneous suppression. */
    if (d)
        *d = (struct wb_drop){
            .used = true, .prefix = *p, .expires = e->now + hold(e->config.update_ms)};
    else
        e->stopped = true; /* Never silently lose loop-suppression state. */
}
static bool route_equal(const struct wb_route *a, const struct wb_route *b)
{
    return wb_prefix_equal(&a->prefix, &b->prefix) && a->router == b->router &&
           a->link == b->link && a->seqno == b->seqno && a->metric == b->metric &&
           a->local == b->local && a->unreachable == b->unreachable &&
           a->next_family == b->next_family && !memcmp(a->next_hop, b->next_hop, 16);
}
static void sort_routes(struct wb_engine *e)
{
    for (size_t i = 1; i < e->route_count; i++)
    {
        struct wb_route r = e->routes[i];
        size_t j = i;
        while (j && prefix_cmp(&r.prefix, &e->routes[j - 1].prefix) < 0)
        {
            e->routes[j] = e->routes[j - 1];
            j--;
        }
        e->routes[j] = r;
    }
}
static void select_routes(struct wb_engine *e)
{
    /* Preserve the previous selected table without a variable-sized stack. */
    if (e->stopped)
        return;
    size_t count = e->route_count;
    if (!wb_reserve_scratch(e, count))
    {
        e->stopped = true;
        return;
    }
    struct wb_route *old = e->scratch;
    if (count)
        memcpy(old, e->routes, count * sizeof *old);
    e->route_count = 0;
    for (size_t i = 0; i < e->local_capacity; i++)
        if (e->local[i].used)
        {
            if (!wb_reserve_routes(e, e->route_count + 1))
            {
                e->stopped = true;
                goto done;
            }
            e->routes[e->route_count++] = (struct wb_route){.prefix = e->local[i].prefix,
                                                            .router = e->config.router,
                                                            .seqno = e->seqno,
                                                            .metric = e->local[i].metric,
                                                            .local = true};
        }
    for (size_t i = 0; i < e->candidates_capacity; i++)
    {
        struct wb_candidate *c = &e->candidates[i];
        if (!c->used || local_for(e, &c->route.prefix))
            continue;
        uint16_t m = metric(e, c);
        if (m == WB_INFINITY || !feasible(e, c))
            continue;
        struct wb_route *r = route_for(e, &c->route.prefix);
        uint64_t previous = 0;
        for (size_t j = 0; j < count; j++)
            if (wb_prefix_equal(&old[j].prefix, &c->route.prefix))
            {
                previous = old[j].link;
                break;
            }
        if (!r)
        {
            if (!wb_reserve_routes(e, e->route_count + 1))
            {
                e->stopped = true;
                goto done;
            }
            r = &e->routes[e->route_count++];
            *r = c->route;
            r->metric = m;
        }
        else if (m < r->metric ||
                 (m == r->metric &&
                  (c->route.link == previous || (r->link != previous && c->route.link < r->link))))
        {
            *r = c->route;
            r->metric = m;
        }
    }
    for (size_t i = 0; i < count; i++)
        if (!old[i].unreachable && !route_for(e, &old[i].prefix))
        {
            drop_route(e, &old[i].prefix);
            trigger(e, true);
            struct wb_source *s = source_for(e, &old[i].prefix, old[i].router);
            if (s)
            {
                uint64_t targets[WB_LINKS];
                unsigned n = 0;
                for (size_t j = 0; j < e->candidates_capacity; j++)
                {
                    struct wb_candidate *c = &e->candidates[j];
                    if (c->used && wb_prefix_equal(&c->route.prefix, &old[i].prefix) &&
                        c->advertised != WB_INFINITY &&
                        cost(e, link_for(e, c->route.link)) != WB_INFINITY && n < WB_LINKS)
                        targets[n++] = c->route.link;
                }
                if (n)
                    request(e, &old[i].prefix, old[i].router, (uint16_t)(s->seqno + 1), targets, n,
                            0, 64);
            }
        }
    for (size_t i = 0; i < e->drops_capacity; i++)
    {
        struct wb_drop *d = &e->drops[i];
        if (!d->used)
            continue;
        if (route_for(e, &d->prefix) || d->expires <= e->now)
        {
            d->used = false;
            continue;
        }
        if (!wb_reserve_routes(e, e->route_count + 1))
        {
            e->stopped = true;
            goto done;
        }
        e->routes[e->route_count++] =
            (struct wb_route){.prefix = d->prefix, .metric = WB_INFINITY, .unreachable = true};
    }
    sort_routes(e);
    for (size_t i = 0; i < e->route_count; i++)
    {
        struct wb_route *r = &e->routes[i], *was = NULL;
        for (size_t j = 0; j < count; j++)
            if (wb_prefix_equal(&old[j].prefix, &r->prefix))
            {
                was = &old[j];
                break;
            }
        if (!was || was->router != r->router || was->unreachable != r->unreachable)
            trigger(e, true);
        else if (was->metric != r->metric || was->seqno != r->seqno)
            trigger(e, false);
    }
    for (size_t i = 0; i < e->requests_capacity; i++)
    {
        struct wb_request_state *q = &e->requests[i];
        if (!q->used)
            continue;
        struct wb_route *r = route_for(e, &q->message.prefix);
        if (r && !r->unreachable &&
            (r->router != q->message.router || at_least(r->seqno, q->message.seqno)))
        {
            if (q->from)
                advertise(e, q->from, &q->message.prefix, true);
            q->used = false;
        }
    }
done:
    /* Reuse the actual-sized selection snapshot on the next linked event.
     * collect releases/shrinks it after disconnection/topology contraction.
     * This remains separate from before: one packet may select routes more
     * than once while before pins the complete transaction's original table. */
    if (e->stopped)
        wb_free_scratch(e);
}
static void update(struct wb_engine *e, struct wb_link_state *l, const struct wb_message *m)
{
    struct wb_candidate *r = NULL, *free_slot = NULL;
    for (size_t i = 0; i < e->candidates_capacity; i++)
    {
        struct wb_candidate *c = &e->candidates[i];
        if (!c->used)
        {
            if (!free_slot)
                free_slot = c;
            continue;
        }
        if (c->route.link != l->config.id)
            continue;
        if (m->wildcard)
            c->advertised = WB_INFINITY;
        else if (wb_prefix_equal(&c->route.prefix, &m->prefix))
            r = c;
    }
    if (m->wildcard)
        return;
    if (m->metric == WB_INFINITY)
    {
        if (r)
            r->advertised = WB_INFINITY;
        return;
    }
    struct wb_candidate incoming = {
        .route = {.prefix = m->prefix, .router = m->router, .seqno = m->seqno}};
    if (!routable(&m->prefix) || !allowed(e, &incoming) || m->router == e->config.router ||
        (m->via6 && !e->config.ipv4_via_ipv6) ||
        (m->address_family == 6 && memcmp(m->address, l->config.peer, 16)))
    {
        e->counters.rejected++;
        return;
    }
    if (!source_for(e, &m->prefix, m->router))
    {
        bool space = false;
        for (size_t i = 0; i < e->sources_capacity; i++)
            space |= !e->sources[i].used;
        if (!space && e->sources_capacity >= WB_SOURCES)
        {
            e->counters.rejected++;
            return;
        }
    }
    if (!r)
    {
        if (!prefix_admitted(e, &m->prefix) && admission_count(e) >= WB_ROUTES)
        {
            e->counters.rejected++;
            return;
        }
        if (!free_slot)
        {
            size_t slot = e->candidates_capacity;
            if (wb_reserve_candidates(e, slot + 1))
                free_slot = &e->candidates[slot];
        }
        if (!free_slot)
        {
            e->counters.rejected++;
            return;
        }
        r = free_slot;
        *r = (struct wb_candidate){.used = true};
    }
    if (r->route.router && r->route.router != m->router)
        trigger(e, true);
    r->route = incoming.route;
    r->route.link = l->config.id;
    r->route.next_family = m->address_family;
    memcpy(r->route.next_hop, m->address, 16);
    r->advertised = m->metric;
    r->interval_ms = (uint32_t)m->interval * 10;
    r->expires = e->now + hold(r->interval_ms);
    r->refresh_requested = false;
    if (!feasible(e, r))
    {
        struct wb_source *s = source_for(e, &m->prefix, m->router);
        struct wb_route *selected = route_for(e, &m->prefix);
        if (s && (!selected || selected->unreachable || selected->link == l->config.id ||
                  metric(e, r) < selected->metric))
        {
            uint64_t target = l->config.id;
            request(e, &m->prefix, m->router, (uint16_t)(s->seqno + 1), &target, 1, 0, 64);
        }
    }
}
static void seq_request(struct wb_engine *e, uint64_t from, const struct wb_message *m)
{
    struct wb_route *r = route_for(e, &m->prefix);
    if (r && !r->unreachable)
    {
        if (r->router != m->router || at_least(r->seqno, m->seqno))
        {
            advertise(e, from, &m->prefix, true);
            return;
        }
        if (r->local)
        {
            e->seqno++;
            select_routes(e);
            advertise(e, from, &m->prefix, true);
            return;
        }
    }
    if (m->router == e->config.router || m->hops < 2)
        return;
    bool advertised = false;
    for (size_t i = 0; i < e->sources_capacity; i++)
        advertised |= e->sources[i].used && wb_prefix_equal(&e->sources[i].prefix, &m->prefix);
    if (!advertised)
        return;
    struct wb_candidate *best = NULL;
    for (size_t i = 0; i < e->candidates_capacity; i++)
    {
        struct wb_candidate *c = &e->candidates[i];
        if (!c->used || !wb_prefix_equal(&c->route.prefix, &m->prefix) || c->route.link == from ||
            metric(e, c) == WB_INFINITY)
            continue;
        if (!best || (feasible(e, c) && !feasible(e, best)) ||
            (feasible(e, c) == feasible(e, best) &&
             (metric(e, c) < metric(e, best) ||
              (metric(e, c) == metric(e, best) && c->route.link < best->route.link))))
            best = c;
    }
    if (best)
        request(e, &m->prefix, m->router, m->seqno, &best->route.link, 1, from,
                (uint8_t)(m->hops - 1));
}
struct receive_context
{
    struct wb_engine *engine;
    struct wb_link_state *link;
};
static void receive_message(void *context, const struct wb_message *m)
{
    struct receive_context *ctx = context;
    struct wb_engine *e = ctx->engine;
    struct wb_link_state *l = ctx->link;
    if (e->stopped)
        return;
    if(e->config.local_only && m->type==WB_SEQ_REQUEST && m->router!=e->config.router)return;
    switch (m->type)
    {
    case WB_HELLO:
    {
        unsigned i = m->unicast ? 1 : 0;
        if (!l->hello_seen[i] || l->hello_expires[i] <= e->now || newer(m->seqno, l->hello_rx[i]))
        {
            l->hello_rx[i] = m->seqno;
            l->hello_seen[i] = true;
            if (m->interval)
                l->hello_expires[i] = e->now + hold((uint64_t)m->interval * 10);
        }
        break;
    }
    case WB_IHU:
        if (!m->address_family ||
            (m->address_family == 6 && !memcmp(m->address, l->config.local, 16)) ||
            (m->address_family == 4 && !memcmp(m->address, l->config.ipv4, 4)))
        {
            l->tx = m->metric;
            l->ihu_expires = e->now + hold((uint64_t)m->interval * 10);
        }
        break;
    case WB_ACK_REQUEST:
    {
        struct wb_message ack = {.type = WB_ACK, .opaque = m->opaque};
        queue(e, l->config.id, &ack);
        break;
    }
    case WB_UPDATE:
        if(e->config.local_only)break;
        update(e, l, m);
        break;
    case WB_REQUEST:
        select_routes(e);
        if (m->wildcard)
        {
            if (!l->dumped || e->now - l->last_dump >= hello_ms(e, l))
            {
                dump(e, l->config.id, true);
                l->last_dump = e->now;
                l->dumped = true;
            }
        }
        else
            advertise(e, l->config.id, &m->prefix, true);
        break;
    case WB_SEQ_REQUEST:
        select_routes(e);
        seq_request(e, l->config.id, m);
        break;
    default:
        break;
    }
}
static void expire(struct wb_engine *e)
{
    for (size_t i = 0; i < e->candidates_capacity; i++)
    {
        struct wb_candidate *c = &e->candidates[i];
        if (!c->used || c->expires > e->now)
            continue;
        if (c->advertised == WB_INFINITY)
            c->used = false;
        else
        {
            c->advertised = WB_INFINITY;
            c->expires = e->now + hold(c->interval_ms);
        }
    }
    for (size_t i = 0; i < e->sources_capacity; i++)
        if (e->sources[i].used && e->sources[i].expires <= e->now)
            e->sources[i].used = false;
    for (size_t i = 0; i < e->requests_capacity; i++)
        if (e->requests[i].used && e->requests[i].expires <= e->now)
            e->requests[i].used = false;
}
static void timers(struct wb_engine *e)
{
    for (size_t i = 0; i < e->links_capacity; i++)
    {
        struct wb_link_state *l = &e->links[i];
        if (!l->config.id)
            continue;
        uint32_t hello = hello_ms(e, l);
        uint64_t id = l->config.id;
        if (l->next_hello <= e->now)
        {
            struct wb_message m = {
                .type = WB_HELLO, .seqno = l->hello_seq++, .interval = (uint16_t)(hello / 10)};
            queue(e, id, &m);
            l->next_hello = e->now + hello - jitter(e, hello / 8);
        }
        if (l->next_ihu <= e->now)
        {
            uint16_t rx = l->config.cost;
            if (l->hello_expires[0] <= e->now && l->hello_expires[1] <= e->now)
                rx = WB_INFINITY;
            struct wb_message m = {
                .type = WB_IHU, .metric = rx, .interval = (uint16_t)(hello * 2 / 10)};
            queue(e, id, &m);
            l->next_ihu = e->now + hello * 2 - jitter(e, hello / 8);
        }
        if (l->next_update <= e->now)
        {
            dump(e, id, false);
            l->next_update = e->now + e->config.update_ms - jitter(e, e->config.update_ms / 8);
        }
    }
    if (e->trigger && e->trigger_at <= e->now)
    {
        for (size_t i = 0; i < e->links_capacity; i++)
            if (e->links[i].config.id)
                dump(e, e->links[i].config.id, false);
        if (e->repeats)
        {
            e->repeats--;
            e->trigger_at = e->now + 100 + jitter(e, 50);
        }
        else
            e->trigger = false;
    }
    for (size_t i = 0; i < e->requests_capacity; i++)
    {
        struct wb_request_state *q = &e->requests[i];
        if (q->used && q->remaining && q->next <= e->now)
        {
            for (unsigned j = 0; j < q->target_count; j++)
                queue(e, q->targets[j], &q->message);
            q->remaining--;
            q->next = e->now + 1000;
        }
    }
    for (size_t i = 0; i < e->candidates_capacity; i++)
    {
        struct wb_candidate *c = &e->candidates[i];
        if (!c->used)
            continue;
        struct wb_route *r = route_for(e, &c->route.prefix);
        if (r && r->link == c->route.link && !c->refresh_requested &&
            c->advertised != WB_INFINITY && c->expires - e->now <= c->interval_ms)
        {
            struct wb_message m = {.type = WB_REQUEST, .prefix = c->route.prefix};
            queue(e, c->route.link, &m);
            c->refresh_requested = true;
        }
    }
}
static int begin(struct wb_engine *e, uint64_t now)
{
    if (e->stopped)
        return WB_STOPPED;
    if (e->pending || e->message_cursor < e->message_count)
        return WB_BUSY;
    if (now < e->now || now > UINT64_MAX - 172800000)
        return WB_INVALID;
    if (!wb_reserve_before(e, e->route_count))
        return WB_LIMIT;
    e->before_count = e->route_count;
    if (e->route_count)
        memcpy(e->before, e->routes, e->route_count * sizeof e->routes[0]);
    wb_free_messages(e);
    e->message_count = e->message_cursor = 0;
    e->ready = false;
    e->now = now;
    expire(e);
    return WB_OK;
}
static int finish(struct wb_engine *e)
{
    select_routes(e);
    timers(e);
    if (e->stopped)
    {
        wb_free_before(e);
        return WB_STOPPED;
    }
    bool changed = e->before_count != e->route_count;
    for (size_t i = 0; !changed && i < e->route_count; i++)
        changed = !route_equal(&e->before[i], &e->routes[i]);
    e->before_count = 0;
    wb_collect(e);
    if (changed)
    {
        e->pending = ++e->revision;
        return WB_PENDING;
    }
    e->ready = true;
    return WB_OK;
}
int wb_init(struct wb_engine *e, const struct wb_config *config)
{
    if (!e || !config || !config->router || config->router == UINT64_MAX ||
        (!!config->allocate != !!config->deallocate))
        return WB_INVALID;
    struct wb_config c = *config;
    if (!c.hello_ms)
        c.hello_ms = 4000;
    if (!c.update_ms)
        c.update_ms = 16000;
    if (!c.source_ms)
        c.source_ms = 180000;
    if (c.hello_ms < 100 || c.hello_ms > 327670 || c.hello_ms % 10 || c.update_ms < 100 ||
        c.update_ms > 655340 || c.update_ms % 10 || c.source_ms < 180000 ||
        c.source_ms < hold(c.update_ms) || c.source_ms > 86400000)
        return WB_INVALID;
    wb_deinit(e);
    e->config = c;
    e->seqno = c.seqno;
    e->rng = c.seed ? c.seed : c.router;
    e->ready = true;
    return WB_OK;
}
int wb_tick(struct wb_engine *e, uint64_t now)
{
    int r = begin(e, now);
    return r ? r : finish(e);
}
int wb_add_link(struct wb_engine *e, uint64_t now, const struct wb_link *config)
{
    if (!config || !config->id || config->id <= e->last_link || !config->cost ||
        config->max_packet < 512 || config->max_packet > WB_PACKET_MAX ||
        (config->hello_ms &&
         (config->hello_ms < 100 || config->hello_ms > 327670 || config->hello_ms % 10)) ||
        config->local[0] != 0xfe || (config->local[1] & 0xc0) != 0x80 || config->peer[0] != 0xfe ||
        (config->peer[1] & 0xc0) != 0x80 || !memcmp(config->local, config->peer, 16))
        return WB_INVALID;
    struct wb_link_state *l = NULL;
    for (size_t i = 0; i < e->links_capacity; i++)
        if (!e->links[i].config.id)
        {
            l = &e->links[i];
            break;
        }
    if (!l)
    {
        size_t slot = e->links_capacity;
        if (wb_reserve_links(e, slot + 1))
            l = &e->links[slot];
    }
    if (!l)
        return WB_LIMIT;
    int r = begin(e, now);
    if (r)
        return r;
    *l = (struct wb_link_state){.config = *config, .tx = WB_INFINITY};
    e->last_link = config->id;
    struct wb_message m = {.type = WB_REQUEST, .wildcard = true};
    queue(e, config->id, &m);
    return finish(e);
}
int wb_remove_link(struct wb_engine *e, uint64_t now, uint64_t id)
{
    int r = begin(e, now);
    if (r)
        return r;
    struct wb_link_state *l = link_for(e, id);
    if (l)
        memset(l, 0, sizeof *l);
    for (size_t i = 0; i < e->candidates_capacity; i++)
        if (e->candidates[i].used && e->candidates[i].route.link == id)
        {
            e->candidates[i].advertised = WB_INFINITY;
            e->candidates[i].expires = e->now + hold(e->config.update_ms);
        }
    return finish(e);
}
int wb_set_cost(struct wb_engine *e, uint64_t now, uint64_t id, uint16_t c)
{
    if (!c)
        return WB_INVALID;
    int r = begin(e, now);
    if (r)
        return r;
    struct wb_link_state *l = link_for(e, id);
    if (l)
        l->config.cost = c;
    return finish(e);
}
int wb_originate(struct wb_engine *e, uint64_t now, const struct wb_prefix *p, uint16_t m)
{
    if (!p || !routable(p) || m == WB_INFINITY)
        return WB_INVALID;
    struct wb_local *local = local_for(e, p);
    if (!local)
    {
        if (!prefix_admitted(e, p) && admission_count(e) >= WB_ROUTES)
            return WB_LIMIT;
        for (size_t i = 0; i < e->local_capacity; i++)
            if (!e->local[i].used)
            {
                local = &e->local[i];
                break;
            }
        if (!local)
        {
            size_t slot = e->local_capacity;
            if (wb_reserve_local(e, slot + 1))
                local = &e->local[slot];
        }
        if (!local)
            return WB_LIMIT;
    }
    /* Bound feasibility history. Its allocation is deferred until export;
     * advertise() never emits a route without recording that history. */
    if (!source_for(e, p, e->config.router))
    {
        bool space = false;
        for (size_t i = 0; i < e->sources_capacity; i++)
            space |= !e->sources[i].used;
        if (!space && e->sources_capacity >= WB_SOURCES)
            return WB_LIMIT;
    }
    int r = begin(e, now);
    if (r)
        return r;
    *local = (struct wb_local){.used = true, .prefix = *p, .metric = m};
    for (size_t i = 0; i < e->drops_capacity; i++)
        if (e->drops[i].used && wb_prefix_equal(&e->drops[i].prefix, p))
            e->drops[i].used = false;
    return finish(e);
}
int wb_withdraw(struct wb_engine *e, uint64_t now, const struct wb_prefix *p)
{
    if (!p || !wb_prefix_valid(p))
        return WB_INVALID;
    int r = begin(e, now);
    if (r)
        return r;
    struct wb_local *l = local_for(e, p);
    if (l)
        l->used = false;
    return finish(e);
}
int wb_receive(struct wb_engine *e, uint64_t now, uint64_t id, const void *data, size_t size)
{
    int r = begin(e, now);
    if (r)
        return r;
    struct wb_link_state *l = link_for(e, id);
    if (!l)
        return finish(e);
    e->counters.received++;
    struct receive_context ctx = {.engine = e, .link = l};
    if (size > l->config.max_packet || wb_decode(data, size, l->config.peer, receive_message, &ctx))
        e->counters.malformed++;
    return finish(e);
}
int wb_commit(struct wb_engine *e, uint64_t revision, bool success)
{
    if (e->stopped)
        return WB_STOPPED;
    if (!revision || revision != e->pending)
        return WB_INVALID;
    e->pending = 0;
    if (!success)
    {
        e->stopped = true;
        e->message_count = e->message_cursor = 0;
        wb_free_messages(e);
        return WB_STOPPED;
    }
    e->ready = true;
    return WB_OK;
}
int wb_next_packet(struct wb_engine *e, uint64_t *id, uint8_t *out, size_t cap)
{
    if (e->stopped)
        return WB_STOPPED;
    if (e->pending || !e->ready || !out || !id)
        return WB_BUSY;
    if (e->message_cursor == e->message_count)
        return 0;
    /* Queue is chronological; no reordering or packet-local context leaks. */
    uint64_t link = e->messages[e->message_cursor].link;
    struct wb_link_state *l = link_for(e, link);
    if (!l)
        return WB_INVALID;
    size_t max = l->config.max_packet;
    if (cap < max)
        return WB_INVALID;
    size_t n = 4;
    out[0] = 42;
    out[1] = 2;
    while (e->message_cursor < e->message_count && e->messages[e->message_cursor].link == link)
    {
        uint8_t message[64];
        size_t size = wb_encode(&e->messages[e->message_cursor].message, message, sizeof message);
        if (!size || size > max - 4)
        {
            e->stopped = true;
            return WB_STOPPED;
        }
        if (n + size > max)
            break;
        memcpy(out + n, message, size);
        n += size;
        e->message_cursor++;
    }
    out[2] = (uint8_t)((n - 4) >> 8);
    out[3] = (uint8_t)(n - 4);
    *id = link;
    e->counters.sent++;
    if (e->message_cursor == e->message_count)
    {
        wb_free_messages(e);
        e->message_cursor = e->message_count = 0;
    }
    return (int)n;
}
uint64_t wb_next_deadline(const struct wb_engine *e)
{
    if (e->stopped || e->pending)
        return UINT64_MAX;
    uint64_t next = UINT64_MAX;
#define DEADLINE(v)                                                                                \
    do                                                                                             \
    {                                                                                              \
        uint64_t d_ = (v);                                                                         \
        if (d_ > e->now && d_ < next)                                                              \
            next = d_;                                                                             \
    } while (0)
    for (size_t i = 0; i < e->links_capacity; i++)
        if (e->links[i].config.id)
        {
            const struct wb_link_state *l = &e->links[i];
            DEADLINE(l->next_hello);
            DEADLINE(l->next_ihu);
            DEADLINE(l->next_update);
            DEADLINE(l->ihu_expires);
            DEADLINE(l->hello_expires[0]);
            DEADLINE(l->hello_expires[1]);
        }
    for (size_t i = 0; i < e->candidates_capacity; i++)
        if (e->candidates[i].used)
        {
            DEADLINE(e->candidates[i].expires);
            if (!e->candidates[i].refresh_requested &&
                e->candidates[i].expires >= e->candidates[i].interval_ms)
                DEADLINE(e->candidates[i].expires - e->candidates[i].interval_ms);
        }
    for (size_t i = 0; i < e->sources_capacity; i++)
        if (e->sources[i].used)
            DEADLINE(e->sources[i].expires);
    for (size_t i = 0; i < e->drops_capacity; i++)
        if (e->drops[i].used)
            DEADLINE(e->drops[i].expires);
    for (size_t i = 0; i < e->requests_capacity; i++)
        if (e->requests[i].used)
        {
            DEADLINE(e->requests[i].expires);
            if (e->requests[i].remaining)
                DEADLINE(e->requests[i].next);
        }
    if (e->trigger)
    {
        if (e->trigger_at <= e->now)
            return e->now;
        DEADLINE(e->trigger_at);
    }
#undef DEADLINE
    return next;
}
const struct wb_route *wb_lookup(const struct wb_engine *e, const struct wb_prefix *host)
{
    if (!host || !wb_prefix_valid(host))
        return NULL;
    const struct wb_route *best = NULL;
    for (size_t i = 0; i < e->route_count; i++)
    {
        const struct wb_route *r = &e->routes[i];
        if (r->prefix.family != host->family || r->prefix.bits > host->bits)
            continue;
        struct wb_prefix masked = *host;
        masked.bits = r->prefix.bits;
        wb_prefix_mask(&masked);
        if (wb_prefix_equal(&masked, &r->prefix) && (!best || r->prefix.bits > best->prefix.bits))
            best = r;
    }
    return best; /* Unreachable entries MUST override a covering default. */
}
