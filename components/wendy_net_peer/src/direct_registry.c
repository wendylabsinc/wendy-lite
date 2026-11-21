#include "wendy_net_direct_registry.h"
#include "wendy_net_alloc.h"
#include <limits.h>
#include <string.h>

static size_t aligned(size_t n)
{
    size_t a = _Alignof(max_align_t);
    return (n + a - 1) / a * a;
}
static void *take(uint8_t **p, size_t n)
{
    void *out = *p;
    *p += aligned(n);
    return out;
}
static bool nonzero(const uint8_t *p, size_t n)
{
    uint8_t v = 0;
    while (n--)
        v |= *p++;
    return v != 0;
}
static bool same_key(const struct wn_direct_peer_key *a, const struct wn_direct_peer_key *b)
{
    return !memcmp(a, b, sizeof *a);
}
static void reap(struct wn_direct_registry *r)
{
    struct wn_direct_peer **at = &r->peers;
    while (*at) {
        struct wn_direct_peer *p = *at;
        if (p->session.closed && !p->pins) {
            *at = p->next;
            r->count--;
            wendy_net_free(p);
        } else
            at = &p->next;
    }
}
int wn_direct_registry_init(struct wn_direct_registry *r, unsigned limit, bool small)
{
    if (!r || !limit)
        return WN_DIRECT_BOUNDS;
    *r = (struct wn_direct_registry){.limit = limit,
                                     .next_serial = 1,
                                     .slots = small ? 4 : 16,
                                     .tx_bytes = small ? 8192 : 65536,
                                     .rx_bytes = small ? 8192 : 65536,
                                     .window = small ? 4096 : 32768,
                                     .initial = small ? 1024 : 4096};
    return 0;
}
static struct wn_direct_peer *allocate(struct wn_direct_registry *r, size_t policy_bytes)
{
    if (!r->slots || r->slots > 32767 || !r->tx_bytes || !r->rx_bytes || r->tx_bytes > 1048576 ||
        r->rx_bytes > 1048576 || r->tx_bytes % WN_DIRECT_CHUNK || r->rx_bytes % WN_DIRECT_CHUNK)
        return NULL;
    if ((!r->datagram_slots) != (!r->datagram_max) || r->datagram_slots > (uint32_t)2 * r->slots)
        return NULL;
    size_t packet_bytes = (size_t)3 * r->datagram_max;
    if (packet_bytes * r->datagram_slots > 1048576)
        return NULL;
    size_t n = (size_t)2 * r->slots, tx = r->tx_bytes / WN_DIRECT_CHUNK,
           rx = r->rx_bytes / WN_DIRECT_CHUNK;
    size_t bytes = sizeof(struct wn_direct_peer) + aligned(n * sizeof(struct wn_direct_flow)) +
                   4 * aligned(n * sizeof(struct wn_direct_recovery_record)) +
                   aligned(2 * n * sizeof(struct wn_direct_recovery_step)) +
                   aligned(n * sizeof(uint32_t)) + aligned(tx * sizeof(struct wn_direct_slot)) +
                   aligned(rx * sizeof(struct wn_direct_slot)) + aligned(policy_bytes) +
                   aligned((size_t)r->datagram_slots * sizeof(struct wn_direct_packet));
    struct wn_direct_peer *p = wendy_net_calloc(1, bytes);
    if (!p)
        return NULL;
    p->allocation = bytes;
    uint8_t *cursor = (uint8_t *)p->storage;
    struct wn_direct_flow *flows = take(&cursor, n * sizeof *flows);
    struct wn_direct_recovery_record *expected = take(&cursor, n * sizeof *expected);
    p->session.cfg.local = take(&cursor, n * sizeof *expected);
    p->session.cfg.remote = take(&cursor, n * sizeof *expected);
    p->session.cfg.scratch = take(&cursor, n * sizeof *expected);
    p->session.cfg.plan = take(&cursor, 2 * n * sizeof(struct wn_direct_recovery_step));
    uint32_t *retired = take(&cursor, n * sizeof *retired);
    struct wn_direct_slot *tc = take(&cursor, tx * sizeof *tc),
                          *rc = take(&cursor, rx * sizeof *rc);
    if (policy_bytes)
        p->session.cfg.check_arg = take(&cursor, policy_bytes);
    if (r->datagram_slots) {
        p->packets = take(&cursor, (size_t)r->datagram_slots * sizeof *p->packets);
        p->packet_count = r->datagram_slots;
        for (unsigned i = 0; i < p->packet_count; i++)
            if (wn_direct_packet_init_dynamic(&p->packets[i], r->datagram_max, wendy_net_malloc,
                                              wendy_net_free)) {
                wendy_net_free(p);
                return NULL;
            }
    }
    if (wn_direct_pool_init_dynamic(&p->tx, tc, (uint32_t)tx, wendy_net_malloc, wendy_net_free) ||
        wn_direct_pool_init_dynamic(&p->rx, rc, (uint32_t)rx, wendy_net_malloc, wendy_net_free)) {
        wendy_net_free(p);
        return NULL;
    }
    // Role is installed by acquire before any namespace can admit a flow.
    if (wn_direct_flows_init(&p->flows, 0, r->slots, flows, expected, retired, &p->tx,
                             &p->rx, r->window, r->initial)) {
        wendy_net_free(p);
        return NULL;
    }
    return p;
}
int wn_direct_registry_acquire(struct wn_direct_registry *r, const struct wn_direct_peer_key *key,
                               const struct wn_direct_session_config *cfg, size_t policy_bytes,
                               int64_t now, struct wn_direct_peer **out)
{
    if (!out)
        return WN_DIRECT_BOUNDS;
    *out = NULL;
    if (!r || r->closed || !key || !cfg || !nonzero(key->principal, 32) ||
        !nonzero(key->instance, 16) || cfg->role > 1 || cfg->deadline <= now || now < 0 ||
        policy_bytes > WN_DIRECT_POLICY_MAX || (policy_bytes && (!cfg->check_arg || !cfg->check)))
        return WN_DIRECT_BOUNDS;
    reap(r);
    for (struct wn_direct_peer *p = r->peers; p; p = p->next)
        if (same_key(&p->key, key)) {
            if (p->session.closed)
                return WN_DIRECT_RETIRED;
            if (memcmp(p->session.binding.identity_digest, cfg->identity_digest, 32) ||
                p->session.binding.role != cfg->role || p->session.cfg.selected != cfg->selected) {
                wn_direct_session_close(&p->session);
                reap(r);
                return WN_DIRECT_RETIRED;
            }
            if (p->pins == UINT_MAX)
                return WN_DIRECT_CAPACITY;
            if (cfg->deadline < p->session.security_deadline)
                p->session.security_deadline = cfg->deadline;
            // Keep original policy and authority; reconnect must not replace them with
            // contexts whose lifetime ends with the new carrier.
            if (!p->session.attached)
                p->carrier_expired = false;
            p->pins++;
            *out = p;
            return 0;
        }
    if (r->count >= r->limit || !r->next_serial)
        return WN_DIRECT_CAPACITY;
    struct wn_direct_peer *p = allocate(r, policy_bytes);
    if (!p)
        return WN_DIRECT_CAPACITY;
    struct wn_direct_session_config owned = *cfg;
    owned.flows = &p->flows;
    owned.local = p->session.cfg.local;
    owned.remote = p->session.cfg.remote;
    owned.scratch = p->session.cfg.scratch;
    owned.plan = p->session.cfg.plan;
    if (policy_bytes) {
        owned.check_arg = p->session.cfg.check_arg;
        memcpy(owned.check_arg, cfg->check_arg, policy_bytes);
    }
    struct wn_direct_flows *f = &p->flows;
    if (cfg->role &&
        wn_direct_flows_init(f, 1, r->slots, f->flows, f->expected, f->retired,
                             &p->tx, &p->rx, r->window, r->initial)) {
        wendy_net_free(p);
        return WN_DIRECT_BOUNDS;
    }
    if (p->packet_count && wn_direct_flows_enable_datagrams(f, p->packets, p->packet_count)) {
        wendy_net_free(p);
        return WN_DIRECT_BOUNDS;
    }
    if (wn_direct_flows_set_datagram_limit(f, r->datagram_max)) {
        wendy_net_free(p);
        return WN_DIRECT_BOUNDS;
    }
    if (wn_direct_session_init(&p->session, &owned, now)) {
        wendy_net_free(p);
        return WN_DIRECT_BOUNDS;
    }
    p->key = *key;
    p->serial = r->next_serial++;
    p->pins = 1;
    p->next = r->peers;
    r->peers = p;
    r->count++;
    *out = p;
    return 0;
}
int wn_direct_registry_pin_promoted(struct wn_direct_registry *r,
                                    const struct wn_direct_peer_key *key,
                                    const struct wn_direct_session_config *cfg,
                                    uint64_t expected_serial, int64_t now,
                                    struct wn_direct_peer **out)
{
    if (!out)
        return WN_DIRECT_BOUNDS;
    *out = NULL;
    if (!r || r->closed || !key || !cfg || now < 0 || cfg->deadline <= now || cfg->role > 1 ||
        !nonzero(key->principal, 32) || !nonzero(key->instance, 16))
        return WN_DIRECT_BOUNDS;
    for (struct wn_direct_peer *p = r->peers; p; p = p->next)
        if (same_key(&p->key, key)) {
            struct wn_direct_session *s = &p->session;
            if (s->closed || (expected_serial && p->serial != expected_serial) ||
                memcmp(s->binding.identity_digest, cfg->identity_digest, 32) ||
                s->binding.role != cfg->role || s->cfg.selected != cfg->selected)
                return WN_DIRECT_RETIRED;
            if (!nonzero(s->binding.session_id, 32) || (!s->binding.role && !s->peer_known))
                return WN_DIRECT_CAPACITY;
            int64_t deadline = s->security_deadline;
            if (cfg->deadline < deadline)
                deadline = cfg->deadline;
            if ((s->cfg.check && s->cfg.check(s->cfg.check_arg, now, &deadline)) ||
                now >= deadline || (s->outage_deadline && now >= s->outage_deadline) ||
                (s->promotion_deadline && now >= s->promotion_deadline))
                return WN_DIRECT_RETIRED;
            if (p->pins == UINT_MAX)
                return WN_DIRECT_CAPACITY;
            s->security_deadline = deadline;
            p->pins++;
            *out = p;
            return 0;
        }
    return WN_DIRECT_RETIRED;
}
void wn_direct_registry_release(struct wn_direct_registry *r, struct wn_direct_peer *p)
{
    if (!r || !p)
        return;
    for (struct wn_direct_peer *at = r->peers; at; at = at->next)
        if (at == p) {
            if (at->pins)
                at->pins--;
            reap(r);
            return;
        }
}
struct wn_direct_peer *wn_direct_registry_lookup(struct wn_direct_registry *r, uint64_t serial)
{
    if (!r || r->closed || !serial)
        return NULL;
    for (struct wn_direct_peer *p = r->peers; p; p = p->next)
        if (p->serial == serial)
            return p->session.closed ? NULL : p;
    return NULL;
}
int wn_direct_registry_tick(struct wn_direct_registry *r, int64_t now)
{
    if (!r)
        return WN_DIRECT_BOUNDS;
    int progress = 0;
    for (struct wn_direct_peer *p = r->peers; p; p = p->next)
        if (!p->session.closed) {
            int n = wn_direct_session_tick(&p->session, now);
            if (n == WN_DIRECT_CARRIER_LOST)
                p->carrier_expired = true;
            if (n)
                progress = 1;
        }
    reap(r);
    return progress;
}
bool wn_direct_registry_close(struct wn_direct_registry *r)
{
    if (!r)
        return true;
    r->closed = true;
    for (struct wn_direct_peer *p = r->peers; p; p = p->next)
        wn_direct_session_close(&p->session);
    reap(r);
    return !r->count;
}

bool wn_direct_registry_has_flows(const struct wn_direct_registry *r)
{
    if (!r || r->closed)
        return false;
    for (const struct wn_direct_peer *p = r->peers; p; p = p->next)
        if (!p->session.closed && p->flows.count)
            return true;
    return false;
}
