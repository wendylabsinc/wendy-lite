/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_directory.h"
#include "wendy_net_service_protocol.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_crypto.h"
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#endif
#include <limits.h>
#include <psa/crypto.h>
#include <stdlib.h>
#include <string.h>

/* Hash all original optional/unknown body fields conservatively. Only the
 * four publication/sequence scalars may differ in a pure route refresh. Map
 * reordering clears continuity instead of inventing equivalence. */
int wn_route_continuity(const struct wn_doc *doc, unsigned body, uint8_t out[32])
{
    const struct wn_token *root = wn_doc_token(doc, body);
    if (!root || root->type != '{' || wendy_pki_crypto_init())
        return -1;
    static const uint8_t domain[] = "wendy-net/route-continuity/1";
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    int result = -1;
    size_t written = 0;
    if (psa_hash_setup(&op, PSA_ALG_SHA_256) != PSA_SUCCESS ||
        psa_hash_update(&op, domain, sizeof domain) != PSA_SUCCESS)
        goto done;
    for (unsigned key = body + 1; key < root->next;) {
        unsigned value = key + 1;
        const struct wn_token *k = wn_doc_token(doc, key), *v = wn_doc_token(doc, value);
        if (!k || !v)
            goto done;
        if (!wn_doc_equal(doc, key, wn_key_name("revision")) && !wn_doc_equal(doc, key, wn_key_name("Issued")) &&
            !wn_doc_equal(doc, key, wn_key_name("Expires"))) {
            if (psa_hash_update(&op, (const uint8_t *)doc->text + k->start, k->end - k->start) != PSA_SUCCESS)
                goto done;
            if (wn_doc_equal(doc, key, wn_key_name("route"))) {
                if (v->type != '{')
                    goto done;
                for (unsigned rk = value + 1; rk < v->next;) {
                    const struct wn_token *rkey = wn_doc_token(doc, rk), *rv = wn_doc_token(doc, rk + 1);
                    if (!rkey || !rv)
                        goto done;
                    if (!wn_doc_equal(doc, rk, wn_key_name("seqno")) &&
                        psa_hash_update(&op, (const uint8_t *)doc->text + rkey->start,
                                        rv->end - rkey->start) != PSA_SUCCESS)
                        goto done;
                    rk = rv->next;
                }
                static const uint8_t end[] = {0xff};
                if (psa_hash_update(&op, end, sizeof end) != PSA_SUCCESS)
                    goto done;
            } else if (psa_hash_update(&op, (const uint8_t *)doc->text + v->start,
                                       v->end - v->start) != PSA_SUCCESS)
                goto done;
        }
        key = v->next;
    }
    result = psa_hash_finish(&op, out, 32, &written) == PSA_SUCCESS && written == 32 ? 0 : -1;
done:
    psa_hash_abort(&op);
    return result;
}
static int number(const struct wn_doc *d, unsigned object, const char *name, uint64_t *value)
{
    return wn_doc_u64(d, wn_doc_member(d, object, name), value);
}
void wne_clear(struct wne_cache *c)
{
    while (c->entries) {
        struct wne_entry *e = c->entries;
        c->entries = e->next;
        wendy_net_free(e);
    }
    c->count = 0;
}
void wne_reap(struct wne_cache *c, int64_t now)
{
    for (struct wne_entry **at = &c->entries; *at;) {
        struct wne_entry *e = *at;
        if (e->deadline_us <= now) {
            *at = e->next;
            wendy_net_free(e);
            c->count--;
        } else
            at = &e->next;
    }
}
int wne_update(struct wne_cache *c, const struct wnd_manifest *m, const uint8_t hash[32],
               int64_t deadline, int64_t now)
{
    wne_reap(c, now);
    if (deadline <= now)
        return 1;
    struct wne_entry *e = c->entries;
    while (e && memcmp(e->device, m->device, 16))
        e = e->next;
    if (e) {
        if (m->revision < e->revision)
            return 1;
        if (m->revision == e->revision) {
            if (memcmp(e->body_hash, hash, 32))
                return 2;
            if (deadline < e->deadline_us)
                e->deadline_us = deadline;
            return 0;
        }
    } else {
        if (c->count == WNE_ENDPOINTS_MAX) {
            /* FIFO replacement reuses the oldest allocation, even when valid. */
            struct wne_entry **old = &c->entries;
            while ((*old)->next)
                old = &(*old)->next;
            e = *old;
            *old = NULL;
            c->count--;
        } else
            e = wendy_net_calloc(1, sizeof *e);
        if (!e)
            return 3;
        memset(e, 0, sizeof *e);
        e->next = c->entries;
        c->entries = e;
        c->count++;
    }
    memcpy(e->device, m->device, 16);
    memcpy(e->body_hash, hash, 32);
    e->revision = m->revision;
    e->deadline_us = deadline;
    e->app_port = m->tls_app_port;
    e->agent_port = m->agent_port;
    e->agent_mtls = m->agent_mtls;
    e->withdraw = m->withdraw;
    e->certificate_not_before = m->certificate_not_before;
    e->certificate_issuer_not_before = m->certificate_issuer_not_before;
    e->certificate_expires = m->certificate_expires;
    return 0;
}
bool wne_endpoint(const struct wne_cache *c, const uint8_t device[16], bool agent, int64_t now,
                  uint16_t *port)
{
    *port = 0;
    for (const struct wne_entry *e = c->entries; e; e = e->next)
        if (!memcmp(e->device, device, 16) && !e->withdraw && e->deadline_us > now) {
            *port = agent ? (e->agent_mtls ? e->agent_port : 0) : e->app_port;
            return *port != 0;
        }
    return false;
}
void wnd_forget_keyless(struct wnd_directory *d)
{
    for (struct wnd_entry **at = &d->entries; *at;) {
        struct wnd_entry *e = *at;
        if (!e->peer.spki_size && !e->key_pinned) {
            *at = e->next;
            #if WN_ROUTE_HANDOFF_ENABLED
            wendy_net_free(e->handoff);
#endif
            wendy_net_free(e);
            d->count--;
        } else
            at = &e->next;
    }
}
static struct wnd_entry *find(const struct wnd_directory *d, const uint8_t device[16])
{
    for (struct wnd_entry *e = d->entries; e; e = e->next)
        if (!memcmp(e->device, device, 16))
            return e;
    return NULL;
}
int wnd_init(struct wnd_directory *d, const char *tenant, const char *self)
{
    uint8_t uuid[16];
    if (!d || wn_uuid_parse(tenant, uuid) || wn_uuid_parse(self, uuid))
        return -1;
    *d = (struct wnd_directory){0};
    d->key_limit = WND_ORIGINS_MAX;
    memcpy(d->tenant, tenant, 37);
    memcpy(d->self, uuid, 16);
    wn_address(uuid, d->self_address);
    return 0;
}
void wnd_deinit(struct wnd_directory *d)
{
    while (d->entries) {
        struct wnd_entry *e = d->entries;
        d->entries = e->next;
        wendy_net_free((void *)e->peer.spki);
#if WN_ROUTE_HANDOFF_ENABLED
        wendy_net_free(e->handoff);
#endif
        wendy_net_free(e);
    }
    while (d->receipts) {
        struct wnd_receipt *r = d->receipts;
        d->receipts = r->next;
        wendy_net_free(r);
    }
    memset(d, 0, sizeof *d);
}
static struct wnd_receipt *receipt(const struct wnd_directory *d, const uint8_t device[16])
{
    for (struct wnd_receipt *r = d->receipts; r; r = r->next)
        if (!memcmp(r->device, device, 16))
            return r;
    return NULL;
}
const struct wnd_receipt *wnd_receipt_find(const struct wnd_directory *d, const uint8_t device[16],
                                          int64_t now)
{
    struct wnd_receipt *r = d && device && now >= 0 ? receipt(d, device) : NULL;
    return r && r->receipt_deadline_us > now ? r : NULL;
}
void wnd_expire(struct wnd_directory *d, int64_t now)
{
    if (!d || now < 0)
        return;
#if WN_ROUTE_HANDOFF_ENABLED
    for (struct wnd_entry *e = d->entries; e; e = e->next)
        if (e->handoff && e->handoff->has_prior && !wnrh_live(&e->handoff->prior, now))
            e->handoff->has_prior = false;
#endif
    for (struct wnd_entry *e = d->entries; e; e = e->next)
        if (e->manifest.revision && e->lease_deadline_us <= now) {
            memset(&e->manifest, 0, sizeof e->manifest);
            memset(e->body_hash, 0, sizeof e->body_hash);
            e->revision = 0;
            e->deadline_us = 0;
            e->pending_receipt = false;
#if WN_ROUTE_HANDOFF_ENABLED
            wendy_net_free(e->handoff);
            e->handoff = NULL;
#endif
        }
    for (struct wnd_receipt **at = &d->receipts; *at;)
        if ((*at)->receipt_deadline_us <= now) {
            struct wnd_receipt *r = *at;
            *at = r->next;
            wendy_net_free(r);
            d->receipt_count--;
        } else
            at = &(*at)->next;
}
int64_t wnd_next_deadline(const struct wnd_directory *d, int64_t now)
{
    int64_t next = INT64_MAX;
    if (!d)
        return next;
    for (const struct wnd_entry *e = d->entries; e; e = e->next)
        if (e->manifest.revision) {
            if (e->lease_deadline_us <= now)
                return now;
            if (e->lease_deadline_us < next)
                next = e->lease_deadline_us;
        }
#if WN_ROUTE_HANDOFF_ENABLED
    for (const struct wnd_entry *e = d->entries; e; e = e->next)
        if (e->handoff) {
            const struct wn_route_handoff *state = e->handoff;
            if (state->current_eligible && state->current.path_deadline_us < next)
                next = state->current.path_deadline_us <= now ? now : state->current.path_deadline_us;
            if (state->has_prior) {
                int64_t end = state->prior.deadline_us < state->prior.path_deadline_us ?
                                  state->prior.deadline_us : state->prior.path_deadline_us;
                if (end < next)
                    next = end <= now ? now : end;
            }
        }
#endif
    for (const struct wnd_receipt *r = d->receipts; r; r = r->next)
        if (r->receipt_deadline_us <= now)
            return now;
        else if (r->receipt_deadline_us < next)
            next = r->receipt_deadline_us;
    return next;
}
int wnd_key_limit(struct wnd_directory *d, unsigned limit)
{
    if (!d || !limit || limit > WND_ORIGINS_MAX)
        return -1;
    while (d->key_count > limit) {
        struct wnd_entry *evict = NULL;
        for (struct wnd_entry *e = d->entries; e; e = e->next)
            if (e->peer.spki_size && !e->key_pinned &&
                (!evict || e->key_serial < evict->key_serial))
                evict = e;
        if (!evict)
            return 3;
        wendy_net_free((void *)evict->peer.spki);
        evict->peer.spki = NULL;
        evict->peer.spki_size = 0;
        evict->peer.expires = 0;
        evict->peer.not_before = 0;
        evict->peer.signing_not_before = 0;
        evict->peer.issuer_not_before = 0;
        evict->key_serial = 0;
        evict->certificate_chain_until = 0;
        memset(evict->certificate_chain_hash, 0, 32);
        memset(evict->certificate_leaf_hash, 0, 32);
        d->key_count--;
    }
    d->key_limit = limit;
    return 0;
}
int wnd_key_pin(struct wnd_directory *d, const uint8_t device[16], bool pinned)
{
    struct wnd_entry *e = d && device ? find(d, device) : NULL;
    if (!e || !e->peer.spki_size)
        return 1;
    e->key_pinned = pinned;
    return 0;
}
static void drop_key(struct wnd_directory *d, struct wnd_entry *e)
{
    wendy_net_free((void *)e->peer.spki);
    e->peer.spki = NULL;
    e->peer.spki_size = 0;
    e->peer.expires = 0;
    e->peer.not_before = 0;
    e->peer.signing_not_before = 0;
    e->peer.issuer_not_before = 0;
    e->key_serial = 0;
    e->certificate_chain_until = 0;
    memset(e->certificate_chain_hash, 0, sizeof e->certificate_chain_hash);
    memset(e->certificate_leaf_hash, 0, sizeof e->certificate_leaf_hash);
    d->key_count--;
}
int wnd_identity(struct wnd_directory *d, const struct wendy_pki_mesh_peer *peer)
{
    uint8_t uuid[16], address[16];
    if (!d || !peer || wn_uuid_parse(peer->device, uuid) || !peer->spki_size ||
        peer->spki_size > sizeof peer->spki || peer->expires <= 0 ||
        peer->expires > INT64_MAX / 1000 ||
        (peer->not_before > 0 && peer->not_before > INT64_MAX / 1000) ||
        (peer->signing_not_before > 0 && peer->signing_not_before > INT64_MAX / 1000) ||
        (peer->issuer_not_before > 0 && peer->issuer_not_before > INT64_MAX / 1000))
        return -1;
    wn_address(uuid, address);
    if (!memcmp(d->self_address, address, 16))
        return -1;
    struct wnd_entry *e = find(d, uuid);
    bool changed = !e || e->peer.spki_size != peer->spki_size ||
        memcmp(e->peer.spki, peer->spki, peer->spki_size);
    if (changed) {
        bool adding = !e || !e->peer.spki_size;
        struct wnd_entry *victim = NULL, *evict = NULL;
        if (!e && d->count >= WND_ORIGINS_MAX) {
            for (struct wnd_entry *old = d->entries; old; old = old->next)
                if (!old->key_pinned && !old->manifest.revision &&
                    (!victim || old->key_serial < victim->key_serial))
                    victim = old;
            if (!victim)
                return 3;
        }
        unsigned replacing_key = victim && victim->peer.spki_size ? 1 : 0;
        if (adding && d->key_count - replacing_key >= d->key_limit) {
            for (struct wnd_entry *old = d->entries; old; old = old->next)
                if (old != victim && old->peer.spki_size && !old->key_pinned &&
                    (!evict || old->key_serial < evict->key_serial))
                    evict = old;
            if (!evict)
                return 3;
        }
        uint8_t *key = wendy_net_malloc(peer->spki_size);
        struct wnd_entry *fresh = !e ? wendy_net_calloc(1, sizeof *fresh) : NULL;
        if (!key || (!e && !fresh)) {
            wendy_net_free(key);
            wendy_net_free(fresh);
            return 3;
        }
        memcpy(key, peer->spki, peer->spki_size);
        /* All allocations are complete before any existing cache state changes.
         * Compact receipt ownership is independent of active/key slot reuse. */
        if (victim) {
            struct wnd_entry **at = &d->entries;
            while (*at != victim)
                at = &(*at)->next;
            *at = victim->next;
            if (victim->peer.spki_size)
                d->key_count--;
            wendy_net_free((void *)victim->peer.spki);
#if WN_ROUTE_HANDOFF_ENABLED
            wendy_net_free(victim->handoff);
#endif
            wendy_net_free(victim);
            d->count--;
        }
        if (evict)
            drop_key(d, evict);
        if (fresh) {
            e = fresh;
            memcpy(e->device, uuid, 16);
            memcpy(e->address, address, 16);
            e->next = d->entries;
            d->entries = e;
            d->count++;
        }
        wendy_net_free((void *)e->peer.spki);
        e->peer.spki = key;
        e->peer.spki_size = peer->spki_size;
        if (adding)
            d->key_count++;
        e->key_serial = ++d->key_serial;
        e->deadline_us = 0;
#if WN_ROUTE_HANDOFF_ENABLED
        if (e->handoff) {
            e->handoff->current_verified = false;
            e->handoff->current_eligible = false;
            e->handoff->has_prior = false;
        }
#else
        e->lease_deadline_us = 0;
#endif
        e->certificate_chain_until = 0;
    }
    memcpy(e->peer.device, peer->device, sizeof e->peer.device);
    e->peer.expires = peer->expires;
    e->peer.not_before = peer->not_before;
    e->peer.signing_not_before = peer->signing_not_before;
    e->peer.issuer_not_before = peer->issuer_not_before;
#if WN_ROUTE_HANDOFF_ENABLED
    /* The currently selected independently verified same-key leaf governs
     * CURRENT eligibility. Its dates never overwrite the original signer
     * provenance retained in state.current for a future HELD proof. */
    if (!changed && e->handoff) {
        e->manifest.certificate_not_before = peer->signing_not_before;
        e->manifest.certificate_issuer_not_before = peer->issuer_not_before;
        e->manifest.certificate_expires = peer->expires;
        if (!wnrh_window(&e->handoff->current, peer->signing_not_before, peer->expires)) {
            e->handoff->current_eligible = false;
            e->deadline_us = 0;
        }
        if (e->handoff->has_prior &&
            !wnrh_window(&e->handoff->prior, peer->signing_not_before, peer->expires))
            e->handoff->has_prior = false;
    }
#endif
    /* Actual signer NotBefore changes only after a signature under a new key. */
    return 0;
}
static int app_endpoints(const struct wn_doc *d, unsigned body, struct wnd_manifest *m)
{
    int endpoints = wn_doc_member(d, body, "appEndpoints");
    if (endpoints < 0 || d->storage[endpoints].type == 'n')
        return 0;
    if (d->storage[endpoints].type != '[')
        return -1;
    unsigned count = 0;
    for (unsigned i = endpoints + 1; i < d->storage[endpoints].next; i = d->storage[i].next) {
        uint64_t port;
        uint16_t *slot;
        char transport[65];
        if (++count > 16 || d->storage[i].type != '{' ||
            wn_doc_string(d, wn_doc_member(d, i, "transport"), transport, sizeof transport) <= 0)
            return -1;
        if (!strcmp(transport, "tls-v1"))
            slot = &m->tls_app_port;
        else if (!strcmp(transport, "quic-v1"))
            slot = &m->quic_app_port;
        else
            continue; /* Optional future endpoint owns its remaining schema. */
        if (number(d, i, "port", &port) || !port || port > 65535 || *slot)
            return -1;
        *slot = (uint16_t)port;
    }
    return 0;
}
static bool extension_name(const char *name)
{
    for (size_t i = 0; name[i]; i++) {
        unsigned char c = (unsigned char)name[i];
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
            continue;
        if (i && (c == '.' || c == '_' || c == '/' || c == '-'))
            continue;
        return false;
    }
    return *name != 0;
}
int wnd_manifest_read(const struct wn_doc *d, unsigned body, struct wnd_manifest *m)
{
    uint64_t version, issued, expires, port = 0, seq;
    char uuid[37], prefix[48];
    uint8_t actual[16], expected[16];
    if (!d || !m || !wn_doc_token(d, (int)body))
        return -1;
    memset(m, 0, sizeof *m);
    if (d->storage[body].type != '{' || number(d, body, "version", &version))
        return -1;
    if (version != 4)
        return WND_UNSUPPORTED;
    int route = wn_doc_member(d, body, "route"), withdraw = wn_doc_member(d, body, "withdraw"),
        name = wn_doc_member(d, body, "name"), agent = wn_doc_member(d, body, "agentTransport"),
        port_token = wn_doc_member(d, body, "agentPort");
    if (route < 0 || d->storage[route].type != '{' || number(d, body, "revision", &m->revision) ||
        !m->revision || number(d, body, "Issued", &issued) || !issued || issued > INT64_MAX ||
        number(d, body, "Expires", &expires) || expires > INT64_MAX || expires <= issued ||
        expires - issued > 900000 || (port_token >= 0 && wn_doc_u64(d, port_token, &port)) ||
        port > 65535 || wn_doc_string(d, wn_doc_member(d, body, "device"), uuid, sizeof uuid) < 0 ||
        wn_uuid_parse(uuid, m->device) || number(d, route, "routerId", &m->origin.router_id) ||
        !m->origin.router_id || m->origin.router_id == UINT64_MAX ||
        number(d, route, "seqno", &seq) || seq > 65535 ||
        wn_doc_string(d, wn_doc_member(d, route, "prefix"), prefix, sizeof prefix) < 0)
        return -1;
    size_t n = strlen(prefix);
    if (n < 5 || strcmp(prefix + n - 4, "/128"))
        return -1;
    prefix[n - 4] = 0;
    wn_address(m->device, expected);
    if (inet_pton(AF_INET6, prefix, actual) != 1 || memcmp(actual, expected, 16))
        return -1;
    if (name >= 0 &&
        (d->storage[name].type != '"' || d->storage[name].end - d->storage[name].start > 1532))
        return -1;
    if (withdraw >= 0) {
        char type = d->storage[withdraw].type;
        if (type != 't' && type != 'f')
            return -1;
        m->withdraw = type == 't';
    }
    if (!m->withdraw && !port)
        return -1;
    if (agent >= 0) {
        char transport[65];
        if (wn_doc_string(d, agent, transport, sizeof transport) < 0)
            return -1;
        /* Unknown agent transports are unavailable locally, never a fallback
         * to today's protocol and never a reason to discard the route. */
        m->agent_mtls = !strcmp(transport, "mtls-v1") && port;
        if (*transport && strcmp(transport, "mtls-v1"))
            port = 0; /* Do not expose an opaque protocol as a usable endpoint. */
    }
    m->agent_port = (uint16_t)port;
    int platform = wn_doc_member(d, body, "platform");
    if (platform >= 0) {
        char value[33];
        if (wn_doc_string(d, platform, value, sizeof value) < 0)
            return -1;
        m->platform_lite = !strcmp(value, "Lite");
    }
    int caps = wn_doc_member(d, body, "caps");
    if (caps >= 0) {
        if (d->storage[caps].type != '[')
            return -1;
        unsigned count = 0;
        for (unsigned i = (unsigned)caps + 1; i < d->storage[caps].next; i = d->storage[i].next) {
            char value[65];
            if (++count > 16 || wn_doc_string(d, (int)i, value, sizeof value) <= 0 ||
                !extension_name(value))
                return -1;
            for (unsigned j = (unsigned)caps + 1; j < i; j = d->storage[j].next)
                if (wn_doc_equal(d, (int)j, value))
                    return -1;
            if (!strcmp(value, "sensors"))
                m->sensors = true;
        }
    }
    int requires = wn_doc_member(d, body, "requires");
    if (requires >= 0) {
        if (d->storage[requires].type != '[')
            return -1;
        unsigned count = 0;
        for (unsigned i = (unsigned)requires + 1; i < d->storage[requires].next;
             i = d->storage[i].next) {
            char value[65];
            if (++count > 16 || wn_doc_string(d, (int)i, value, sizeof value) <= 0 ||
                !extension_name(value))
                return -1;
            for (unsigned j = (unsigned)requires + 1; j < i; j = d->storage[j].next)
                if (wn_doc_equal(d, (int)j, value))
                    return -1;
        }
        /* Baseline v4 defines the mechanism and no named required extensions. */
        if (count)
            return WND_UNSUPPORTED;
    }
    m->issued = (int64_t)issued;
    m->expires = (int64_t)expires;
    m->origin.seqno = (uint16_t)seq;
    int services = wns_manifest_services_validate(d, body);
    return services ? services : app_endpoints(d, body, m);
}
static int accept_manifest(struct wnd_directory *d, const void *data, size_t size, int64_t now,
                           int64_t monotonic, bool verified)
{
    struct wn_doc doc;
    struct wnd_manifest m;
    char principal[106];
    uint8_t uuid[16], hash[32];
    const uint8_t *signature;
    size_t signature_size = 0;
    (void)now; /* Receiver UTC does not start or refresh an announcement lease. */
    if (!d || monotonic < 0 ||
        wn_doc_parse_array_view(&doc, data, size, 40 * 1024, "s"))
        return -1;
    /* Envelope extensions are optional. The exact principal and body bytes
     * below remain the signed preimage; ignored metadata cannot alter them. */
    int body = wn_doc_member(&doc, 0, "body");
    if (body < 0)
        return -1;
    int decoded = wnd_manifest_read(&doc, (unsigned)body, &m);
    if (decoded)
        return decoded;
    if (wn_doc_string(&doc, wn_doc_member(&doc, 0, "principal"), principal, sizeof principal) < 0 ||
        wn_principal_device(principal, d->tenant, uuid) || memcmp(uuid, m.device, 16) ||
        wn_doc_bytes(&doc, wn_doc_member(&doc, 0, "signature"), &signature, &signature_size) ||
        signature_size < 8)
        return -1;
    /* An opaque larger signature is an unsupported origin artifact, not a
     * malformed carrier frame. The session may continue other gossip. */
    if (signature_size > WN_ORIGIN_SIGNATURE_MAX)
        return WND_UNSUPPORTED;
    const struct wn_token *t = &doc.tokens[body];
    const char *raw = doc.text + t->start;
    size_t n = t->end - t->start;
    if (n > 32768 || wendy_pki_sha256((const uint8_t *)raw, n, hash))
        return -1;
    const struct wnd_receipt *seen = wnd_receipt_find(d, m.device, monotonic);
    if (seen && m.revision < seen->revision)
        return 1;
    struct wnd_entry *e = find(d, uuid);
    bool duplicate = seen && m.revision == seen->revision;
    if (duplicate && memcmp(hash, seen->body_hash, 32))
        return -1;
    if (!e || !e->peer.spki_size)
        return duplicate ? 1 : 2;
    if (duplicate && (e->manifest.revision != m.revision || e->lease_deadline_us <= monotonic))
        return 1;
#if !WN_ROUTE_HANDOFF_ENABLED
    if (duplicate) {
        if (!verified && wendy_pki_mesh_verify_key(&e->peer, principal, raw, n, signature, signature_size))
            return -1;
        return 0;
    }
#endif
    if (m.expires > (int64_t)e->peer.expires * 1000 ||
        (e->peer.signing_not_before > 0 && m.issued < (int64_t)e->peer.signing_not_before * 1000) ||
        (!verified && wendy_pki_mesh_verify_key(&e->peer, principal, raw, n, signature, signature_size)))
        return -1;
    int64_t lease_us = (m.expires - m.issued) * 1000;
    if (lease_us > INT64_MAX / 10 || monotonic > INT64_MAX - lease_us * 10)
        return -1;
#if WN_ROUTE_HANDOFF_ENABLED
    time_t policy_base = d->route_policy_set ?
        wnrh_policy_at(d->route_policy_base, d->route_policy_monotonic, monotonic) : 0;
    if (d->route_policy_set && policy_base <= 0)
        return -1;
    struct wn_route_proof next = {.origin = m.origin,
        .deadline_us = duplicate ? e->lease_deadline_us : monotonic + (m.expires - m.issued) * 1000,
        .issued = m.issued, .expires = m.expires,
        .path_deadline_us = policy_base > 0 ? wnrh_cap(e->peer.expires, policy_base, monotonic) : INT64_MAX,
        .signing_not_before = e->peer.signing_not_before,
        .issuer_not_before = e->peer.issuer_not_before, .not_after = e->peer.expires};
    if (!m.withdraw && (wendy_pki_sha256(e->peer.spki, e->peer.spki_size, next.key) ||
        wn_route_continuity(&doc, (unsigned)body, next.continuity)))
        return -1;
    if (d->route_policy_set && !wnrh_refresh_proof(&next, policy_base, monotonic,
                                                 d->route_policy_uncertain))
        return 1;
    bool new_state = !e->handoff;
    struct wn_route_handoff *state = e->handoff;
    if (!state && !m.withdraw && !duplicate) {
        state = wendy_net_calloc(1, sizeof *state);
        if (!state)
            return 3;
    }
    if (duplicate) {
        if (m.withdraw)
            return 0;
        if (!state || !wnrh_live(&state->current, monotonic) || next.path_deadline_us <= monotonic)
            return 1;
        struct wn_route_handoff candidate = *state;
        wnrh_resign(&candidate, &next);
        if (d->route_policy_set)
            wnrh_refresh(&candidate, policy_base, monotonic, d->route_policy_uncertain,
                          e->peer.signing_not_before, e->peer.issuer_not_before, e->peer.expires);
        if (!candidate.current_eligible)
            return 1;
        *state = candidate;
        m = e->manifest;
        m.certificate_not_before = e->peer.signing_not_before;
        m.certificate_issuer_not_before = e->peer.issuer_not_before;
        m.certificate_expires = e->peer.expires;
        e->manifest = m;
        e->deadline_us = m.withdraw ? 0 : e->lease_deadline_us;
        return 0;
    }
#else
    if (duplicate)
        return 0;
#endif
    struct wnd_receipt *floor = receipt(d, m.device);
    if (!floor) {
        floor = wendy_net_calloc(1, sizeof *floor);
        if (!floor) {
#if WN_ROUTE_HANDOFF_ENABLED
            if (new_state)
                wendy_net_free(state);
#endif
            return 3;
        }
        memcpy(floor->device, m.device, 16);
        floor->next = d->receipts;
        d->receipts = floor;
        d->receipt_count++;
    }
    floor->revision = m.revision;
    memcpy(floor->body_hash, hash, 32);
    floor->withdrawn = m.withdraw;
    floor->receipt_deadline_us = monotonic + lease_us * 10;
#if WN_ROUTE_HANDOFF_ENABLED
    if (m.withdraw) {
        wendy_net_free(state);
        e->handoff = NULL;
    } else {
        wnrh_replace(state, &next, true, !e->pending_receipt, monotonic);
        if (d->route_policy_set)
            wnrh_refresh(state, policy_base, monotonic, d->route_policy_uncertain,
                          e->peer.signing_not_before, e->peer.issuer_not_before, e->peer.expires);
        e->handoff = state;
    }
#endif
    e->pending_receipt = true;
    e->revision = m.revision;
    memcpy(e->body_hash, hash, 32);
    m.certificate_not_before = e->peer.signing_not_before;
    m.certificate_issuer_not_before = e->peer.issuer_not_before;
    m.certificate_expires = e->peer.expires;
    e->manifest = m;
    e->lease_deadline_us = monotonic + lease_us;
#if WN_ROUTE_HANDOFF_ENABLED
    /* Withdrawals retain no routing tracker. Pin the original selected-path
     * monotonic cap into their existing lease scalar at FIRST admission. */
    if (m.withdraw && next.path_deadline_us < e->lease_deadline_us)
        e->lease_deadline_us = next.path_deadline_us;
#endif
    e->deadline_us = m.withdraw ? 0 : e->lease_deadline_us;
    return 0;
}
static const struct wnd_entry *owner(const struct wnd_directory *d, const uint8_t address[16],
                                     int64_t now)
{
    const struct wnd_entry *found = NULL;
    if (!d || !address || now < 0)
        return NULL;
    for (const struct wnd_entry *e = d->entries; e; e = e->next)
        if (e->deadline_us > now && !memcmp(e->address, address, 16)) {
            if (found)
                return NULL;
            found = e;
        }
    return found;
}
bool wnd_address(const struct wnd_directory *d, const uint8_t address[16], int64_t now)
{
    return owner(d, address, now) != NULL;
}
bool wnd_authorizes(const struct wnd_directory *d, const uint8_t address[16], uint64_t router,
                    uint16_t seqno, int64_t now)
{
    const struct wnd_entry *e = owner(d, address, now);
    if (!e)
        return false;
#if WN_ROUTE_HANDOFF_ENABLED
    if (e->handoff && (!e->handoff->current_verified || !e->handoff->current_eligible || !wnrh_live(&e->handoff->current, now)))
        return false;
    if (e->handoff && e->handoff->has_prior && wnrh_live(&e->handoff->prior, now) &&
        e->handoff->prior.origin.router_id == router && e->handoff->prior.origin.seqno == seqno)
        return true;
#endif
    return e->manifest.origin.router_id == router && e->manifest.origin.seqno == seqno;
}
static void put64(uint8_t *out, uint64_t n)
{
    for (unsigned i = 0; i < 8; i++)
        out[7 - i] = (uint8_t)(n >> (i * 8));
}
static uint64_t get64(const uint8_t *in)
{
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; i++)
        n = (n << 8) | in[i];
    return n;
}
int wnd_save(const struct wnd_directory *d, void *data, size_t capacity)
{
    if (!d || d->receipt_count > UINT32_MAX || d->receipt_count > (INT_MAX - 8) / 65 ||
        (data && capacity < 8))
        return -1;
    uint8_t *out = data;
    size_t n = 8;
    if (out) {
        memcpy(out, "WDR2", 4);
        wn_put32(out + 4, (uint32_t)d->receipt_count);
    }
    for (const struct wnd_receipt *r = d->receipts; r; r = r->next) {
        if (out && capacity - n < 65)
            return -1;
        if (out) {
            memcpy(out + n, r->device, 16);
            put64(out + n + 16, r->revision);
            memcpy(out + n + 24, r->body_hash, 32);
            put64(out + n + 56, (uint64_t)r->receipt_deadline_us);
            out[n + 64] = r->withdrawn;
        }
        n += 65;
    }
    return (int)n;
}
int wnd_restore(struct wnd_directory *d, const void *data, size_t size)
{
    const uint8_t *in = data;
    /* WDR1 had no monotonic lifetime. Do not invent a new clock for an old
     * snapshot. WDR2 is a RAM-only snapshot within the same mesh epoch. */
    if (!d || !in || size < 8 || d->entries || d->receipts || memcmp(in, "WDR2", 4))
        return -1;
    uint32_t count = wn_get32(in + 4);
    if ((size - 8) / 65 != count || (size - 8) % 65)
        return -1;
    struct wnd_directory next = *d;
    uint8_t zero[16] = {0};
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *p = in + 8 + (size_t)i * 65;
        uint8_t address[16];
        wn_address(p, address);
        uint64_t deadline = get64(p + 56);
        if (!memcmp(p, zero, 16) || !memcmp(address, d->self_address, 16) ||
            receipt(&next, p) || !get64(p + 16) || deadline > INT64_MAX || p[64] > 1)
            goto fail;
        struct wnd_receipt *r = wendy_net_calloc(1, sizeof *r);
        if (!r)
            goto fail;
        memcpy(r->device, p, 16);
        r->revision = get64(p + 16);
        memcpy(r->body_hash, p + 24, 32);
        r->receipt_deadline_us = (int64_t)deadline;
        r->withdrawn = p[64];
        r->next = next.receipts;
        next.receipts = r;
        next.receipt_count++;
    }
    *d = next;
    return 0;
fail:
    wnd_deinit(&next);
    return -1;
}
size_t wnd_memory(const struct wnd_directory *d)
{
    size_t bytes = sizeof *d;
    for (const struct wnd_entry *e = d->entries; e; e = e->next)
        bytes += sizeof *e + e->peer.spki_size
#if WN_ROUTE_HANDOFF_ENABLED
                 + (e->handoff ? sizeof *e->handoff : 0)
#endif
            ;
    bytes += d->receipt_count * sizeof(struct wnd_receipt);
    return bytes;
}

int wnd_accept(struct wnd_directory *d, const void *data, size_t size, int64_t now,
               int64_t monotonic)
{
    return accept_manifest(d, data, size, now, monotonic, false);
}
int wnd_accept_verified(struct wnd_directory *d, const void *data, size_t size, int64_t now,
                        int64_t monotonic)
{
    return accept_manifest(d, data, size, now, monotonic, true);
}

bool wnd_route_signature_current(const struct wnd_entry *e)
{
#if WN_ROUTE_HANDOFF_ENABLED
    return e && (!e->handoff || (e->handoff->current_verified && e->handoff->current_eligible));
#else
    return e != NULL;
#endif
}
bool wnd_pending_handoff(const struct wnd_directory *d, unsigned index, int64_t now,
                              uint8_t address[16], struct wn_origin *current)
{
#if WN_ROUTE_HANDOFF_ENABLED
    for (const struct wnd_entry *e = d ? d->entries : NULL; e; e = e->next)
        if (e->handoff && e->handoff->current_verified && e->handoff->current_eligible && e->handoff->has_prior &&
            wnrh_live(&e->handoff->current, now) && wnrh_live(&e->handoff->prior, now)) {
            if (index--)
                continue;
            memcpy(address, e->address, 16);
            *current = e->manifest.origin;
            return true;
        }
#else
    (void)d; (void)index; (void)now; (void)address; (void)current;
#endif
    return false;
}
bool wnd_complete_handoff(struct wnd_directory *d, const uint8_t address[16],
                               const struct wn_origin *current, int64_t now)
{
#if WN_ROUTE_HANDOFF_ENABLED
    for (struct wnd_entry *e = d ? d->entries : NULL; e; e = e->next)
        if (!memcmp(e->address, address, 16) && e->handoff && e->handoff->has_prior &&
            e->manifest.origin.router_id == current->router_id && e->manifest.origin.seqno == current->seqno &&
            wnrh_live(&e->handoff->current, now)) {
            e->handoff->has_prior = false;
            return true;
        }
#else
    (void)d; (void)address; (void)current; (void)now;
#endif
    return false;
}
void wnd_refresh_route_policy(struct wnd_directory *d, time_t base, int64_t now, bool uncertain)
{
    wnd_cache_route_policy(d, base, now, uncertain);
#if WN_ROUTE_HANDOFF_ENABLED
    if (!d)
        return;
    for (struct wnd_entry *e = d->entries; e; e = e->next)
        if (e->handoff) {
            wnrh_refresh(e->handoff, base, now, uncertain,
                          e->manifest.certificate_not_before,
                          e->manifest.certificate_issuer_not_before,
                          e->manifest.certificate_expires);
            e->deadline_us = !e->manifest.withdraw && e->handoff->current_eligible ?
                                 e->lease_deadline_us : 0;
        }
#else
    (void)d; (void)base; (void)now; (void)uncertain;
#endif
}

bool wnd_handoff_request_needed(const struct wnd_directory *d, const uint8_t address[16],
                                      const struct wn_origin *current, int64_t now)
{
#if WN_ROUTE_HANDOFF_ENABLED
    for (const struct wnd_entry *e = d ? d->entries : NULL; e; e = e->next)
        if (!memcmp(e->address, address, 16) && e->handoff && e->handoff->has_prior &&
            !e->handoff->requested && e->handoff->current_verified && e->handoff->current_eligible &&
            wnrh_live(&e->handoff->current, now) && wnrh_live(&e->handoff->prior, now) &&
            e->manifest.origin.router_id == current->router_id && e->manifest.origin.seqno == current->seqno)
            return true;
#else
    (void)d; (void)address; (void)current; (void)now;
#endif
    return false;
}
void wnd_handoff_requested(struct wnd_directory *d, const uint8_t address[16],
                                const struct wn_origin *current, int64_t now)
{
#if WN_ROUTE_HANDOFF_ENABLED
    for (struct wnd_entry *e = d ? d->entries : NULL; e; e = e->next)
        if (!memcmp(e->address, address, 16) && e->handoff && e->handoff->has_prior &&
            e->manifest.origin.router_id == current->router_id && e->manifest.origin.seqno == current->seqno &&
            wnrh_live(&e->handoff->current, now))
            e->handoff->requested = true;
#else
    (void)d; (void)address; (void)current; (void)now;
#endif
}

int64_t wnd_route_deadline(const struct wnd_directory *d, const uint8_t address[16],
                               uint64_t router, uint16_t seqno, int64_t now)
{
    if (!wnd_authorizes(d, address, router, seqno, now))
        return 0;
    const struct wnd_entry *e = owner(d, address, now);
    int64_t until = e->deadline_us;
#if WN_ROUTE_HANDOFF_ENABLED
    if (e->handoff) {
        const struct wn_route_proof *proof = &e->handoff->current;
        if (e->handoff->has_prior && e->handoff->prior.origin.router_id == router &&
            e->handoff->prior.origin.seqno == seqno)
            proof = &e->handoff->prior;
        if (proof->deadline_us < until)
            until = proof->deadline_us;
        if (proof->path_deadline_us < until)
            until = proof->path_deadline_us;
        if (e->handoff->current.path_deadline_us < until)
            until = e->handoff->current.path_deadline_us;
    }
#endif
    return until;
}

bool wnd_withdraw_wire_committed(struct wnd_directory *d, const uint8_t device[16],
                                  uint64_t revision, const uint8_t body_hash[32],
                                  const struct wendy_pki_mesh_key *signer, int64_t now)
{
#if !WN_ROUTE_HANDOFF_ENABLED
    (void)d; (void)device; (void)revision; (void)body_hash; (void)signer; (void)now;
    return false;
#else
    struct wnd_entry *e = d && device ? find(d, device) : NULL;
    uint8_t signer_device[16];
    if (!e || !signer || !body_hash || now < 0 || !e->manifest.withdraw ||
        e->revision != revision || e->lease_deadline_us <= now ||
        memcmp(e->body_hash, body_hash, 32) ||
        wn_uuid_parse(signer->device, signer_device) || memcmp(signer_device, device, 16) ||
        !signer->spki || !signer->spki_size || signer->spki_size > WENDY_PKI_MESH_SPKI_MAX ||
        signer->spki_size != e->peer.spki_size ||
        memcmp(signer->spki, e->peer.spki, signer->spki_size) ||
        signer->expires <= 0 || signer->expires > INT64_MAX / 1000 ||
        signer->signing_not_before < 0 || signer->signing_not_before > INT64_MAX / 1000 ||
        signer->issuer_not_before < 0 || signer->issuer_not_before > INT64_MAX / 1000 ||
        e->manifest.issued < (int64_t)signer->signing_not_before * 1000 ||
        e->manifest.expires > (int64_t)signer->expires * 1000)
        return false;
    time_t end = e->manifest.certificate_expires;
    if (!end || signer->expires < end)
        end = signer->expires;
    int64_t deadline = e->lease_deadline_us;
#if WN_ROUTE_HANDOFF_ENABLED
    if (d->route_policy_set) {
        time_t base = wnrh_policy_at(d->route_policy_base, d->route_policy_monotonic, now);
        struct wn_route_proof proof = {.deadline_us = deadline, .path_deadline_us = deadline,
            .issued = e->manifest.issued, .expires = e->manifest.expires,
            .signing_not_before = signer->signing_not_before,
            .issuer_not_before = signer->issuer_not_before, .not_after = end};
        if (!wnrh_refresh_proof(&proof, base, now, d->route_policy_uncertain))
            return false;
        if (proof.path_deadline_us < deadline)
            deadline = proof.path_deadline_us;
    }
#endif
    e->manifest.certificate_not_before = signer->signing_not_before;
    e->manifest.certificate_issuer_not_before = signer->issuer_not_before;
    e->manifest.certificate_expires = end;
    e->lease_deadline_us = deadline;
    return true;
#endif
}

void wnd_cache_route_policy(struct wnd_directory *d, time_t base, int64_t now, bool uncertain)
{
#if WN_ROUTE_HANDOFF_ENABLED
    if (!d)
        return;
    d->route_policy_base = base;
    d->route_policy_monotonic = now;
    d->route_policy_set = true;
    d->route_policy_uncertain = uncertain;
#else
    (void)d; (void)base; (void)now; (void)uncertain;
#endif
}
