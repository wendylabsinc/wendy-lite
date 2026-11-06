/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_operator.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_crypto.h"
#include <psa/crypto.h>
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#endif
#include <limits.h>
#include <string.h>

bool wno_in_pool(const uint8_t address[16])
{
    static const uint8_t prefix[] = {0xfd, 0x45, 0xb8, 0x91, 0x56, 0x80};
    return address && !memcmp(address, prefix, sizeof prefix);
}
int wno_address(const char *principal, size_t size, const uint8_t instance[16], uint8_t out[16])
{
    static const uint8_t domain[] = "wendy-net/operator-address/v1";
    if (!instance || !out || wendy_pki_operator_principal(principal, size, NULL) ||
        wendy_pki_crypto_init())
        return -1;
    uint8_t length[4];
    wn_put32(length, (uint32_t)size);
    uint8_t digest[32];
    size_t written = 0;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    bool okay = psa_hash_setup(&operation, PSA_ALG_SHA_256) == PSA_SUCCESS &&
                psa_hash_update(&operation, domain, sizeof domain) == PSA_SUCCESS &&
                psa_hash_update(&operation, length, sizeof length) == PSA_SUCCESS &&
                psa_hash_update(&operation, (const uint8_t *)principal, size) == PSA_SUCCESS &&
                psa_hash_update(&operation, instance, 16) == PSA_SUCCESS &&
                psa_hash_finish(&operation, digest, sizeof digest, &written) == PSA_SUCCESS &&
                written == sizeof digest;
    psa_hash_abort(&operation);
    if (!okay)
        return -1;
    memcpy(out, (const uint8_t[]){0xfd, 0x45, 0xb8, 0x91, 0x56, 0x80}, 6);
    memcpy(out + 6, digest, 10);
    return 0;
}
static int number(const struct wn_doc *d, unsigned at, const char *name, uint64_t *out)
{
    return wn_doc_u64(d, wn_doc_member(d, at, name), out);
}
static bool normalized(const char *s, size_t n)
{
    if (!n || n > 64)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              (i && (c == '.' || c == '_' || c == '/' || c == '-'))))
            return false;
    }
    return true;
}
int wno_manifest_read(const void *wire, size_t size, const char *tenant, struct wno_manifest *out)
{
    if (!out)
        return -1;
    struct wn_doc d;
    if (wn_doc_parse_array_view(&d, wire, size, WNO_ARTIFACT_MAX, "s"))
        return -1;
    /* Required members are checked below; future optional envelope members
     * do not change the exact signed principal/body preimage. */
    struct wno_manifest p = {.envelope = wire, .envelope_size = size};
    if (wn_doc_text(&d, wn_doc_member(&d, 0, "principal"), &p.principal, &p.principal_size) ||
        wendy_pki_operator_principal(p.principal, p.principal_size, tenant) ||
        wn_doc_bytes(&d, wn_doc_member(&d, 0, "signature"), &p.signature, &p.signature_size) ||
        !p.signature_size || p.signature_size > 8192)
        return -1;
    /* Match ordinary device origins: a larger supported-by-WendyOS scheme is
     * outside this verifier's current bound, not a reason to drop a carrier. */
    if (p.signature_size > WENDY_PKI_MESH_SIGNATURE_MAX)
        return WNO_UNSUPPORTED;
    int body = wn_doc_member(&d, 0, "body");
    if (body < 0 || d.tokens[body].type != '{')
        return -1;
    p.body = (const uint8_t *)d.text + d.tokens[body].start;
    p.body_size = d.tokens[body].end - d.tokens[body].start;
    if (p.body_size > WENDY_PKI_OPERATOR_BODY_MAX)
        return -1;
    uint64_t version, issued, expires, port;
    if (number(&d, (unsigned)body, "version", &version))
        return -1;
    if (version != 4)
        return WNO_UNSUPPORTED;
    int owner = wn_doc_member(&d, (unsigned)body, "owner");
    const char *principal;
    size_t principal_size;
    char instance[37], device[37];
    uint8_t zero[16] = {0}, device_id[16];
    if (owner < 0 || d.tokens[owner].type != '{' ||
        wn_doc_text(&d, wn_doc_member(&d, (unsigned)owner, "principal"), &principal,
                    &principal_size) ||
        principal_size != p.principal_size || memcmp(principal, p.principal, p.principal_size) ||
        wn_doc_string(&d, wn_doc_member(&d, (unsigned)owner, "instance"), instance,
                      sizeof instance) < 0 ||
        wn_uuid_parse(instance, p.instance) || !memcmp(p.instance, zero, 16) ||
        wn_doc_string(&d, wn_doc_member(&d, (unsigned)body, "device"), device, sizeof device) < 0 ||
        wn_uuid_parse(device, device_id) || memcmp(device_id, zero, 16) ||
        number(&d, (unsigned)body, "agentPort", &port) || port ||
        number(&d, (unsigned)body, "revision", &p.revision) || !p.revision ||
        number(&d, (unsigned)body, "Issued", &issued) || issued > INT64_MAX ||
        number(&d, (unsigned)body, "Expires", &expires) || expires > INT64_MAX ||
        expires <= issued || expires - issued > 900000)
        return -1;
    int hashes = wn_doc_member(&d, (unsigned)owner, "hashes");
    if (hashes < 0 || d.tokens[hashes].type != '[')
        return -1;
    for (unsigned i = (unsigned)hashes + 1; i < d.tokens[hashes].next; i = d.tokens[i].next) {
        size_t n;
        if (p.hash_count == 16 || wn_doc_bytes(&d, (int)i, &p.hashes[p.hash_count], &n) || n != 32)
            return -1;
        p.hash_count++;
    }
    if (!p.hash_count)
        return -1;
    p.issued = (int64_t)issued;
    p.expires = (int64_t)expires;
    int withdraw = wn_doc_member(&d, (unsigned)body, "withdraw");
    if (withdraw >= 0) {
        if (d.tokens[withdraw].type != 't' && d.tokens[withdraw].type != 'f')
            return -1;
        p.withdraw = d.tokens[withdraw].type == 't';
    }
    int required = wn_doc_member(&d, (unsigned)body, "requires");
    if (required >= 0) {
        if (d.tokens[required].type != '[')
            return -1;
        unsigned count = 0;
        for (unsigned i = (unsigned)required + 1; i < d.tokens[required].next;
             i = d.tokens[i].next) {
            const char *name;
            size_t n;
            if (++count > 16 || wn_doc_text(&d, (int)i, &name, &n) || !normalized(name, n))
                return -1;
        }
        if (count)
            return WNO_UNSUPPORTED;
    }
    static const char *const arrays[] = {"caps", "appEndpoints", "s", NULL};
    for (unsigned i = 0; arrays[i]; i++) {
        int array = wn_doc_member(&d, (unsigned)body, arrays[i]);
        if (array >= 0 &&
            (d.tokens[array].type != '[' || (uint8_t)d.text[d.tokens[array].start] != 0x80))
            return -1;
    }
    static const char *const texts[] = {"agentTransport", "platform", NULL};
    for (unsigned i = 0; texts[i]; i++) {
        int text = wn_doc_member(&d, (unsigned)body, texts[i]);
        if (text >= 0 && !wn_doc_equal(&d, text, ""))
            return -1;
    }
    int route = wn_doc_member(&d, (unsigned)body, "route");
    uint64_t seqno;
    char prefix[64];
    uint8_t expected[16];
    if (route < 0 || d.tokens[route].type != '{' ||
        number(&d, (unsigned)route, "routerId", &p.origin.router_id) || !p.origin.router_id ||
        p.origin.router_id == UINT64_MAX || number(&d, (unsigned)route, "seqno", &seqno) ||
        seqno > UINT16_MAX ||
        wn_doc_string(&d, wn_doc_member(&d, (unsigned)route, "prefix"), prefix, sizeof prefix) <=
            0 ||
        wno_address(p.principal, p.principal_size, p.instance, expected))
        return -1;
    size_t n = strlen(prefix);
    if (n <= 4 || strcmp(prefix + n - 4, "/128"))
        return -1;
    prefix[n - 4] = 0;
    if (inet_pton(AF_INET6, prefix, p.address) != 1 || memcmp(p.address, expected, 16))
        return -1;
    p.origin.seqno = (uint16_t)seqno;
    *out = p;
    return 0;
}

int wno_init(struct wno_directory *d, const char *tenant, unsigned limit)
{
    uint8_t uuid[16];
    if (!d || wn_uuid_parse(tenant, uuid) || !limit || limit > WNO_DIRECTORY_MAX)
        return -1;
    *d = (struct wno_directory){.limit = limit};
    memcpy(d->tenant, tenant, 37);
    return 0;
}
void wno_deinit(struct wno_directory *d)
{
    if (!d)
        return;
    while (d->entries) {
        struct wno_entry *e = d->entries;
        d->entries = e->next;
#if WN_ROUTE_HANDOFF_ENABLED
        wendy_net_free(e->handoff);
#endif
        wendy_net_free(e);
    }
    while (d->receipts) {
        struct wno_receipt *r = d->receipts;
        d->receipts = r->next;
        wendy_net_free(r);
    }
    memset(d, 0, sizeof *d);
}
static struct wno_receipt *receipt(const struct wno_directory *d, const char *principal, size_t n,
                                  const uint8_t instance[16])
{
    for (struct wno_receipt *r = d->receipts; r; r = r->next)
        if (r->principal_size == n && !memcmp(r->principal, principal, n) &&
            !memcmp(r->instance, instance, 16))
            return r;
    return NULL;
}
const struct wno_receipt *wno_receipt_find(const struct wno_directory *d, const char *principal,
                                          size_t n, const uint8_t instance[16], int64_t now)
{
    struct wno_receipt *r = d && principal && instance && now >= 0
                               ? receipt(d, principal, n, instance)
                               : NULL;
    return r && r->receipt_deadline_us > now ? r : NULL;
}
void wno_expire(struct wno_directory *d, int64_t now)
{
    if (!d || now < 0)
        return;
#if WN_ROUTE_HANDOFF_ENABLED
    for (struct wno_entry *e = d->entries; e; e = e->next)
        if (e->handoff && e->handoff->has_prior && !wnrh_live(&e->handoff->prior, now))
            e->handoff->has_prior = false;
#endif
    for (struct wno_entry **at = &d->entries; *at;)
        if ((*at)->lease_deadline_us <= now) {
            struct wno_entry *e = *at;
            *at = e->next;
#if WN_ROUTE_HANDOFF_ENABLED
            wendy_net_free(e->handoff);
#endif
            wendy_net_free(e);
            d->count--;
        } else
            at = &(*at)->next;
    for (struct wno_receipt **at = &d->receipts; *at;)
        if ((*at)->receipt_deadline_us <= now) {
            struct wno_receipt *r = *at;
            *at = r->next;
            wendy_net_free(r);
            d->receipt_count--;
        } else
            at = &(*at)->next;
}
int64_t wno_next_deadline(const struct wno_directory *d, int64_t now)
{
    int64_t next = INT64_MAX;
    if (!d)
        return next;
    for (const struct wno_entry *e = d->entries; e; e = e->next)
        if (e->lease_deadline_us <= now)
            return now;
        else if (e->lease_deadline_us < next)
            next = e->lease_deadline_us;
#if WN_ROUTE_HANDOFF_ENABLED
    for (const struct wno_entry *e = d->entries; e; e = e->next)
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
    for (const struct wno_receipt *r = d->receipts; r; r = r->next)
        if (r->receipt_deadline_us <= now)
            return now;
        else if (r->receipt_deadline_us < next)
            next = r->receipt_deadline_us;
    return next;
}
int wno_accept_manifest_verified(struct wno_directory *d, const struct wno_manifest *p,
                                 const struct wendy_pki_operator_peer *identity, int64_t now,
                                 int64_t monotonic)
{
    (void)now; /* Receiver UTC does not start or refresh announcement lifetime. */
    if (!d || !d->limit || !p || !identity || monotonic < 0 ||
        wendy_pki_operator_principal(p->principal, p->principal_size, d->tenant) ||
        strnlen(identity->principal, sizeof identity->principal) != p->principal_size ||
        memcmp(identity->principal, p->principal, p->principal_size) || identity->expires <= 0 ||
        identity->expires > INT64_MAX / 1000 ||
        (identity->not_before > 0 && identity->not_before > INT64_MAX / 1000) ||
        (identity->signing_not_before > 0 && identity->signing_not_before > INT64_MAX / 1000) ||
        (identity->issuer_not_before > 0 && identity->issuer_not_before > INT64_MAX / 1000) ||
        p->issued < 0 || p->expires <= p->issued || p->expires - p->issued > 900000 ||
        !p->revision)
        return -1;
    int64_t lease_us = (p->expires - p->issued) * 1000;
    if (lease_us > INT64_MAX / 10 || monotonic > INT64_MAX - lease_us * 10)
        return -1;
    uint8_t digest[32];
    if (wendy_pki_sha256(p->body, p->body_size, digest))
        return -1;
    wno_expire(d, monotonic);
    const struct wno_receipt *seen = wno_receipt_find(d, p->principal, p->principal_size,
                                                     p->instance, monotonic);
    if (seen && p->revision < seen->revision)
        return 1;
    struct wno_entry *e = d->entries;
    while (e && !(e->principal_size == p->principal_size &&
                  !memcmp(e->principal, p->principal, p->principal_size) &&
                  !memcmp(e->instance, p->instance, 16)))
        e = e->next;
    bool duplicate = seen && p->revision == seen->revision;
    if (duplicate && memcmp(seen->digest, digest, 32))
        return -1;
    if (duplicate && (!e || e->lease_deadline_us <= monotonic))
        return 1;
#if !WN_ROUTE_HANDOFF_ENABLED
    if (duplicate)
        return 0;
#endif
    if (!p->hash_count || memcmp(p->hashes[0], identity->leaf_hash, 32) ||
        p->expires > (int64_t)identity->expires * 1000 ||
        (identity->signing_not_before > 0 && p->issued < (int64_t)identity->signing_not_before * 1000))
        return -1;
    if (!duplicate && !e && d->count >= d->limit)
        return 3;
#if WN_ROUTE_HANDOFF_ENABLED
    struct wn_doc doc;
    int body;
    time_t policy_base = d->route_policy_set ?
        wnrh_policy_at(d->route_policy_base, d->route_policy_monotonic, monotonic) : 0;
    if (d->route_policy_set && policy_base <= 0)
        return -1;
    struct wn_route_proof next = {.origin = p->origin,
        .deadline_us = duplicate ? e->lease_deadline_us : monotonic + lease_us,
        .issued = p->issued, .expires = p->expires,
        .path_deadline_us = policy_base > 0 ? wnrh_cap(identity->expires, policy_base, monotonic) : INT64_MAX,
        .signing_not_before = identity->signing_not_before,
        .issuer_not_before = identity->issuer_not_before, .not_after = identity->expires};
    if (!p->withdraw && (wn_doc_parse_array_view(&doc, p->envelope, p->envelope_size, WNO_ARTIFACT_MAX, "s") ||
        (body = wn_doc_member(&doc, 0, "body")) < 0 ||
        wn_route_continuity(&doc, (unsigned)body, next.continuity) ||
        wendy_pki_sha256(identity->spki, identity->spki_size, next.key)))
        return -1;
    if (d->route_policy_set && !wnrh_refresh_proof(&next, policy_base, monotonic,
                                                 d->route_policy_uncertain))
        return 1;
    struct wn_route_handoff *state = e ? e->handoff : NULL;
    bool new_state = !state;
    if (!state && !p->withdraw && !duplicate) {
        state = wendy_net_calloc(1, sizeof *state);
        if (!state)
            return 3;
    }
    if (duplicate) {
        if (p->withdraw)
            return 0;
        if (!state || !wnrh_live(&state->current, monotonic) || next.path_deadline_us <= monotonic)
            return 1;
        struct wn_route_handoff candidate = *state;
        wnrh_resign(&candidate, &next);
        if (d->route_policy_set)
            wnrh_refresh(&candidate, policy_base, monotonic, d->route_policy_uncertain,
                          identity->signing_not_before, identity->issuer_not_before, identity->expires);
        if (!candidate.current_eligible)
            return 1;
        *state = candidate;
        e->claim_not_before = identity->signing_not_before;
        e->claim_issuer_not_before = identity->issuer_not_before;
        e->claim_expires = identity->expires;
        e->deadline_us = p->withdraw ? 0 : e->lease_deadline_us;
        return 0;
    }
#else
    if (duplicate)
        return 0;
#endif
    struct wno_receipt *floor = receipt(d, p->principal, p->principal_size, p->instance);
    bool new_floor = !floor;
    if (new_floor) {
        floor = wendy_net_calloc(1, sizeof *floor + p->principal_size + 1);
        if (!floor) {
#if WN_ROUTE_HANDOFF_ENABLED
            if (new_state)
                wendy_net_free(state);
#endif
            return 3;
        }
    }
    if (!e) {
        e = wendy_net_calloc(1, sizeof *e + p->principal_size + 1);
        if (!e) {
            if (new_floor)
                wendy_net_free(floor);
#if WN_ROUTE_HANDOFF_ENABLED
            if (new_state)
                wendy_net_free(state);
#endif
            return 3;
        }
        memcpy(e->principal, p->principal, p->principal_size);
        e->principal_size = p->principal_size;
        memcpy(e->instance, p->instance, 16);
        e->next = d->entries;
        d->entries = e;
        d->count++;
    }
    if (new_floor) {
        memcpy(floor->principal, p->principal, p->principal_size);
        floor->principal_size = p->principal_size;
        memcpy(floor->instance, p->instance, 16);
        floor->next = d->receipts;
        d->receipts = floor;
        d->receipt_count++;
    }
#if WN_ROUTE_HANDOFF_ENABLED
    if (p->withdraw) {
        wendy_net_free(state);
        e->handoff = NULL;
    } else {
        wnrh_replace(state, &next, true, true, monotonic);
        if (d->route_policy_set)
            wnrh_refresh(state, policy_base, monotonic, d->route_policy_uncertain,
                          identity->signing_not_before, identity->issuer_not_before, identity->expires);
        e->handoff = state;
    }
#endif
    floor->revision = p->revision;
    memcpy(floor->digest, digest, 32);
    floor->withdrawn = p->withdraw;
    floor->receipt_deadline_us = monotonic + lease_us * 10;
    e->lease_deadline_us = monotonic + lease_us;
#if WN_ROUTE_HANDOFF_ENABLED
    /* Withdrawals retain no routing tracker. Pin the original selected-path
     * monotonic cap into their existing lease scalar at FIRST admission. */
    if (p->withdraw && next.path_deadline_us < e->lease_deadline_us)
        e->lease_deadline_us = next.path_deadline_us;
#endif
    e->deadline_us = p->withdraw ? 0 : e->lease_deadline_us;
    e->revision = p->revision;
    e->origin = p->origin;
    e->claim_not_before = identity->signing_not_before;
    e->claim_issuer_not_before = identity->issuer_not_before;
    e->claim_expires = identity->expires;
    memcpy(e->address, p->address, 16);
    memcpy(e->digest, digest, 32);
    return 0;
}
static const struct wno_entry *owner(const struct wno_directory *d, const uint8_t address[16],
                                     int64_t now)
{
    if (!d || !address || now < 0)
        return NULL;
    const struct wno_entry *found = NULL;
    for (const struct wno_entry *e = d->entries; e; e = e->next)
        if (e->deadline_us > now && !memcmp(e->address, address, 16)) {
            if (found)
                return NULL;
            found = e;
        }
    return found;
}
bool wno_live_address(const struct wno_directory *d, const uint8_t address[16], int64_t now)
{
    return owner(d, address, now) != NULL;
}
bool wno_authorizes(const struct wno_directory *d, const uint8_t address[16], uint64_t router,
                    uint16_t seqno, int64_t now)
{
    const struct wno_entry *e = owner(d, address, now);
    if (!e)
        return false;
#if WN_ROUTE_HANDOFF_ENABLED
    if (e->handoff && (!e->handoff->current_verified || !e->handoff->current_eligible || !wnrh_live(&e->handoff->current, now)))
        return false;
    if (e->handoff && e->handoff->has_prior && wnrh_live(&e->handoff->prior, now) &&
        e->handoff->prior.origin.router_id == router && e->handoff->prior.origin.seqno == seqno)
        return true;
#endif
    return e->origin.router_id == router && e->origin.seqno == seqno;
}
size_t wno_memory(const struct wno_directory *d)
{
    size_t bytes = 0;
    if (!d)
        return 0;
    for (const struct wno_entry *e = d->entries; e; e = e->next)
        bytes += sizeof *e + e->principal_size + 1
#if WN_ROUTE_HANDOFF_ENABLED
                 + (e->handoff ? sizeof *e->handoff : 0)
#endif
            ;
    for (const struct wno_receipt *r = d->receipts; r; r = r->next)
        bytes += sizeof *r + r->principal_size + 1;
    return bytes;
}

bool wno_route_signature_current(const struct wno_entry *e)
{
#if WN_ROUTE_HANDOFF_ENABLED
    return e && (!e->handoff || (e->handoff->current_verified && e->handoff->current_eligible));
#else
    return e != NULL;
#endif
}
bool wno_pending_handoff(const struct wno_directory *d, unsigned index, int64_t now,
                              uint8_t address[16], struct wn_origin *current)
{
#if WN_ROUTE_HANDOFF_ENABLED
    for (const struct wno_entry *e = d ? d->entries : NULL; e; e = e->next)
        if (e->handoff && e->handoff->current_verified && e->handoff->current_eligible && e->handoff->has_prior &&
            wnrh_live(&e->handoff->current, now) && wnrh_live(&e->handoff->prior, now)) {
            if (index--)
                continue;
            memcpy(address, e->address, 16);
            *current = e->origin;
            return true;
        }
#else
    (void)d; (void)index; (void)now; (void)address; (void)current;
#endif
    return false;
}
bool wno_complete_handoff(struct wno_directory *d, const uint8_t address[16],
                               const struct wn_origin *current, int64_t now)
{
#if WN_ROUTE_HANDOFF_ENABLED
    for (struct wno_entry *e = d ? d->entries : NULL; e; e = e->next)
        if (!memcmp(e->address, address, 16) && e->handoff && e->handoff->has_prior &&
            e->origin.router_id == current->router_id && e->origin.seqno == current->seqno &&
            wnrh_live(&e->handoff->current, now)) {
            e->handoff->has_prior = false;
            return true;
        }
#else
    (void)d; (void)address; (void)current; (void)now;
#endif
    return false;
}
void wno_refresh_route_policy(struct wno_directory *d, time_t base, int64_t now, bool uncertain)
{
    wno_cache_route_policy(d, base, now, uncertain);
#if WN_ROUTE_HANDOFF_ENABLED
    if (!d)
        return;
    for (struct wno_entry *e = d->entries; e; e = e->next)
        if (e->handoff) {
            wnrh_refresh(e->handoff, base, now, uncertain, e->claim_not_before,
                          e->claim_issuer_not_before, e->claim_expires);
            e->deadline_us = e->handoff->current_eligible ? e->lease_deadline_us : 0;
        }
#else
    (void)d; (void)base; (void)now; (void)uncertain;
#endif
}

bool wno_handoff_request_needed(const struct wno_directory *d, const uint8_t address[16],
                                      const struct wn_origin *current, int64_t now)
{
#if WN_ROUTE_HANDOFF_ENABLED
    for (const struct wno_entry *e = d ? d->entries : NULL; e; e = e->next)
        if (!memcmp(e->address, address, 16) && e->handoff && e->handoff->has_prior &&
            !e->handoff->requested && e->handoff->current_verified && e->handoff->current_eligible &&
            wnrh_live(&e->handoff->current, now) && wnrh_live(&e->handoff->prior, now) &&
            e->origin.router_id == current->router_id && e->origin.seqno == current->seqno)
            return true;
#else
    (void)d; (void)address; (void)current; (void)now;
#endif
    return false;
}
void wno_handoff_requested(struct wno_directory *d, const uint8_t address[16],
                                const struct wn_origin *current, int64_t now)
{
#if WN_ROUTE_HANDOFF_ENABLED
    for (struct wno_entry *e = d ? d->entries : NULL; e; e = e->next)
        if (!memcmp(e->address, address, 16) && e->handoff && e->handoff->has_prior &&
            e->origin.router_id == current->router_id && e->origin.seqno == current->seqno &&
            wnrh_live(&e->handoff->current, now))
            e->handoff->requested = true;
#else
    (void)d; (void)address; (void)current; (void)now;
#endif
}

int64_t wno_route_deadline(const struct wno_directory *d, const uint8_t address[16],
                               uint64_t router, uint16_t seqno, int64_t now)
{
    if (!wno_authorizes(d, address, router, seqno, now))
        return 0;
    const struct wno_entry *e = owner(d, address, now);
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

void wno_cache_route_policy(struct wno_directory *d, time_t base, int64_t now, bool uncertain)
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
