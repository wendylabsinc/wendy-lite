/* Already-verified operator projections use monotonic payload/receipt lifetimes.
 * Certificate/signature verification is exercised by the separate interop
 * fixtures; these records pass the real v4 shape parser before admission. */
#include "wendy_net_operator.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_crypto.h"
#include <arpa/inet.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static const char tenant[] = "11111111-1111-4111-8111-111111111111";
static const char principal[] =
    "spiffe://wendy.sh/tenant/11111111-1111-4111-8111-111111111111/operator/ttl-test";
static uint16_t fixture_sequence = 5;
static const int64_t issued = INT64_C(1800000000000);
struct fixture {
    uint8_t wire[2048];
    struct wno_manifest proof;
};
static void fixture(struct fixture *f, const struct wendy_pki_operator_peer *peer, unsigned instance,
                    uint64_t revision, int64_t start, int64_t duration_ms, bool withdrawn,
                    unsigned signature_variant)
{
    uint8_t id[16] = {0}, address[16], body[1536], signature[64];
    id[14] = (uint8_t)(instance >> 8);
    id[15] = (uint8_t)instance;
    assert(instance && !wno_address(principal, strlen(principal), id, address));
    char uuid[37], prefix[64], ip[INET6_ADDRSTRLEN];
    wn_uuid_format(id, uuid);
    assert(inet_ntop(AF_INET6, address, ip, sizeof ip));
    assert(snprintf(prefix, sizeof prefix, "%s/128", ip) > 0);
    struct wn_writer w = {.data = body, .capacity = sizeof body, .maximum = sizeof body};
    wn_map(&w, 9);
    wn_key(&w, "version");
    wn_uint(&w, 4);
    wn_key(&w, "owner");
    wn_map(&w, 3);
    wn_key(&w, "principal");
    wn_text(&w, principal);
    wn_key(&w, "instance");
    wn_text(&w, uuid);
    wn_key(&w, "hashes");
    wn_array(&w, 1);
    wn_bytes(&w, peer->leaf_hash, sizeof peer->leaf_hash);
    wn_key(&w, "device");
    wn_text(&w, "00000000-0000-0000-0000-000000000000");
    wn_key(&w, "agentPort");
    wn_uint(&w, 0);
    wn_key(&w, "revision");
    wn_uint(&w, revision);
    wn_key(&w, "Issued");
    wn_uint(&w, (uint64_t)start);
    wn_key(&w, "Expires");
    wn_uint(&w, (uint64_t)(start + duration_ms));
    wn_key(&w, "withdraw");
    wn_bool(&w, withdrawn);
    wn_key(&w, "route");
    wn_map(&w, 3);
    wn_key(&w, "routerId");
    wn_uint(&w, 1000 + instance);
    wn_key(&w, "seqno");
    wn_uint(&w, fixture_sequence);
    wn_key(&w, "prefix");
    wn_text(&w, prefix);
    int n = wn_finish(&w);
    assert(n > 0);
    memset(signature, (int)signature_variant, sizeof signature);
    w = (struct wn_writer){.data = f->wire, .capacity = sizeof f->wire,
                            .maximum = sizeof f->wire};
    wn_map(&w, 3);
    wn_key(&w, "body");
    wn_raw(&w, body, (size_t)n);
    wn_key(&w, "principal");
    wn_text(&w, principal);
    wn_key(&w, "signature");
    wn_bytes(&w, signature, sizeof signature);
    n = wn_finish(&w);
    assert(n > 0 && !wno_manifest_read(f->wire, (size_t)n, tenant, &f->proof));
}
static const struct wno_receipt *floor_for(const struct wno_directory *d,
                                          const struct wno_manifest *p, int64_t now)
{
    return wno_receipt_find(d, p->principal, p->principal_size, p->instance, now);
}
static void ledger_empty(void)
{
    wendy_net_memory_snapshot_t state;
    wendy_net_runtime_memory_snapshot(&state);
    assert(!state.current_bytes && !state.allocation_count && !state.reservation_count);
}
static void lifecycle(const struct wendy_pki_operator_peer *peer)
{
    struct wno_directory d;
    assert(!wno_init(&d, tenant, 64));
    struct fixture first, resign, higher, withdrawal;
    const int64_t now = 1000000, lifetime = 100000;
    fixture(&first, peer, 1, 5, issued, 100, false, 1);
    fixture(&resign, peer, 1, 5, issued, 100, false, 2);
    assert(!wno_accept_manifest_verified(&d, &first.proof, peer, 0, now));
    const struct wno_receipt *r = floor_for(&d, &first.proof, now);
    assert(r && d.receipt_count == 1 && d.count == 1 && r->revision == 5);
    assert(r->receipt_deadline_us == now + 10 * lifetime);
    assert(d.entries->deadline_us == now + lifetime);
    assert(d.entries->lease_deadline_us == now + lifetime);
    assert(wno_next_deadline(&d, now) == now + lifetime);
    assert(d.entries->claim_not_before == peer->signing_not_before &&
           d.entries->claim_issuer_not_before == peer->issuer_not_before &&
           d.entries->claim_expires == peer->expires);
    struct wendy_pki_operator_peer renewed = *peer;
    renewed.not_before += 100;
    renewed.issuer_not_before += 100;
    renewed.signing_not_before = (time_t)(issued / 1000) + 10;
    renewed.expires += 100;
    /* A re-signed duplicate must still fit the ACTUAL signing certificate.
     * Out-of-window metadata cannot borrow the earlier accepted signature. */
#if WN_ROUTE_HANDOFF_ENABLED
    assert(wno_accept_manifest_verified(&d, &resign.proof, &renewed, INT64_MAX, now + 1) < 0);
#else
    assert(!wno_accept_manifest_verified(&d, &resign.proof, &renewed, INT64_MAX, now + 1));
#endif
    assert(d.entries->claim_not_before == peer->signing_not_before &&
           d.entries->claim_issuer_not_before == peer->issuer_not_before &&
           d.entries->claim_expires == peer->expires);
    assert(!wno_accept_manifest_verified(&d, &resign.proof, peer, INT64_MAX, now + 1));
    assert(!wno_accept_manifest_verified(&d, &first.proof, peer, INT64_MIN, now + 2));
    assert(r->receipt_deadline_us == now + 10 * lifetime &&
           d.entries->lease_deadline_us == now + lifetime);
    assert(wno_next_deadline(&d, now + lifetime) == now + lifetime);
    wno_expire(&d, now + lifetime);
    assert(!d.entries && !d.count && d.receipt_count == 1);
    size_t receipt_only = wno_memory(&d);
    assert(receipt_only == sizeof *r + strlen(principal) + 1);
    assert(wno_next_deadline(&d, now + lifetime) == now + 10 * lifetime);
    /* A expired; delayed B/reconnect carries the original or re-signed body. */
    assert(wno_accept_manifest_verified(&d, &first.proof, peer, INT64_MIN,
                                         now + lifetime + 1) == 1);
    assert(wno_accept_manifest_verified(&d, &resign.proof, peer, INT64_MAX,
                                         now + lifetime + 2) == 1);
    assert(!d.entries && d.receipt_count == 1 && wno_memory(&d) == receipt_only);
    assert(r->receipt_deadline_us == now + 10 * lifetime);
    fixture(&higher, peer, 1, 4, issued, 100, false, 1);
    assert(wno_accept_manifest_verified(&d, &higher.proof, peer, 0,
                                         now + lifetime + 3) == 1);
    fixture(&higher, peer, 1, 5, issued, 100, true, 1);
    assert(wno_accept_manifest_verified(&d, &higher.proof, peer, 0,
                                         now + lifetime + 4) < 0);
    const int64_t replacement = now + 2 * lifetime;
    fixture(&higher, peer, 1, 6, issued, 100, false, 1);
    renewed.signing_not_before = peer->signing_not_before;
    assert(!wno_accept_manifest_verified(&d, &higher.proof, &renewed, 0, replacement));
    assert(d.entries->claim_not_before == renewed.signing_not_before &&
           d.entries->claim_issuer_not_before == renewed.issuer_not_before &&
           d.entries->claim_expires == renewed.expires);
    assert(d.count == 1 && d.entries->revision == 6 && d.receipt_count == 1);
    assert(r->receipt_deadline_us == replacement + 10 * lifetime);
    fixture(&withdrawal, peer, 1, 7, issued, 100, true, 1);
    const int64_t withdrawn = replacement + 1;
    assert(!wno_accept_manifest_verified(&d, &withdrawal.proof, peer, INT64_MAX, withdrawn));
    assert(!d.entries->deadline_us && d.entries->lease_deadline_us == withdrawn + lifetime);
    assert(r->withdrawn && r->receipt_deadline_us == withdrawn + 10 * lifetime);
    wno_expire(&d, withdrawn + lifetime);
    assert(!d.entries && d.receipt_count == 1);
    assert(wno_accept_manifest_verified(&d, &withdrawal.proof, peer, 0,
                                         withdrawn + lifetime + 1) == 1);
    assert(wno_next_deadline(&d, withdrawn + 10 * lifetime) == withdrawn + 10 * lifetime);
    wno_expire(&d, withdrawn + 10 * lifetime);
    assert(!d.entries && !d.receipts && !d.receipt_count && !wno_memory(&d));
    assert(wno_next_deadline(&d, withdrawn + 10 * lifetime) == INT64_MAX);
    /* A floor intentionally forgotten at 10x permits a new first receipt. */
    assert(!wno_accept_manifest_verified(&d, &first.proof, peer, 0,
                                          withdrawn + 10 * lifetime));
    assert(d.entries->revision == 5);
    wno_deinit(&d);
    ledger_empty();
}
static void dynamic_floors(const struct wendy_pki_operator_peer *peer)
{
    struct wno_directory d;
    assert(!wno_init(&d, tenant, 64));
    const int64_t start = 2000000, lifetime = 100000;
    struct fixture f, delayed;
    fixture(&delayed, peer, 1, 1, issued, 100, false, 3);
    for (unsigned batch = 0; batch < 9; batch++) {
        int64_t now = start + (int64_t)batch * 101000;
        for (unsigned i = 1; i <= 16; i++) {
            unsigned instance = batch * 16 + i;
            fixture(&f, peer, instance, 1, issued, 100, false, 1);
            assert(!wno_accept_manifest_verified(&d, &f.proof, peer, i & 1 ? 0 : INT64_MAX, now));
        }
        assert(d.count == 16 && d.receipt_count == (batch + 1) * 16);
        wno_expire(&d, now + lifetime);
        assert(!d.count && !d.entries && d.receipt_count == (batch + 1) * 16);
    }
    assert(d.receipt_count == 144);
    const struct wno_receipt *r = floor_for(&d, &delayed.proof, start + 909000);
    assert(r && r->receipt_deadline_us == start + 10 * lifetime);
    assert(wno_accept_manifest_verified(&d, &delayed.proof, peer, 0, start + 909000) == 1);
    assert(!d.entries && d.receipt_count == 144);
    wno_expire(&d, start + 1808000);
    assert(!d.receipts && !d.receipt_count && !wno_memory(&d));
    wno_deinit(&d);
    ledger_empty();
}
static void active_capacity(const struct wendy_pki_operator_peer *peer)
{
    struct wno_directory d;
    assert(!wno_init(&d, tenant, 64));
    struct fixture f;
    const int64_t now = 4000000;
    for (unsigned instance = 1; instance <= 64; instance++) {
        fixture(&f, peer, instance, 1, issued, 100, false, 1);
        assert(!wno_accept_manifest_verified(&d, &f.proof, peer, 0, now));
    }
    assert(d.count == 64 && d.receipt_count == 64);
    size_t before = wno_memory(&d);
    fixture(&f, peer, 65, 1, issued, 100, false, 1);
    assert(wno_accept_manifest_verified(&d, &f.proof, peer, 0, now) == 3);
    assert(d.count == 64 && d.receipt_count == 64 && wno_memory(&d) == before);
    fixture(&f, peer, 1, 2, issued, 100, false, 1);
    assert(!wno_accept_manifest_verified(&d, &f.proof, peer, 0, now + 1));
    assert(d.count == 64 && d.receipt_count == 64);
    wno_expire(&d, now + 100001);
    assert(!d.entries && d.receipt_count == 64);
    fixture(&f, peer, 65, 1, issued, 100, false, 1);
    assert(!wno_accept_manifest_verified(&d, &f.proof, peer, 0, now + 100001));
    assert(d.count == 1 && d.receipt_count == 65);
    wno_deinit(&d);
    ledger_empty();
}
static void short_cycles(const struct wendy_pki_operator_peer *peer)
{
    struct wno_directory d;
    assert(!wno_init(&d, tenant, 64));
    struct fixture f;
    for (unsigned i = 0; i < 128; i++) {
        int64_t now = 5000000 + (int64_t)i * 20000;
        fixture(&f, peer, 1, i + 1, issued, 1, false, 1);
        assert(!wno_accept_manifest_verified(&d, &f.proof, peer, INT64_MAX, now));
        assert(d.count == 1 && d.receipt_count == 1);
        wno_expire(&d, now + 1000);
        assert(!d.entries && !d.count && d.receipt_count == 1);
        assert(wno_accept_manifest_verified(&d, &f.proof, peer, 0, now + 1001) == 1);
        wno_expire(&d, now + 10000);
        assert(!d.receipts && !d.receipt_count && !wno_memory(&d));
        ledger_empty();
    }
    wno_deinit(&d);
}
static void bounds(const struct wendy_pki_operator_peer *peer)
{
    struct wno_directory d;
    assert(!wno_init(&d, tenant, 64));
    struct fixture f;
    fixture(&f, peer, 1, 1, (int64_t)peer->signing_not_before * 1000 - 1, 100, false, 1);
    assert(wno_accept_manifest_verified(&d, &f.proof, peer, 0, 0) < 0);
    fixture(&f, peer, 1, 1, (int64_t)peer->expires * 1000 - 1, 100, false, 1);
    assert(wno_accept_manifest_verified(&d, &f.proof, peer, 0, 0) < 0);
    fixture(&f, peer, 1, 1, issued, 100, false, 1);
    assert(!wno_accept_manifest_verified(&d, &f.proof, peer, 0, 1000));
    struct wno_entry *entry = d.entries;
    const struct wno_receipt *r = floor_for(&d, &f.proof, 1000);
    assert(r);
    int64_t lease = entry->lease_deadline_us, receipt = r->receipt_deadline_us;
    size_t bytes = wno_memory(&d);
    fixture(&f, peer, 2, 1, issued, 900000, false, 1);
    assert(wno_accept_manifest_verified(&d, &f.proof, peer, 0, INT64_MAX - 8999999999) < 0);
    /* Invalid overflow input must not run the idle sweep as a side effect. */
    assert(d.entries == entry && d.receipt_count == 1 && d.count == 1);
    assert(entry->lease_deadline_us == lease && r->receipt_deadline_us == receipt &&
           wno_memory(&d) == bytes);
    wno_deinit(&d);
    ledger_empty();
}
static void allocation_failure(const struct wendy_pki_operator_peer *peer)
{
    struct wno_directory d;
    assert(!wno_init(&d, tenant, 64));
    struct fixture first, other, higher;
    fixture(&first, peer, 1, 1, issued, 100, false, 1);
    fixture(&other, peer, 2, 1, issued, 100, false, 1);
    fixture(&higher, peer, 1, 2, issued, 100, false, 1);
    assert(!wno_accept_manifest_verified(&d, &first.proof, peer, 0, 1000));
    struct wno_entry *entry = d.entries;
    const struct wno_receipt *r = floor_for(&d, &first.proof, 1000);
    assert(r);
    uint8_t digest[32];
    memcpy(digest, r->digest, sizeof digest);
    int64_t lease = entry->lease_deadline_us, receipt = r->receipt_deadline_us;
    for (unsigned fail_entry = 0; fail_entry < 2; fail_entry++) {
        wendy_net_memory_snapshot_t before, after;
        wendy_net_runtime_memory_snapshot(&before);
        size_t room = fail_entry ? wendy_net_memory_charge(sizeof *r + strlen(principal) + 1) : 0;
        assert(before.limit_bytes - before.current_bytes > room);
        wendy_net_memory_reservation_t reserve = {0};
        assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(), &reserve,
                                         before.limit_bytes - before.current_bytes - room,
                                         WENDY_NET_MEMORY_INTERNAL));
        assert(wno_accept_manifest_verified(&d, &other.proof, peer, 0, 1001) == 3);
        assert(d.entries == entry && d.count == 1 && d.receipt_count == 1);
        assert(r->revision == 1 && !memcmp(r->digest, digest, sizeof digest));
        assert(entry->lease_deadline_us == lease && r->receipt_deadline_us == receipt);
        wendy_net_memory_release(&reserve);
        wendy_net_runtime_memory_snapshot(&after);
        assert(after.current_bytes == before.current_bytes &&
               after.allocation_count == before.allocation_count);
    }
    wno_expire(&d, lease);
    assert(!d.entries && d.receipt_count == 1);
    wendy_net_memory_snapshot_t state;
    wendy_net_runtime_memory_snapshot(&state);
    wendy_net_memory_reservation_t reserve = {0};
    assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(), &reserve,
                                     state.limit_bytes - state.current_bytes,
                                     WENDY_NET_MEMORY_INTERNAL));
    assert(wno_accept_manifest_verified(&d, &higher.proof, peer, 0, lease + 1) == 3);
    assert(!d.entries && d.receipt_count == 1 && r->revision == 1 &&
           r->receipt_deadline_us == receipt && !memcmp(r->digest, digest, sizeof digest));
    wendy_net_memory_release(&reserve);
    assert(!wno_accept_manifest_verified(&d, &higher.proof, peer, 0, lease + 1));
    assert(d.entries->revision == 2 && r->revision == 2);
    wno_deinit(&d);
    ledger_empty();
}
static void compact_operator_handoff(const struct wendy_pki_operator_peer *identity)
{
#if WN_ROUTE_HANDOFF_ENABLED
    struct wno_directory d;
    struct wendy_pki_operator_peer peer = *identity;
    peer.issuer_not_before = peer.signing_not_before = issued / 1000 - 100;
    peer.spki_size = 1;
    peer.spki[0] = 42;
    assert(!wno_init(&d, tenant, 64));
    wno_refresh_route_policy(&d, issued / 1000, 1000, false);
    struct fixture f;
    fixture_sequence = 5;
    fixture(&f, &peer, 1, 1, issued, 60000, false, 1);
    assert(!wno_accept_manifest_verified(&d, &f.proof, &peer, 0, 1000));
    uint8_t address[16];
    memcpy(address, f.proof.address, 16);
    int64_t original = d.entries->lease_deadline_us;
    fixture_sequence = 6;
    fixture(&f, &peer, 1, 2, issued, 60000, false, 1);
    assert(!wno_accept_manifest_verified(&d, &f.proof, &peer, 0, 2000));
    assert(wno_authorizes(&d, address, 1001, 5, 2000) && wno_authorizes(&d, address, 1001, 6, 2000));
    assert(d.entries->handoff->prior.deadline_us == original);
    struct wn_origin pending;
    uint8_t projected[16];
    assert(wno_pending_handoff(&d, 0, 2000, projected, &pending) && pending.seqno == 6);
    assert(wno_handoff_request_needed(&d, address, &pending, 2000));
    wno_handoff_requested(&d, address, &pending, 2000);
    assert(!wno_handoff_request_needed(&d, address, &pending, 2000));
    fixture(&f, &peer, 1, 3, issued + 1, 60000, false, 1);
    assert(!wno_accept_manifest_verified(&d, &f.proof, &peer, 0, 2001));
    assert(!wno_handoff_request_needed(&d, address, &pending, 2001));
    assert(wno_authorizes(&d, address, 1001, 5, 2001) &&
           d.entries->handoff->prior.origin.seqno == 5 &&
           d.entries->handoff->prior.deadline_us == original);
    int64_t receipt = d.receipts->receipt_deadline_us, lease = d.entries->lease_deadline_us;
    struct wendy_pki_operator_peer wrong = peer;
    wrong.leaf_hash[0] ^= 1;
    assert(wno_accept_manifest_verified(&d, &f.proof, &wrong, 0, 2001) < 0);
    assert(d.entries->lease_deadline_us == lease && d.receipts->receipt_deadline_us == receipt &&
           wno_authorizes(&d, address, 1001, 5, 2001));
    /* Repeated replacements reuse one bounded tracking allocation, and keep
     * the earliest prior proof instead of chaining renewed old lifetimes. */
    struct wn_route_handoff *state = d.entries->handoff;
    size_t before_cycles = wno_memory(&d);
    for (unsigned i = 0; i < 200; i++) {
        fixture_sequence++;
        fixture(&f, &peer, 1, 4 + i, issued, 60000, false, 1);
        assert(!wno_accept_manifest_verified(&d, &f.proof, &peer, 0, 2100 + i));
        assert(d.entries->handoff == state && wno_memory(&d) == before_cycles &&
               state->prior.origin.seqno == 5 && state->prior.deadline_us == original);
    }
    wno_refresh_route_policy(&d, peer.expires - 1, 3000, false);
    int64_t cap = d.entries->handoff->prior.path_deadline_us;
    assert(cap == 1003000);
    wno_refresh_route_policy(&d, issued / 1000, 4000, false);
    assert(d.entries->handoff->prior.path_deadline_us == cap);
    assert(wno_authorizes(&d, address, 1001, 5, cap - 1));
    assert(!wno_authorizes(&d, address, 1001, 5, cap));
    lease = d.entries->lease_deadline_us;
    receipt = d.receipts->receipt_deadline_us;
    assert(wno_accept_manifest_verified(&d, &f.proof, &peer, 0, cap) == 1);
    assert(d.entries->lease_deadline_us == lease && d.receipts->receipt_deadline_us == receipt);
    wno_refresh_route_policy(&d, peer.expires, cap, false);
    assert(!wno_route_signature_current(d.entries) && !wno_authorizes(&d, address, 1001, fixture_sequence, cap));
    wno_deinit(&d);
    ledger_empty();

    /* A newly observed shorter current selected path makes both signed
     * intervals unusable immediately, not merely at its future NotAfter. */
    assert(!wno_init(&d, tenant, 64));
    wno_refresh_route_policy(&d, issued / 1000, 1000, false);
    fixture_sequence = 5;
    fixture(&f, &peer, 1, 1, issued, 60000, false, 1);
    assert(!wno_accept_manifest_verified(&d, &f.proof, &peer, 0, 1000));
    fixture_sequence++;
    fixture(&f, &peer, 1, 2, issued, 60000, false, 1);
    assert(!wno_accept_manifest_verified(&d, &f.proof, &peer, 0, 2000));
    lease = d.entries->lease_deadline_us;
    receipt = d.receipts->receipt_deadline_us;
    d.entries->claim_expires = issued / 1000 + 30;
    wno_refresh_route_policy(&d, issued / 1000, 3000, false);
    assert(!wno_authorizes(&d, address, 1001, 5, 3000) &&
           !wno_authorizes(&d, address, 1001, 6, 3000) &&
           d.entries->handoff->current_verified && !d.entries->handoff->has_prior);
    assert(d.entries->lease_deadline_us == lease && d.receipts->receipt_deadline_us == receipt);
    d.entries->claim_expires = peer.expires;
    wno_refresh_route_policy(&d, issued / 1000, 4000, false);
    assert(wno_authorizes(&d, address, 1001, 6, 4000) &&
           !wno_authorizes(&d, address, 1001, 5, 4000));
    wno_deinit(&d);
    ledger_empty();
    fixture_sequence = 5;
#endif
}
int main(void)
{
    assert(!wendy_pki_crypto_init() && wendy_net_runtime_memory_open());
    struct wendy_pki_operator_peer peer = {.not_before = 1800000100,
                                           .signing_not_before = 1799999000,
                                           .issuer_not_before = 1800000100,
                                           .expires = 1800003600};
    strcpy(peer.principal, principal);
    memset(peer.leaf_hash, 0x52, sizeof peer.leaf_hash);
    compact_operator_handoff(&peer);
    lifecycle(&peer);
    dynamic_floors(&peer);
    active_capacity(&peer);
    short_cycles(&peer);
    bounds(&peer);
    allocation_failure(&peer);
    wendy_net_runtime_memory_close();
    assert(wendy_net_runtime_memory_drained());
    puts("Operator monotonic TTL: lifecycle,144 floors,128 idle cycles,window/overflow and atomic pressure PASS");
    return 0;
}
