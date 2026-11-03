/* Ordinary native CBOR signing, route leases, replacement and RAM snapshots. */
#include "wendy_net_directory.h"
#include "wendy_pki_crypto.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WENDY_NET_MEMORY_HOST_BUDGET_TEST
/* Compile the actual directory with one allocation-failure boundary, rather
 * than failing its earlier temporary service parser allocation by accident. */
static bool fail_receipt_allocation, fail_handoff_allocation;
static void *directory_test_calloc(size_t count, size_t bytes)
{
    if ((fail_receipt_allocation && count == 1 && bytes == sizeof(struct wnd_receipt)) ||
        (fail_handoff_allocation && count == 1 && bytes == sizeof(struct wn_route_handoff)))
        return NULL;
    return wendy_net_calloc(count, bytes);
}
#define wendy_net_calloc directory_test_calloc
#include "../src/directory.c"
#undef wendy_net_calloc
#endif
static const char tenant[] = "2558fd76-afc7-466e-9613-6b715296a526";
static const char self[] = "00000000-0000-4000-8000-000000000005";
static const char peer_id[] = "00000000-0000-4000-8000-000000000004";
static int envelope_for(mbedtls_pk_context *key, const char *device, const void *body, size_t bytes,
                         char *out, size_t capacity)
{
    static const char domain[] = "wendy-local-mesh/manifest/4";
    char principal[106];
    uint8_t hash[32], signature[80];
    size_t size = 0, written = 0;
    assert(wn_principal(tenant, device, principal) == 105);
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    const uint8_t principal_size[] = {0, 0, 0, 105};
    assert(psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS);
    assert(psa_hash_update(&op, (const uint8_t *)domain, sizeof domain) == PSA_SUCCESS);
    assert(psa_hash_update(&op, principal_size, sizeof principal_size) == PSA_SUCCESS);
    assert(psa_hash_update(&op, (const uint8_t *)principal, 105) == PSA_SUCCESS);
    assert(psa_hash_update(&op, body, bytes) == PSA_SUCCESS);
    assert(psa_hash_finish(&op, hash, sizeof hash, &written) == PSA_SUCCESS && written == 32);
    assert(!mbedtls_pk_sign(key, MBEDTLS_MD_SHA256, hash, 32, signature, sizeof signature, &size));
    return wn_manifest_wire_write(principal, body, bytes, signature, size, out, capacity);
}
static int envelope(mbedtls_pk_context *key, const void *body, size_t bytes, char *out,
                    size_t capacity)
{
    return envelope_for(key, peer_id, body, bytes, out, capacity);
}
static int body_write(uint8_t uuid[16], struct wn_origin *origin, uint64_t revision, uint16_t port,
                      bool withdraw, char body[2048])
{
    int n = wn_manifest_app_write(uuid, origin, revision, INT64_C(1800000000000),
                                  INT64_C(1800000060000), port, 43022, body, 2048);
    assert(n > 0);
    if (withdraw) {
        /* One optional current-format boolean, after the ordinary map fields. */
        assert((uint8_t)body[0] == 0xad);
        body[0] = (char)0xae;
        struct wn_writer w = {
            .data = (uint8_t *)body, .capacity = 2048, .maximum = 2048, .size = (size_t)n};
        wn_key(&w, "withdraw");
        wn_bool(&w, true);
        n = wn_finish(&w);
        assert(n > 0);
    }
    return n;
}
/* Keep optional envelope metadata separate from the exact signed body. */
static int extra_field(char *data, int size, size_t capacity)
{
    assert(size > 0 && (uint8_t)data[0] >= 0xa0 && (uint8_t)data[0] < 0xb7);
    data[0]++;
    struct wn_writer w = {
        .data = (uint8_t *)data, .capacity = capacity, .maximum = capacity, .size = (size_t)size};
    wn_text(&w, "z");
    wn_map(&w, 1);
    wn_text(&w, "future");
    wn_array(&w, 2);
    wn_uint(&w, 42);
    wn_bool(&w, true);
    return wn_finish(&w);
}
static int optional_transports(const char *base, int size, char *out, size_t capacity)
{
    struct wn_doc d;
    assert(!wn_doc_parse(&d, base, (size_t)size));
    struct wn_writer w = {.data = (uint8_t *)out, .capacity = capacity, .maximum = capacity};
    wn_map(&w, 13);
    for (unsigned i = 1; i < d.storage[0].next; i = d.storage[i + 1].next) {
        const struct wn_token *k = &d.storage[i], *v = &d.storage[i + 1];
        wn_raw(&w, d.text + k->start, k->end - k->start);
        if (wn_doc_equal(&d, (int)i, wn_key_name("agentTransport")))
            wn_text(&w, "future-agent-v2");
        else if (wn_doc_equal(&d, (int)i, wn_key_name("appEndpoints"))) {
            wn_array(&w, 3);
            wn_map(&w, 2);
            wn_text(&w, "t");
            wn_text(&w, "future-v2");
            wn_text(&w, "p");
            wn_map(&w, 0);
            wn_map(&w, 2);
            wn_text(&w, "t");
            wn_text(&w, "tls-v1");
            wn_text(&w, "p");
            wn_uint(&w, 43022);
            wn_map(&w, 2);
            wn_text(&w, "t");
            wn_text(&w, "quic-v1");
            wn_text(&w, "p");
            wn_uint(&w, 43023);
        } else
            wn_raw(&w, d.text + v->start, v->end - v->start);
    }
    return wn_finish(&w);
}
static void future_fields(mbedtls_pk_context *key, const struct wendy_pki_mesh_peer *peer,
                          uint8_t uuid[16], struct wn_origin *origin)
{
    struct wnd_directory d;
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, peer));
    char body[2048], wire[4096];
    int n = body_write(uuid, origin, 7, 5054, false, body);
    n = extra_field(body, n, sizeof body);
    assert(n > 0);
    int size = envelope(key, body, (size_t)n, wire, sizeof wire);
    size = extra_field(wire, size, sizeof wire);
    assert(size > 0 && !wnd_accept(&d, wire, (size_t)size, INT64_C(1800000000000), 100));
    assert(d.entries->revision == 7 && d.entries->manifest.agent_mtls &&
           d.entries->manifest.tls_app_port == 43022);
    /* A same-revision envelope-only change is harmless. Its signed body and
     * replay binding are unchanged, so the directory must not diverge. */
    wire[size - 1] = (char)0xf4;
    assert(!wnd_accept(&d, wire, (size_t)size, INT64_C(1800000000000), 100));
    /* Unknown body fields remain authenticated, never stripped/re-encoded. */
    struct wn_doc doc;
    assert(!wn_doc_parse_array_view(&doc, wire, (size_t)size, sizeof wire, "s"));
    int at = wn_doc_member(&doc, 0, "body");
    assert(at > 0);
    size_t end = doc.tokens[at].end;
    wire[end - 1] = (char)0xf4;
    assert(wnd_accept(&d, wire, (size_t)size, INT64_C(1800000000000), 100) < 0);
    char base[2048];
    n = body_write(uuid, origin, 8, 5054, false, base);
    n = optional_transports(base, n, body, sizeof body);
    assert(n > 0);
    size = envelope(key, body, (size_t)n, wire, sizeof wire);
    assert(size > 0 && !wnd_accept(&d, wire, (size_t)size, INT64_C(1800000000000), 100));
    assert(d.entries->revision == 8 && !d.entries->manifest.agent_mtls &&
           !d.entries->manifest.agent_port && d.entries->manifest.tls_app_port == 43022 &&
           d.entries->manifest.quic_app_port == 43023);
    uint8_t address[16];
    wn_address(uuid, address);
    assert(wnd_authorizes(&d, address, origin->router_id, origin->seqno, 100));
    wnd_deinit(&d);
}
static int duration_body(uint8_t uuid[16], struct wn_origin *origin, uint64_t revision,
                         int64_t issued, int64_t lifetime, bool withdraw, char body[2048])
{
    int n = wn_manifest_app_write(uuid, origin, revision, issued, issued + lifetime, 5054, 43022,
                                  body, 2048);
    assert(n > 0);
    if (withdraw) {
        body[0]++;
        struct wn_writer w = {.data = (uint8_t *)body, .capacity = 2048,
                               .maximum = 2048, .size = (size_t)n};
        wn_key(&w, "withdraw");
        wn_bool(&w, true);
        n = wn_finish(&w);
        assert(n > 0);
    }
    return n;
}
static void monotonic_lifetime(mbedtls_pk_context *key, const struct wendy_pki_mesh_peer *identity,
                               uint8_t uuid[16], struct wn_origin *origin)
{
    struct wnd_directory d;
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, identity));
    size_t empty = wnd_memory(&d);
    char body[2048], wire[4096], resigned[4096];
    const int64_t issued = INT64_C(1800000000000), start = 1000000, span = 100000;
    int n = duration_body(uuid, origin, 1, issued, 100, false, body);
    int size = envelope(key, body, (size_t)n, wire, sizeof wire);
    assert(size > 0 && !wnd_accept(&d, wire, (size_t)size, 0, start));
    const struct wnd_receipt *floor = wnd_receipt_find(&d, uuid, start);
    assert(floor && floor->revision == 1 && floor->receipt_deadline_us == start + 10 * span);
    assert(d.entries->deadline_us == start + span && d.entries->lease_deadline_us == start + span);
    assert(wnd_next_deadline(&d, start) == start + span);
    assert(d.entries->manifest.certificate_not_before == identity->signing_not_before &&
           d.entries->manifest.certificate_issuer_not_before == identity->issuer_not_before &&
           d.entries->manifest.certificate_expires == identity->expires);
    struct wendy_pki_mesh_peer renewed = *identity;
    renewed.not_before = (time_t)(issued / 1000) + 100;
    renewed.issuer_not_before = identity->issuer_not_before;
    renewed.signing_not_before = (time_t)(issued / 1000) + 10;
    renewed.expires += 100;
    assert(!wnd_identity(&d, &renewed));
#if WN_ROUTE_HANDOFF_ENABLED
    assert(!d.entries->deadline_us && d.entries->handoff->current_verified);
#else
    assert(d.entries->deadline_us == start + span);
#endif
    int again = envelope(key, body, (size_t)n, resigned, sizeof resigned);
    assert(again > 0);
#if WN_ROUTE_HANDOFF_ENABLED
    assert(wnd_accept(&d, resigned, (size_t)again, INT64_MAX, start + 1) < 0);
#else
    assert(!wnd_accept(&d, resigned, (size_t)again, INT64_MAX, start + 1));
#endif
    assert(d.entries->lease_deadline_us == start + span &&
           floor->receipt_deadline_us == start + 10 * span);
#if WN_ROUTE_HANDOFF_ENABLED
    assert(!d.entries->deadline_us &&
           d.entries->manifest.certificate_not_before == renewed.signing_not_before &&
           d.entries->handoff->current.signing_not_before == identity->signing_not_before);
#else
    assert(d.entries->deadline_us == start + span &&
           d.entries->manifest.certificate_not_before == identity->signing_not_before);
#endif
    /* Renew the key view again for a later new revision's signed interval. */
    renewed.signing_not_before = (time_t)(issued / 1000) - 1;
    assert(!wnd_identity(&d, &renewed));
    wnd_expire(&d, start + span);
    assert(!d.entries->manifest.revision && !d.entries->manifest.agent_port &&
           !d.entries->deadline_us && !d.entries->revision);
    assert(d.receipt_count == 1 && wnd_next_deadline(&d, start + span) == start + 10 * span);
    size_t receipt_only = wnd_memory(&d);
    /* A's payload expired. B reconnects and re-signs the same record. Its
     * compact floor survives the transport and never starts another TTL. */
    assert(wnd_accept(&d, resigned, (size_t)again, -1, start + span + 1) == 1);
    assert(!d.entries->manifest.revision && wnd_memory(&d) == receipt_only);
    assert(floor->receipt_deadline_us == start + 10 * span);
    n = duration_body(uuid, origin, 2, issued, 100, true, body);
    size = envelope(key, body, (size_t)n, wire, sizeof wire);
    int64_t newer = start + 2 * span;
    assert(size > 0 && !wnd_accept(&d, wire, (size_t)size, INT64_MAX, newer));
    floor = wnd_receipt_find(&d, uuid, newer);
    assert(floor->withdrawn && floor->receipt_deadline_us == newer + 10 * span);
    assert(!d.entries->deadline_us && d.entries->lease_deadline_us == newer + span);
    assert(d.entries->manifest.certificate_not_before == renewed.signing_not_before &&
           d.entries->manifest.certificate_issuer_not_before == renewed.issuer_not_before &&
           d.entries->manifest.certificate_expires == renewed.expires);
    struct wne_cache endpoints = {0};
    struct wnd_manifest projection = d.entries->manifest;
    assert(!wne_update(&endpoints, &projection, d.entries->body_hash,
                       d.entries->lease_deadline_us, newer));
    assert(endpoints.entries->certificate_not_before == renewed.signing_not_before &&
           endpoints.entries->certificate_issuer_not_before == renewed.issuer_not_before &&
           endpoints.entries->certificate_expires == renewed.expires);
    projection.certificate_not_before++;
    projection.certificate_expires++;
    assert(!wne_update(&endpoints, &projection, d.entries->body_hash,
                       d.entries->lease_deadline_us + 1, newer));
    assert(endpoints.entries->certificate_not_before == renewed.signing_not_before &&
           endpoints.entries->certificate_issuer_not_before == renewed.issuer_not_before &&
           endpoints.entries->certificate_expires == renewed.expires);
    wne_reap(&endpoints, newer + span);
    assert(!endpoints.entries && !endpoints.count);
    wnd_expire(&d, newer + span);
    assert(!d.entries->manifest.revision && d.receipt_count == 1);
    assert(wnd_accept(&d, wire, (size_t)size, 0, newer + span + 1) == 1);
    wnd_expire(&d, newer + 10 * span);
    assert(!d.receipt_count && !d.receipts && wnd_memory(&d) == empty);
    /* The 10x floor is intentionally forgotten; this can be a first receipt. */
    assert(!wnd_accept(&d, resigned, (size_t)again, 0, newer + 10 * span));
    assert(d.entries->revision == 1);
    int64_t now = newer + 20 * span;
    for (uint64_t revision = 3; revision < 103; revision++) {
        n = duration_body(uuid, origin, revision, issued, 1, false, body);
        size = envelope(key, body, (size_t)n, wire, sizeof wire);
        assert(size > 0 && !wnd_accept(&d, wire, (size_t)size, revision & 1 ? 0 : INT64_MAX, now));
        assert(d.entries->manifest.revision == revision && d.receipt_count == 1);
        wnd_expire(&d, now + 1000);
        assert(!d.entries->manifest.revision && !d.entries->deadline_us);
        assert(wnd_accept(&d, wire, (size_t)size, -1, now + 1001) == 1);
        wnd_expire(&d, now + 10000);
        assert(!d.receipts && !d.receipt_count && wnd_memory(&d) == empty);
        now += 20000;
    }
    /* The accepted path's NotBefore/NotAfter window is independent of UTC. */
    struct wendy_pki_mesh_peer bounded = *identity;
    bounded.signing_not_before = (time_t)(issued / 1000);
    bounded.not_before = bounded.signing_not_before + 100;
    bounded.issuer_not_before = bounded.not_before;
    assert(!wnd_identity(&d, &bounded));
    n = duration_body(uuid, origin, 200, issued - 1, 100, false, body);
    size = envelope(key, body, (size_t)n, wire, sizeof wire);
    assert(size > 0 && wnd_accept(&d, wire, (size_t)size, 0, now) < 0);
    n = duration_body(uuid, origin, 200, (int64_t)bounded.expires * 1000 - 1, 100, false, body);
    size = envelope(key, body, (size_t)n, wire, sizeof wire);
    assert(size > 0 && wnd_accept(&d, wire, (size_t)size, 0, now) < 0);
    n = duration_body(uuid, origin, 201, issued, 900000, false, body);
    size = envelope(key, body, (size_t)n, wire, sizeof wire);
    assert(size > 0 && wnd_accept(&d, wire, (size_t)size, 0, INT64_MAX - 8999999999) < 0);
    wnd_deinit(&d);
}
static void dynamic_receipts(mbedtls_pk_context *key, const struct wendy_pki_mesh_peer *identity)
{
    struct wnd_directory d;
    assert(!wnd_init(&d, tenant, self));
    char body[2048], wire[4096], first[4096];
    uint8_t first_device[16] = {0};
    int first_size = 0;
    int64_t start = 1000000, mono = start;
    /* Nine batches turn over the bounded 128-entry active/key cache while all
     * 144 dynamic compact receipts remain inside their first 10x lifetime. */
    for (unsigned batch = 0; batch < 9; batch++) {
        for (unsigned i = 0; i < 16; i++) {
            unsigned number = batch * 16 + i + 16;
            struct wendy_pki_mesh_peer peer = *identity;
            snprintf(peer.device, sizeof peer.device, "00000000-0000-4000-8000-%012x", number);
            uint8_t device[16];
            assert(!wn_uuid_parse(peer.device, device) && !wnd_identity(&d, &peer));
            struct wn_origin origin = {.router_id = number + 1, .seqno = 1};
            int n = duration_body(device, &origin, 1, INT64_C(1800000000000), 100, false, body);
            int size = envelope_for(key, peer.device, body, (size_t)n, wire, sizeof wire);
            assert(size > 0 && !wnd_accept(&d, wire, (size_t)size, 0, mono));
            if (!batch && !i) {
                memcpy(first, wire, (size_t)size);
                first_size = size;
                memcpy(first_device, device, 16);
            }
        }
        wnd_expire(&d, mono + 100000);
        for (const struct wnd_entry *e = d.entries; e; e = e->next)
            assert(!e->manifest.revision && !e->manifest.agent_port && !e->deadline_us);
        mono += 101000;
    }
    assert(d.receipt_count == 144 && d.count <= WND_ORIGINS_MAX);
    const struct wnd_receipt *floor = wnd_receipt_find(&d, first_device, mono);
    assert(floor && floor->revision == 1);
    size_t count = d.count, bytes = wnd_memory(&d);
    assert(wnd_accept(&d, first, (size_t)first_size, INT64_MAX, mono) == 1);
    assert(d.count == count && wnd_memory(&d) == bytes && d.receipt_count == 144);
    wnd_expire(&d, start + 2000000);
    assert(!d.receipt_count && !d.receipts && wnd_next_deadline(&d, start + 2000000) == INT64_MAX);
    wnd_deinit(&d);
}
#ifdef WENDY_NET_MEMORY_HOST_BUDGET_TEST
static void allocation_failure(mbedtls_pk_context *key,
                               const struct wendy_pki_mesh_peer *identity, uint8_t device[16],
                               struct wn_origin *origin)
{
    struct wnd_directory d;
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, identity));
    char body[2048], wire[4096];
    int n = duration_body(device, origin, 1, INT64_C(1800000000000), 100, false, body);
    int size = envelope(key, body, (size_t)n, wire, sizeof wire);
    size_t before = wnd_memory(&d);
    fail_receipt_allocation = true;
    assert(wnd_accept(&d, wire, (size_t)size, 0, 1) == 3);
    fail_receipt_allocation = false;
    assert(wnd_memory(&d) == before && !d.receipts && !d.receipt_count &&
           !d.entries->manifest.revision && d.count == 1);
    wendy_net_memory_snapshot_t memory;
    wendy_net_runtime_memory_snapshot(&memory);
    wendy_net_memory_reservation_t full = {0};
    assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(), &full,
                                    memory.limit_bytes - memory.current_bytes,
                                    WENDY_NET_MEMORY_INTERNAL));
    struct wendy_pki_mesh_peer another = *identity;
    strcpy(another.device, "00000000-0000-4000-8000-000000000006");
    assert(wnd_identity(&d, &another) == 3 && d.count == 1 && wnd_memory(&d) == before);
    wendy_net_memory_release(&full);
    assert(!wnd_accept(&d, wire, (size_t)size, 0, 1) && d.receipt_count == 1);
    int64_t deadline = d.receipts->receipt_deadline_us;
    wendy_net_runtime_memory_snapshot(&memory);
    assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(), &full,
                                    memory.limit_bytes - memory.current_bytes,
                                    WENDY_NET_MEMORY_INTERNAL));
    /* Total pressure can defer the existing temporary service parser before
     * receipt lookup; that bounded result must not change the retained clock. */
    assert(wnd_accept(&d, wire, (size_t)size, 0, 2) == 4);
    assert(d.receipts->receipt_deadline_us == deadline);
    wendy_net_memory_release(&full);
    /* At cache pressure, key allocation can succeed but the replacement entry
     * allocation can still fail. No victim or compact floor may be lost. */
    for (unsigned i = 0; i < WND_ORIGINS_MAX - 1; i++) {
        struct wendy_pki_mesh_peer cached = *identity;
        snprintf(cached.device, sizeof cached.device, "00000000-0000-4000-8000-%012x", i + 16);
        assert(!wnd_identity(&d, &cached));
    }
    assert(d.count == WND_ORIGINS_MAX);
    struct wnd_entry *head = d.entries;
    struct wnd_receipt *floor = d.receipts;
    uint64_t serial = d.key_serial;
    unsigned keys = d.key_count;
    before = wnd_memory(&d);
    wendy_net_runtime_memory_snapshot(&memory);
    size_t key_room = wendy_net_memory_charge(identity->spki_size);
    assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(), &full,
                                    memory.limit_bytes - memory.current_bytes - key_room,
                                    WENDY_NET_MEMORY_INTERNAL));
    strcpy(another.device, "00000000-0000-4000-8000-00000000ffff");
    assert(wnd_identity(&d, &another) == 3 && d.entries == head && d.receipts == floor &&
           d.key_serial == serial && d.key_count == keys && d.count == WND_ORIGINS_MAX &&
           wnd_memory(&d) == before);
    wendy_net_memory_release(&full);
    assert(!wnd_identity(&d, &another) && d.count == WND_ORIGINS_MAX && d.receipts == floor);
    wnd_deinit(&d);
}
#endif
static int64_t handoff_date_offset, handoff_duration_ms = 60000;
static int handoff_admit(struct wnd_directory *d, mbedtls_pk_context *key, uint8_t uuid[16],
                         struct wn_origin origin, uint64_t revision, uint16_t port,
                         bool withdraw, unsigned future, int64_t now)
{
    char body[2048], wire[4096];
    int n = wn_manifest_app_write(uuid, &origin, revision,
        INT64_C(1800000000000) + handoff_date_offset,
        INT64_C(1800000000000) + handoff_duration_ms + handoff_date_offset, port, 43022, body, sizeof body);
    assert(n > 0);
    if (withdraw) {
        body[0]++;
        struct wn_writer writer = {.data = (uint8_t *)body, .capacity = sizeof body,
            .maximum = sizeof body, .size = (size_t)n};
        wn_key(&writer, "withdraw");
        wn_bool(&writer, true);
        n = wn_finish(&writer);
    }
    if (future) {
        n = extra_field(body, n, sizeof body);
        if (future == 2)
            body[n - 1] = (char)0xf4;
    }
    int bytes = envelope(key, body, (size_t)n, wire, sizeof wire);
    assert(bytes > 0);
    int result = wnd_accept(d, wire, (size_t)bytes, INT64_MAX, now);
    /* This format fixture models a successful portable checkpoint. Deferred
     * checkpoint behavior is separately exercised by the routing controller. */
    if (!result)
        d->entries->pending_receipt = false;
    return result;
}
static void compact_handoff(mbedtls_pk_context *key, const struct wendy_pki_mesh_peer *identity,
                             uint8_t uuid[16])
{
#if WN_ROUTE_HANDOFF_ENABLED
    struct wnd_directory d;
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, identity));
    wnd_refresh_route_policy(&d, 1800000000, 1000, false);
    struct wn_origin route = {77, 10}, pending;
    uint8_t address[16], projected[16];
    wn_address(uuid, address);
#ifdef WENDY_NET_MEMORY_HOST_BUDGET_TEST
    size_t before_failure = wnd_memory(&d);
    fail_handoff_allocation = true;
    assert(handoff_admit(&d, key, uuid, route, 1, 5054, false, 0, 1000) == 3);
    assert(!d.receipts && !d.entries->handoff && wnd_memory(&d) == before_failure);
    fail_handoff_allocation = false;
#endif
    assert(!handoff_admit(&d, key, uuid, route, 1, 5054, false, 0, 1000));
    d.entries->pending_receipt = true;
    struct wn_origin uncommitted_next = route;
    uncommitted_next.seqno++;
    assert(!handoff_admit(&d, key, uuid, uncommitted_next, 2, 5054, false, 0, 1100));
    assert(!wnd_pending_handoff(&d, 0, 1100, projected, &pending));
    wnd_deinit(&d);
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, identity));
    wnd_refresh_route_policy(&d, 1800000000, 1000, false);
    assert(!handoff_admit(&d, key, uuid, route, 1, 5054, false, 0, 1000));
    int64_t first_deadline = d.entries->lease_deadline_us;
    route.seqno++;
    assert(!handoff_admit(&d, key, uuid, route, 2, 5054, false, 0, 2000));
    assert(wnd_authorizes(&d, address, 77, 10, 2000) && wnd_authorizes(&d, address, 77, 11, 2000));
    assert(wnd_pending_handoff(&d, 0, 2000, projected, &pending) && pending.seqno == 11);
    assert(!memcmp(address, projected, 16) && !wnd_pending_handoff(&d, 1, 2000, projected, &pending));
    /* A new publication may refresh only dates/revision while the same Babel
     * sequence is pending. It must not discard or chain the original proof. */
    wnd_handoff_requested(&d, address, &route, 2000);
    d.entries->pending_receipt = true;
    handoff_date_offset = 1;
    assert(!handoff_admit(&d, key, uuid, route, 3, 5054, false, 0, 2500));
    handoff_date_offset = 0;
    assert(!wnd_handoff_request_needed(&d, address, &route, 2500));
    assert(wnd_authorizes(&d, address, 77, 10, 2500) &&
           d.entries->handoff->prior.deadline_us == first_deadline);
    route.seqno++;
    d.entries->pending_receipt = true; /* Preserve the earlier committed prior. */
    assert(!handoff_admit(&d, key, uuid, route, 4, 5054, false, 0, 3000));
    assert(wnd_authorizes(&d, address, 77, 10, 3000) && !wnd_authorizes(&d, address, 77, 11, 3000));
    assert(d.entries->handoff->prior.deadline_us == first_deadline);
    assert(wnd_handoff_request_needed(&d, address, &route, 3000));
    wnd_handoff_requested(&d, address, &route, 3000);
    assert(!wnd_handoff_request_needed(&d, address, &route, 3000));
    assert(!handoff_admit(&d, key, uuid, route, 4, 5054, false, 0, 4000));
    assert(!wnd_handoff_request_needed(&d, address, &route, 4000));
    struct wn_origin stale = {77, 11};
    assert(!wnd_complete_handoff(&d, address, &stale, 4000));
    assert(wnd_complete_handoff(&d, address, &route, 4000));
    assert(!wnd_authorizes(&d, address, 77, 10, 4000));
    route.seqno++;
    assert(!handoff_admit(&d, key, uuid, route, 5, 5054, false, 1, 5000));
    assert(!wnd_pending_handoff(&d, 0, 5000, projected, &pending));
    route.seqno++;
    assert(!handoff_admit(&d, key, uuid, route, 6, 5054, false, 1, 6000));
    assert(wnd_authorizes(&d, address, 77, 13, 6000));
    route.seqno++;
    assert(!handoff_admit(&d, key, uuid, route, 7, 5054, false, 2, 7000));
    assert(!wnd_pending_handoff(&d, 0, 7000, projected, &pending));
    route.seqno++;
    assert(!handoff_admit(&d, key, uuid, route, 8, 5055, false, 2, 8000));
    assert(!wnd_pending_handoff(&d, 0, 8000, projected, &pending));
    route.router_id++;
    route.seqno++;
    assert(!handoff_admit(&d, key, uuid, route, 9, 5055, false, 2, 9000));
    assert(!wnd_pending_handoff(&d, 0, 9000, projected, &pending));
    route.seqno++;
    size_t before_withdraw = wnd_memory(&d);
#ifdef WENDY_NET_MEMORY_HOST_BUDGET_TEST
    fail_handoff_allocation = true;
#endif
    assert(!handoff_admit(&d, key, uuid, route, 10, 5055, true, 2, 10000));
#ifdef WENDY_NET_MEMORY_HOST_BUDGET_TEST
    fail_handoff_allocation = false;
#endif
    assert(!d.entries->handoff && wnd_memory(&d) == before_withdraw - sizeof(struct wn_route_handoff));
#ifdef WENDY_NET_MEMORY_HOST_BUDGET_TEST
    fail_handoff_allocation = true;
#endif
    assert(!handoff_admit(&d, key, uuid, route, 11, 5055, true, 2, 10001));
#ifdef WENDY_NET_MEMORY_HOST_BUDGET_TEST
    fail_handoff_allocation = false;
#endif
    assert(!d.entries->handoff && d.receipts->revision == 11);
    assert(!wnd_pending_handoff(&d, 0, 10000, projected, &pending));
    assert(!wnd_authorizes(&d, address, route.router_id, route.seqno, 10000));
    wnd_deinit(&d);

    /* An independently valid retained proof survives a pending intermediate
     * whose longer signed window no longer fits a newly shortened path. */
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, identity));
    wnd_refresh_route_policy(&d, 1800000000, 1000, false);
    route = (struct wn_origin){79, 30};
    assert(!handoff_admit(&d, key, uuid, route, 1, 5054, false, 0, 1000));
    first_deadline = d.entries->lease_deadline_us;
    route.seqno++;
    handoff_duration_ms = 300000;
    assert(!handoff_admit(&d, key, uuid, route, 2, 5054, false, 0, 2000));
    assert(wnd_authorizes(&d, address, 79, 30, 2000));
    struct wendy_pki_mesh_peer shorter = *identity;
    shorter.expires = 1800000120;
    assert(!wnd_identity(&d, &shorter));
    wnd_cache_route_policy(&d, 1800000000, 2500, false);
    handoff_duration_ms = 100000;
    assert(!handoff_admit(&d, key, uuid, route, 3, 5054, false, 0, 3000));
    assert(wnd_authorizes(&d, address, 79, 30, 3000) &&
           d.entries->handoff->prior.deadline_us == first_deadline);
    handoff_duration_ms = 60000;
    wnd_deinit(&d);

    /* With NO replacement body, a shorter current selected path immediately
     * makes the signed interval invalid, even before that path expires. A
     * later valid same-key path can re-evaluate CURRENT without a new body. */
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, identity));
    wnd_refresh_route_policy(&d, 1800000000, 1000, false);
    route = (struct wn_origin){80, 40};
    assert(!handoff_admit(&d, key, uuid, route, 1, 5054, false, 0, 1000));
    route.seqno++;
    assert(!handoff_admit(&d, key, uuid, route, 2, 5054, false, 0, 2000));
    int64_t unchanged_lease = d.entries->lease_deadline_us;
    int64_t unchanged_floor = d.receipts->receipt_deadline_us;
    shorter.expires = 1800000030;
    assert(!wnd_identity(&d, &shorter));
    wnd_refresh_route_policy(&d, 1800000000, 3000, false);
    assert(!wnd_authorizes(&d, address, 80, 40, 3000) &&
           !wnd_authorizes(&d, address, 80, 41, 3000) &&
           d.entries->handoff->current_verified && !d.entries->handoff->has_prior);
    assert(d.entries->lease_deadline_us == unchanged_lease &&
           d.receipts->receipt_deadline_us == unchanged_floor);
    assert(!wnd_identity(&d, identity));
    wnd_refresh_route_policy(&d, 1800000000, 4000, false);
    assert(wnd_authorizes(&d, address, 80, 41, 4000) &&
           !wnd_authorizes(&d, address, 80, 40, 4000));
    struct wendy_pki_mesh_peer later_leaf = *identity;
    later_leaf.signing_not_before = 1800000010;
    assert(!wnd_identity(&d, &later_leaf));
    wnd_refresh_route_policy(&d, 1800000050, 5000, false);
    assert(!wnd_authorizes(&d, address, 80, 41, 5000) &&
           d.entries->handoff->current_verified);
    assert(!wnd_identity(&d, identity));
    wnd_refresh_route_policy(&d, 1800000050, 6000, false);
    assert(wnd_authorizes(&d, address, 80, 41, 6000));
    wnd_deinit(&d);

    /* A longer newly selected same-key path cannot replace an ORIGINAL
     * selected-path NotAfter. A trusted forward clock jump revokes it now,
     * and a later backward anchor cannot restore the pinned monotonic cap. */
    struct wendy_pki_mesh_peer original_short = *identity;
    original_short.expires = 1800000030;
    handoff_duration_ms = 10000;
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, &original_short));
    wnd_refresh_route_policy(&d, 1800000000, 1000, false);
    route = (struct wn_origin){81, 50};
    assert(!handoff_admit(&d, key, uuid, route, 1, 5054, false, 0, 1000));
    route.seqno++;
    assert(!handoff_admit(&d, key, uuid, route, 2, 5054, false, 0, 2000));
    first_deadline = d.entries->lease_deadline_us;
    int64_t original_floor = d.receipts->receipt_deadline_us;
    assert(!wnd_identity(&d, identity));
    assert(d.entries->handoff->current.not_after == original_short.expires &&
           d.entries->handoff->prior.not_after == original_short.expires);
    wnd_refresh_route_policy(&d, 1800000031, 3000, false);
    assert(!wnd_authorizes(&d, address, 81, 50, 3000) &&
           !wnd_authorizes(&d, address, 81, 51, 3000) &&
           d.entries->handoff->current.path_deadline_us <= 3000);
    wnd_refresh_route_policy(&d, 1800000000, 4000, false);
    assert(!wnd_authorizes(&d, address, 81, 51, 4000) &&
           d.entries->lease_deadline_us == first_deadline &&
           d.receipts->receipt_deadline_us == original_floor);
    wnd_deinit(&d);

    /* A new body has its own newly verified path. Its CURRENT can remain
     * eligible while the older HELD proof loses its shorter original path. */
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, &original_short));
    wnd_refresh_route_policy(&d, 1800000000, 1000, false);
    route = (struct wn_origin){82, 60};
    assert(!handoff_admit(&d, key, uuid, route, 1, 5054, false, 0, 1000));
    assert(!wnd_identity(&d, identity));
    route.seqno++;
    assert(!handoff_admit(&d, key, uuid, route, 2, 5054, false, 0, 2000));
    wnd_refresh_route_policy(&d, 1800000031, 3000, false);
    assert(wnd_authorizes(&d, address, 82, 61, 3000) &&
           !wnd_authorizes(&d, address, 82, 60, 3000));
    handoff_duration_ms = 60000;
    wnd_deinit(&d);

    /* A same-body repair under a NEW independently verified key records its
     * actual signer NotBefore, keeping the original lease/path/watermark cap. */
    struct wendy_pki_mesh_peer old = *identity;
    old.signing_not_before = 1800000000;
    old.issuer_not_before = 1790000000;
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, &old));
    wnd_refresh_route_policy(&d, 1799999990, 1000, true);
    route = (struct wn_origin){88, 10};
    assert(!handoff_admit(&d, key, uuid, route, 1, 5054, false, 0, 1000));
    route.seqno++;
    assert(!handoff_admit(&d, key, uuid, route, 2, 5054, false, 0, 1100));
    assert(wnd_authorizes(&d, address, 88, 10, 1100));
    first_deadline = d.entries->lease_deadline_us;
    int64_t receipt_until = d.receipts->receipt_deadline_us;
    struct wendy_pki_mesh_peer same_key = old;
    same_key.signing_not_before = 1799999980;
    assert(!wnd_identity(&d, &same_key));
    wnd_refresh_route_policy(&d, 1799999990, 1500, false);
    /* CURRENT re-verifies under the selected valid same-key leaf, but HELD
     * keeps its original future signer NotBefore and loses boot grace. */
    assert(wnd_authorizes(&d, address, 88, 11, 1500) &&
           !wnd_authorizes(&d, address, 88, 10, 1500));
    assert(d.entries->manifest.certificate_not_before == same_key.signing_not_before &&
           d.entries->handoff->current.signing_not_before == old.signing_not_before);
    assert(!handoff_admit(&d, key, uuid, route, 2, 5054, false, 0, 1600));
    assert(wnd_route_signature_current(d.entries) &&
           d.entries->lease_deadline_us == first_deadline &&
           d.receipts->receipt_deadline_us == receipt_until);
    assert(!wnd_identity(&d, &old));
    wnd_refresh_route_policy(&d, 1799999990, 1700, false);
    assert(!wnd_authorizes(&d, address, 88, 11, 1700) && d.entries->handoff->current_verified);
    struct wn_origin rejected = route;
    rejected.seqno++;
    assert(handoff_admit(&d, key, uuid, rejected, 3, 5054, false, 0, 1700) == 1);
    assert(d.entries->revision == 2 && d.receipts->revision == 2 &&
           d.entries->lease_deadline_us == first_deadline &&
           d.receipts->receipt_deadline_us == receipt_until);
    assert(!wnd_identity(&d, &same_key));
    wnd_refresh_route_policy(&d, 1799999990, 1800, false);
    assert(wnd_authorizes(&d, address, 88, 11, 1800));
    uint8_t generated[256], spki[128];
    int size = wendy_pki_generate_key_der(generated, sizeof generated);
    mbedtls_pk_context replacement;
    mbedtls_pk_init(&replacement);
    assert(size > 0 && !mbedtls_pk_parse_key(&replacement, generated + sizeof generated - size,
                                             (size_t)size, NULL, 0));
    int pub = mbedtls_pk_write_pubkey_der(&replacement, spki, sizeof spki);
    assert(pub > 0);
    struct wendy_pki_mesh_peer renewed = old;
    memcpy(renewed.spki, spki + sizeof spki - pub, (size_t)pub);
    renewed.spki_size = (size_t)pub;
    renewed.signing_not_before = 1799999980;
    assert(!wnd_identity(&d, &renewed));
    assert(!wnd_route_signature_current(d.entries) && !wnd_authorizes(&d, address, 88, 11, 2000));
    assert(d.entries->lease_deadline_us == first_deadline);
    assert(!handoff_admit(&d, &replacement, uuid, route, 2, 5054, false, 0, 2000));
    assert(d.entries->manifest.certificate_not_before == renewed.signing_not_before);
    assert(d.entries->lease_deadline_us == first_deadline && d.receipts->receipt_deadline_us == receipt_until);
    wnd_refresh_route_policy(&d, 1799999990, 2000, false);
    assert(wnd_authorizes(&d, address, 88, 11, 2000));
    route.seqno++;
    assert(!handoff_admit(&d, &replacement, uuid, route, 3, 5054, false, 0, 3000));
    assert(wnd_authorizes(&d, address, 88, 11, 3000));
    assert(d.entries->handoff->prior.signing_not_before == renewed.signing_not_before);
    int64_t old_cap = d.entries->handoff->prior.path_deadline_us;
    wnd_refresh_route_policy(&d, 1799999900, 4000, true);
    assert(d.entries->handoff->prior.path_deadline_us == old_cap);
    wnd_expire(&d, first_deadline);
    assert(!wnd_authorizes(&d, address, 88, 11, first_deadline));
    wnd_deinit(&d);

    /* Inactive withdrawals retain no tracker. New signer dates are committed
     * only by the adapter's explicit successfully-replaced-wire callback. */
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, &old));
    wnd_refresh_route_policy(&d, 1799999990, 1000, true);
    route = (struct wn_origin){89, 10};
    assert(!handoff_admit(&d, key, uuid, route, 1, 5054, true, 0, 1000));
    assert(!d.entries->handoff && !d.entries->deadline_us);
    first_deadline = d.entries->lease_deadline_us;
    receipt_until = d.receipts->receipt_deadline_us;
    assert(!wnd_identity(&d, &renewed));
    wnd_refresh_route_policy(&d, 1799999990, 2000, false);
    assert(!handoff_admit(&d, &replacement, uuid, route, 1, 5054, true, 0, 2000));
    assert(d.entries->manifest.certificate_not_before == old.signing_not_before);
    uint8_t digest[32];
    memcpy(digest, d.entries->body_hash, sizeof digest);
    struct wendy_pki_mesh_key invalid = d.entries->peer;
    invalid.signing_not_before = 1800000001;
    assert(!wnd_withdraw_wire_committed(&d, uuid, 1, digest, &invalid, 2000));
    assert(d.entries->manifest.certificate_not_before == old.signing_not_before &&
           d.entries->lease_deadline_us == first_deadline &&
           d.receipts->receipt_deadline_us == receipt_until);
    assert(wnd_withdraw_wire_committed(&d, uuid, 1, digest, &d.entries->peer, 2000));
    assert(d.entries->manifest.certificate_not_before == renewed.signing_not_before &&
           !d.entries->handoff && !d.entries->deadline_us &&
           d.entries->lease_deadline_us == first_deadline &&
           d.receipts->receipt_deadline_us == receipt_until);
    wnd_deinit(&d);

    /* Original selected-path monotonic expiry is pinned at first withdrawal
     * receipt. A backward certificate-clock anchor and valid new wire cannot
     * extend it by projecting the same absolute NotAfter a second time. */
    struct wendy_pki_mesh_peer close_path = *identity;
    close_path.signing_not_before = 1799999900;
    close_path.expires = 1800000060;
    assert(!wnd_init(&d, tenant, self) && !wnd_identity(&d, &close_path));
    wnd_refresh_route_policy(&d, 1800000059, 1000, false);
    route = (struct wn_origin){90, 10};
    assert(!handoff_admit(&d, key, uuid, route, 1, 5054, true, 0, 1000));
    first_deadline = d.entries->lease_deadline_us;
    assert(first_deadline == 1001000 && d.receipts->receipt_deadline_us == 600001000);
    receipt_until = d.receipts->receipt_deadline_us;
    wnd_refresh_route_policy(&d, 1800000000, 2000, false);
    assert(!handoff_admit(&d, key, uuid, route, 1, 5054, true, 0, 2000));
    memcpy(digest, d.entries->body_hash, sizeof digest);
    assert(wnd_withdraw_wire_committed(&d, uuid, 1, digest, &d.entries->peer, 2000));
    assert(d.entries->lease_deadline_us == first_deadline &&
           d.receipts->receipt_deadline_us == receipt_until);
    wnd_expire(&d, first_deadline);
    assert(!d.entries->manifest.revision && d.receipt_count == 1);
    wnd_deinit(&d);
    mbedtls_pk_free(&replacement);
#endif
}
int main(int argc, char **argv)
{
    assert(argc == 2 && !wendy_pki_crypto_init());
#ifdef WENDY_NET_MEMORY_HOST_BUDGET_TEST
    assert(wendy_net_runtime_memory_open());
#endif
    FILE *file = fopen(argv[1], "rb");
    assert(file);
    uint8_t keybytes[1024];
    size_t keysize = fread(keybytes, 1, sizeof keybytes, file);
    assert(feof(file));
    fclose(file);
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    assert(!mbedtls_pk_parse_key(&key, keybytes, keysize, NULL, 0));
    struct wendy_pki_mesh_peer peer = {.expires = 1800003600};
    memcpy(peer.device, peer_id, 37);
    uint8_t spki[128];
    int spki_size = mbedtls_pk_write_pubkey_der(&key, spki, sizeof spki);
    assert(spki_size > 0);
    memcpy(peer.spki, spki + sizeof spki - spki_size, (size_t)spki_size);
    peer.spki_size = (size_t)spki_size;
    struct wnd_directory d;
    assert(!wnd_init(&d, tenant, self));
    size_t idle = wnd_memory(&d);
    assert(!d.count && !d.entries && idle == sizeof d);
    uint8_t uuid[16], address[16];
    assert(!wn_uuid_parse(peer_id, uuid));
    wn_address(uuid, address);
    struct wn_origin origin = {.router_id = UINT64_MAX - 1, .seqno = 65535};
    compact_handoff(&key, &peer, uuid);
    future_fields(&key, &peer, uuid, &origin);
    monotonic_lifetime(&key, &peer, uuid, &origin);
    dynamic_receipts(&key, &peer);
#ifdef WENDY_NET_MEMORY_HOST_BUDGET_TEST
    allocation_failure(&key, &peer, uuid, &origin);
#endif
    char body[2048], wire[4096], old[4096];
    uint64_t revision = UINT64_C(9007199254740993);
    int n = body_write(uuid, &origin, revision, 5054, false, body);
    /* The public parser honors operation-owned token storage, too. */
    struct wn_doc doc;
    struct wn_token tokens[WN_TOKENS];
    struct wnd_manifest manifest;
    assert(!wn_doc_parse_into(&doc, body, (size_t)n, WN_MANIFEST_BODY_MAX, tokens, WN_TOKENS));
    assert(!wnd_manifest_read(&doc, 0, &manifest) && manifest.revision == revision);
    int size = envelope(&key, body, (size_t)n, wire, sizeof wire);
    assert(size > 0);
    memcpy(old, wire, (size_t)size);
    int old_size = size;
    assert(wnd_accept(&d, wire, (size_t)size, INT64_C(1800000000000), 100) == 2 && !d.count);
    assert(!wnd_identity(&d, &peer) && d.count == 1);
    assert(!wnd_accept(&d, wire, (size_t)size, INT64_C(1800000000000), 100));
    assert(wnd_authorizes(&d, address, origin.router_id, origin.seqno, 100));
    assert(!wnd_authorizes(&d, address, origin.router_id, 0, 100));
    assert(d.entries->manifest.agent_mtls && d.entries->manifest.tls_app_port == 43022);
    assert(d.entries->revision == revision);
    int64_t deadline = d.entries->deadline_us;
    assert(!wnd_accept(&d, wire, (size_t)size, INT64_C(1800000000000), 1000));
    assert(d.entries->deadline_us == deadline);
    /* A restarted service may immediately publish a new port/revision. */
    n = body_write(uuid, &origin, revision + 1, 5055, false, body);
    size = envelope(&key, body, (size_t)n, wire, sizeof wire);
    assert(size > 0 && !wnd_accept(&d, wire, (size_t)size, INT64_C(1800000000000), 100));
    assert(d.entries->manifest.agent_port == 5055 && d.entries->revision == revision + 1);
    origin.seqno = 0;
    n = body_write(uuid, &origin, revision + 2, 5055, true, body);
    size = envelope(&key, body, (size_t)n, wire, sizeof wire);
    assert(size > 0 && !wnd_accept(&d, wire, (size_t)size, INT64_C(1800000000000), 100));
    assert(!wnd_address(&d, address, 100));
    uint8_t receipts[WND_RECEIPTS_MAX];
    int saved = wnd_save(&d, receipts, sizeof receipts);
    assert(saved == 73);
    struct wnd_directory restarted;
    assert(!wnd_init(&restarted, tenant, self));
    assert(!wnd_restore(&restarted, receipts, (size_t)saved));
    assert(!wnd_address(&restarted, address, 100) && !restarted.entries &&
           restarted.receipts->revision == revision + 2);
    assert(!wnd_identity(&restarted, &peer));
    assert(wnd_accept(&restarted, old, (size_t)old_size, INT64_C(1800000000000), 100) == 1);
    assert(wnd_accept(&restarted, wire, (size_t)size, INT64_C(1800000000000), 100) == 1);
    assert(!wnd_address(&restarted, address, 100));
    assert(!wnd_accept(&d, wire, (size_t)size, INT64_C(1800000060000), 100));
    printf("Native signed directory: idle=%zu one=%zu RAM receipt=%d bytes\n", idle, wnd_memory(&d),
           saved);
    wnd_deinit(&d);
    wnd_deinit(&restarted);
    mbedtls_pk_free(&key);
#ifdef WENDY_NET_MEMORY_HOST_BUDGET_TEST
    wendy_net_runtime_memory_close();
    assert(wendy_net_runtime_memory_drained());
#endif
    return 0;
}
