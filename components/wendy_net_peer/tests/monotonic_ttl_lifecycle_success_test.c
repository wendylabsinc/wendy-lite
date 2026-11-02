/* Exercise signed v4 admission, projection, idle expiry and neighbour changes
 * together. The shared fixture supplies already authenticated certificate keys;
 * this test owns no TLS policy and never obtains time from a neighbour. */
#define main shared_router_fixture_main
#include "router_node_success_test.c"
#undef main

#ifndef TTL_TEST_COMPACT
#define TTL_TEST_COMPACT 0
#endif

struct ttl_artifact {
    struct wg_id id;
    uint8_t device[16];
    size_t size;
    char body[2048], wire[3072];
    size_t body_size;
};
static const int64_t ttl_issued = INT64_C(1800000100000);
static int ttl_publish(void *ctx, const struct wn_origin *origin, int64_t wall, int64_t mono)
{
    (void)ctx;
    (void)origin;
    (void)wall;
    (void)mono;
    return 0;
}
static int ttl_packet(void *ctx, uint64_t link, const void *bytes, size_t size)
{
    (void)ctx;
    (void)link;
    (void)bytes;
    (void)size;
    return 0;
}
static int ttl_send(void *ctx, const void *bytes, size_t size, bool control)
{
    (void)ctx;
    (void)bytes;
    (void)size;
    (void)control;
    return 0;
}
static uint64_t ttl_next_hop(void *ctx, const uint8_t device[16], uint64_t exclude)
{
    (void)ctx;
    (void)device;
    (void)exclude;
    return 1; /* A live authenticated underlay is independent of the TTL. */
}
static struct wnrs *ttl_attach(struct wnrs_node *node, uint64_t supplier)
{
    struct wnrs *s = wendy_net_calloc(1, sizeof *s);
    assert(s);
    s->node = node;
    s->identity = node->clock;
    s->link = supplier;
    s->send = ttl_send;
    assert(!wg_open(&node->pool, &s->gossip, 1));
    s->next = node->sessions;
    node->sessions = s;
    return s;
}
static struct wnrs_node *ttl_node(struct wnrs_node **owner)
{
    struct wnrs_node *node = wendy_net_calloc(1, sizeof *node);
    assert(node);
    node->owner = owner;
    node->clock.certificate_time.seconds = 1800000000;
    node->clock.certificate_time.floor = 1800000000;
    node->clock.certificate_time.monotonic_us = clock_us;
    node->clock.certificate_expires = 1800010000;
    strcpy(node->clock.tenant, tenant);
    strcpy(node->clock.device, ids[0]);
    struct wnr_config config = {.tenant = tenant,
                                .device = ids[0],
                                .router = 99,
                                .non_transit = TTL_TEST_COMPACT,
                                .endpoint_gateway = TTL_TEST_COMPACT,
                                .context = node,
                                .publish = ttl_publish,
                                .send = ttl_packet};
    assert(!wnr_init(&node->core, &config, clock_us, NULL, 0));
    if (TTL_TEST_COMPACT)
        assert(!wnd_key_limit(&node->core.directory, 8));
    assert(!wnr_start(&node->core, node_unix(node), clock_us));
    struct wg_config gossip = {.identify = wn_gossip_identify,
                               .context = node,
                               .objects = 256,
                               .pending = 64,
                               .bytes = 128 * 1024,
                               .fifo = true,
                               .known_object = known_artifact,
                               .evicted = evicted_artifact};
    assert(!wg_init(&node->pool, &gossip));
    struct wnsc_config catalog = {.tenant = tenant,
                                  .device = ids[0],
                                  .next_hop = ttl_next_hop,
                                  .catalog_bytes = 32768,
                                  .catalog_records = 64};
    assert(!wnsc_open(&node->catalog, &catalog));
    *owner = node;
    return node;
}
static void ttl_identity_path(struct wnrs_node *node, const char *device, time_t leaf_not_before,
                                time_t issuer_not_before, time_t expires)
{
    struct wendy_pki_mesh_peer peer = {
        .not_before = leaf_not_before > issuer_not_before ? leaf_not_before : issuer_not_before,
        .signing_not_before = leaf_not_before,
        .issuer_not_before = issuer_not_before,
        .expires = expires};
    uint8_t spki[128];
    int n = mbedtls_pk_write_pubkey_der(&key, spki, sizeof spki);
    assert(n > 0);
    peer.spki_size = (size_t)n;
    memcpy(peer.spki, spki + sizeof spki - n, (size_t)n);
    strcpy(peer.device, device);
    assert(!wnr_identity(&node->core, &peer, node_unix(node), clock_us));
}
static void ttl_identity(struct wnrs_node *node, const char *device)
{
    ttl_identity_path(node, device, 1800000000, 1800000000, 1800010000);
}
static void ttl_sign(struct ttl_artifact *artifact, const char *device)
{
    char principal[106];
    uint8_t signature[80];
    size_t signature_size;
    assert(wn_principal(tenant, device, principal) > 0);
    assert(!wendy_pki_mesh_sign(NULL, principal, artifact->body, artifact->body_size, signature,
                               &signature_size));
    int n = wn_manifest_wire_write(principal, artifact->body, artifact->body_size, signature,
                                   signature_size, artifact->wire, sizeof artifact->wire);
    assert(n > 0);
    artifact->size = (size_t)n;
    artifact->id.type = 1;
    assert(!wn_gossip_identify(NULL, 1, artifact->wire, artifact->size, artifact->id.hash));
}
static void ttl_reencode(struct ttl_artifact *artifact)
{
    /* P-256 signing is deterministic. Reorder only the envelope members to
     * produce distinct valid artifact bytes around the identical signed body. */
    struct wn_doc doc;
    char principal[106], wire[sizeof artifact->wire];
    const uint8_t *signature;
    size_t signature_size;
    assert(!wn_doc_parse_array_view(&doc, artifact->wire, artifact->size, WG_OBJECT_MAX, "s"));
    assert(wn_doc_string(&doc, wn_doc_member(&doc, 0, "principal"), principal,
                         sizeof principal) == 105);
    assert(!wn_doc_bytes(&doc, wn_doc_member(&doc, 0, "signature"), &signature, &signature_size));
    const struct wn_token *body = wn_doc_token(&doc, wn_doc_member(&doc, 0, "body"));
    assert(body && body->end - body->start == artifact->body_size &&
           !memcmp(doc.text + body->start, artifact->body, artifact->body_size));
    struct wn_writer writer = {
        .data = (uint8_t *)wire, .capacity = sizeof wire, .maximum = sizeof wire};
    wn_map(&writer, 3);
    wn_key(&writer, "signature");
    wn_bytes(&writer, signature, signature_size);
    wn_key(&writer, "principal");
    wn_text(&writer, principal);
    wn_key(&writer, "body");
    wn_raw(&writer, doc.text + body->start, artifact->body_size);
    int n = wn_finish(&writer);
    assert(n > 0);
    memcpy(artifact->wire, wire, (size_t)n);
    artifact->size = (size_t)n;
    assert(!wn_gossip_identify(NULL, 1, artifact->wire, artifact->size, artifact->id.hash));
}
static void ttl_proof(struct ttl_artifact *artifact, const char *device, uint64_t revision,
                       int64_t duration_ms, bool withdraw)
{
    memset(artifact, 0, sizeof *artifact);
    assert(!wn_uuid_parse(device, artifact->device));
    struct wnsc_config config = {.tenant = tenant, .device = device};
    struct wnsc_node *source = NULL;
    assert(!wnsc_open(&source, &config));
    struct wns_record service = {.port = 8080};
    strcpy(service.app, WNS_GUEST_APP_ID);
    strcpy(service.service, "temperature");
    strcpy(service.type, "_sensorlink._tcp");
    strcpy(service.instance, "room");
    assert(!wnsc_publish(source, &service, NULL, ttl_issued, 0));
    char array[512];
    int array_size = wnsc_services_write(source, array, sizeof array);
    assert(array_size > 0);
    struct wn_origin origin = {.router_id = 101, .seqno = 1};
    int n = wn_manifest_services_write(artifact->device, &origin, revision, ttl_issued,
                                       ttl_issued + duration_ms, 5054, 43022, "peer", false,
                                       array, (size_t)array_size, artifact->body,
                                       sizeof artifact->body);
    assert(n > 0);
    if (withdraw) {
        char body[2048];
        struct wn_doc doc;
        assert(!wn_doc_parse(&doc, artifact->body, (size_t)n));
        struct wn_writer writer = {
            .data = (uint8_t *)body, .capacity = sizeof body, .maximum = sizeof body};
        unsigned fields = 0;
        for (unsigned i = 1; i < doc.storage[0].next; i = doc.storage[i + 1].next)
            fields++;
        wn_map(&writer, fields + 1);
        wn_key(&writer, "withdraw");
        wn_bool(&writer, true);
        for (unsigned i = 1; i < doc.storage[0].next; i = doc.storage[i + 1].next)
            wn_raw(&writer, doc.text + doc.storage[i].start,
                   doc.storage[i + 1].end - doc.storage[i].start);
        n = wn_finish(&writer);
        assert(n > 0);
        memcpy(artifact->body, body, (size_t)n);
    }
    artifact->body_size = (size_t)n;
    /* No lease field, nonce or new version was introduced into signed bytes. */
    struct wn_doc doc;
    uint64_t version;
    assert(!wn_doc_parse(&doc, artifact->body, artifact->body_size));
    assert(!wn_doc_u64(&doc, wn_doc_member(&doc, 0, "version"), &version) && version == 4);
    assert(wn_doc_member(&doc, 0, "lease") < 0);
    ttl_sign(artifact, device);
    wnsc_close(source);
}
static const struct wnd_receipt *ttl_receipt(struct wnrs_node *node,
                                            const struct ttl_artifact *artifact)
{
    return wnd_receipt_find(&node->core.directory, artifact->device, clock_us);
}
static void ttl_verify(struct wnrs *session, const struct ttl_artifact *artifact)
{
    struct wn_doc doc;
    char principal[106];
    const uint8_t *signature;
    size_t signature_size;
    assert(!wn_doc_parse_array_view(&doc, artifact->wire, artifact->size, WG_OBJECT_MAX, "s"));
    assert(wn_doc_string(&doc, wn_doc_member(&doc, 0, "principal"), principal,
                         sizeof principal) == 105);
    assert(!wn_doc_bytes(&doc, wn_doc_member(&doc, 0, "signature"), &signature, &signature_size));
    int body = wn_doc_member(&doc, 0, "body");
    const struct wn_token *span = wn_doc_token(&doc, body);
    assert(span);
    const struct wnd_entry *identity = session->node->core.directory.entries;
    while (identity && memcmp(identity->device, artifact->device, 16))
        identity = identity->next;
    assert(identity && identity->peer.spki_size);
    /* Meet the production adapter's already-verified-worker precondition with
     * the real verifier before crossing that asynchronous completion boundary. */
    assert(!wendy_pki_mesh_verify_key(&identity->peer, principal, doc.text + span->start,
                                      span->end - span->start, signature, signature_size));
}
static void ttl_admit(struct wnrs *session, const struct ttl_artifact *artifact)
{
    ttl_verify(session, artifact);
    assert(!admit_complete(session, &artifact->id, artifact->wire, artifact->size));
}
static uint64_t ttl_want_request;
static struct wg_id ttl_want_id;
static int ttl_download_emit(void *ctx, const struct wg_message *message)
{
    (void)ctx;
    if (message->op == WG_WANT) {
        ttl_want_request = message->request;
        ttl_want_id = message->id;
    }
    return 0;
}
static int ttl_download(struct wnrs *session, const struct ttl_artifact *artifact,
                         wg_complete completion, bool verified)
{
    if (verified)
        ttl_verify(session, artifact);
    ttl_want_request = 0;
    struct wg_message message = {.id = artifact->id, .op = WG_HAVE};
    assert(!wg_receive(&session->gossip, &message, (uint64_t)clock_us / 1000,
                       ttl_download_emit, completion, session));
    for (unsigned i = 0; !ttl_want_request && i < 8; ++i)
        assert(!wg_poll(&session->gossip, (uint64_t)clock_us / 1000, ttl_download_emit, session));
    assert(ttl_want_request && !memcmp(ttl_want_id.hash, artifact->id.hash, 32));
    int result = 0;
    for (size_t at = 0; at < artifact->size; at += WG_CHUNK) {
        size_t size = artifact->size - at;
        if (size > WG_CHUNK)
            size = WG_CHUNK;
        message = (struct wg_message){.id = artifact->id,
                                       .op = WG_DATA,
                                       .request = ttl_want_request,
                                       .offset = (uint32_t)at,
                                       .total = (uint32_t)artifact->size,
                                       .data = (const uint8_t *)artifact->wire + at,
                                       .size = size};
        result = wg_receive(&session->gossip, &message, (uint64_t)clock_us / 1000,
                             ttl_download_emit, completion, session);
        assert(result == 0 || (at + size == artifact->size && result == WG_DEFER));
    }
    return result;
}
static void ttl_idle(struct wnrs_node *node)
{
    (void)wnrs_poll_effects(node);
}
static void ttl_empty_payloads(struct wnrs_node *node)
{
    assert(!node->pool.payload_bytes && !node->pool.object_count);
    assert(!node->catalog->records.count && !node->catalog->records.bytes);
    assert(!node->core.endpoints.count);
}
static void ttl_lifecycle(void)
{
    struct wnrs_node *owner = NULL, *node = ttl_node(&owner);
    struct wnrs *supplier = ttl_attach(node, 1);
    ttl_identity(node, ids[1]);
    struct ttl_artifact old, resigned, newer, withdrawal;
    const int64_t start = clock_us, duration = 100000;
    ttl_proof(&old, ids[1], 1, duration / 1000, false);
    ttl_admit(supplier, &old);
    assert(node->catalog->records.count == 1);
    assert(ttl_receipt(node, &old)->receipt_deadline_us == start + 10 * duration);
    assert(TTL_TEST_COMPACT ? node->pool.payload_bytes == 0
                           : node->pool.payload_bytes == old.size);
    /* Equal body with a distinct valid envelope is still the same claim. */
    resigned = old;
    ttl_sign(&resigned, ids[1]);
    ttl_reencode(&resigned);
    assert(memcmp(old.id.hash, resigned.id.hash, sizeof old.id.hash));
    clock_us = start + duration / 2;
    ttl_admit(supplier, &resigned);
    assert(ttl_receipt(node, &old)->receipt_deadline_us == start + 10 * duration);
    /* Reclaim to digest-only fallback before the original lease expires. */
    if (!TTL_TEST_COMPACT) {
        size_t payload = node->pool.payload_bytes;
        assert(payload && wg_reclaim(&node->pool, 1) == payload);
    }
    clock_us = start + duration;
    ttl_idle(node);
    ttl_empty_payloads(node);
    uint8_t address[16];
    wn_address(old.device, address);
    assert(!wnd_authorizes(&node->core.directory, address, 101, 1, clock_us));
    assert(ttl_receipt(node, &old));
    /* A completed unknown-origin download can still be awaiting its identity
     * when the final supplier disconnects. Release that full transient body
     * and its pending parser metadata without erasing accepted watermarks. */
    struct ttl_artifact pending;
    ttl_proof(&pending, ids[2], 1, 100, false);
    assert(!ttl_download(supplier, &pending, complete, false));
    assert(node->pending_count == 1 && node->pending && node->pool.pending_count == 1 &&
           node->pool.payload_bytes == pending.size);
    /* A new authenticated supplier cannot restart an already observed lease. */
    wnrs_close(supplier);
    assert(owner == node && !node->sessions);
    assert(!node->pending && !node->pending_count && !node->pending_bytes &&
           !node->pool.pending_count && !node->pool.payload_bytes && !node->verification);
    assert(ttl_receipt(node, &old));
    supplier = ttl_attach(node, 2);
    clock_us += 1;
    ttl_admit(supplier, &old);
    ttl_admit(supplier, &resigned);
    ttl_empty_payloads(node);
    assert(ttl_receipt(node, &old)->receipt_deadline_us == start + 10 * duration);
    ttl_proof(&newer, ids[1], 2, duration / 1000, false);
    ttl_admit(supplier, &newer);
    assert(node->catalog->records.count == 1);
    const int64_t replacement = clock_us;
    assert(ttl_receipt(node, &newer)->receipt_deadline_us == replacement + 10 * duration);
    ttl_admit(supplier, &old);
    assert(node->catalog->records.count == 1);
    ttl_proof(&withdrawal, ids[1], 3, duration / 1000, true);
    ttl_admit(supplier, &withdrawal);
    assert(!node->catalog->records.count);
    assert(ttl_receipt(node, &withdrawal)->withdrawn);
    ttl_admit(supplier, &newer);
    assert(!node->catalog->records.count);
    clock_us = replacement + duration;
    ttl_idle(node);
    ttl_empty_payloads(node);
    clock_us = replacement + 10 * duration;
    ttl_idle(node);
    assert(!ttl_receipt(node, &old));
    assert(!known_artifact(node, &withdrawal.id));
    /* Explicit product boundary: once compact history expires, relearn is valid. */
    ttl_admit(supplier, &old);
    assert(node->catalog->records.count == 1);
    wnrs_close(supplier);
    wnrs_node_reset(&owner);
    assert(!owner);
}
static void ttl_cycles(void)
{
    struct wnrs_node *owner = NULL, *node = ttl_node(&owner);
    struct wnrs *supplier = ttl_attach(node, 1);
    ttl_identity(node, ids[1]);
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    wendy_net_memory_snapshot_t baseline;
    wendy_net_runtime_memory_snapshot(&baseline);
#endif
    struct ttl_artifact artifact;
    const int64_t duration = 10000;
    for (unsigned i = 0; i < 128; ++i) {
        int64_t start = clock_us;
        ttl_proof(&artifact, ids[1], i + 1, duration / 1000, false);
        ttl_admit(supplier, &artifact);
        assert(node->catalog->records.count == 1);
        /* Large policy-clock changes cannot affect receiver-monotonic expiry. */
        node->clock.certificate_time.seconds += i & 1 ? -3600 : 3600;
        clock_us = start + duration - 1;
        ttl_idle(node);
        assert(node->catalog->records.count == 1);
        clock_us = start + duration;
        ttl_idle(node);
        ttl_empty_payloads(node);
        assert(node->core.directory.receipt_count == 1);
        assert(known_artifact(node, &artifact.id));
        clock_us = start + 10 * duration;
        ttl_idle(node);
        assert(!node->core.directory.receipt_count);
        assert(!known_artifact(node, &artifact.id));
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
        wendy_net_memory_snapshot_t after;
        wendy_net_runtime_memory_snapshot(&after);
        assert(after.current_bytes == baseline.current_bytes &&
               after.allocation_count == baseline.allocation_count && !after.failed_admissions);
#endif
        /* Reacquire the exact highest artifact through the real WG gate, not
         * only the admission helper, once its 10x receipt has expired. */
        assert(!ttl_download(supplier, &artifact, admit_complete, true));
        assert(node->catalog->records.count == 1);
        clock_us += 10 * duration;
        ttl_idle(node);
        ttl_empty_payloads(node);
        assert(!node->core.directory.receipt_count && !known_artifact(node, &artifact.id));
    }
    wnrs_close(supplier);
    wnrs_node_reset(&owner);
    assert(!owner);
}
static void ttl_dynamic_history(void)
{
    struct wnrs_node *owner = NULL, *node = ttl_node(&owner);
    struct wnrs *supplier = ttl_attach(node, 1);
    struct ttl_artifact first = {0}, artifact;
    int64_t start = clock_us;
    /* Nine groups expire their payloads between groups. One hundred forty-four
     * compact receipts coexist, exceeding both old full/compact cache limits. */
    for (unsigned group = 0; group < 9; ++group) {
        for (unsigned i = 0; i < 16; ++i) {
            char device[37];
            assert(snprintf(device, sizeof device, "00000000-0000-4000-8000-%012u",
                             100 + group * 16 + i) == 36);
            ttl_identity(node, device);
            ttl_proof(&artifact, device, 1, 100, false);
            ttl_admit(supplier, &artifact);
            if (!group && !i)
                first = artifact;
        }
        clock_us = start + (group + 1) * INT64_C(100000);
        ttl_idle(node);
        ttl_empty_payloads(node);
    }
    assert(node->core.directory.receipt_count == 144);
    const struct wnd_entry *first_identity = node->core.directory.entries;
    while (first_identity && memcmp(first_identity->device, first.device, 16))
        first_identity = first_identity->next;
    assert(!first_identity); /* Full cache turnover and compact key eviction both occurred. */
    assert(!known_artifact(node, &first.id)); /* Exercise the download completion precheck. */
    const struct wnd_receipt *first_receipt = ttl_receipt(node, &first);
    assert(first_receipt);
    const int64_t first_deadline = first_receipt->receipt_deadline_us;
    assert(!node->pending && !node->pending_count && !node->pool.pending_count &&
           !node->pool.payload_bytes);
    /* The compact watermark alone must dispose of this delayed complete body
     * before requesting its evicted identity or keeping an unverified loan. */
    assert(!ttl_download(supplier, &first, complete, false));
    assert(!node->pending && !node->pending_count && !node->pending_bytes &&
           !node->pool.pending_count && !node->pool.payload_bytes && !node->pool.object_count);
    assert(ttl_receipt(node, &first)->receipt_deadline_us == first_deadline &&
           node->core.directory.receipt_count == 144);
    char first_device[37];
    wn_uuid_format(first.device, first_device);
    ttl_identity(node, first_device);
    ttl_admit(supplier, &first);
    ttl_empty_payloads(node);
    assert(node->core.directory.receipt_count == 144);
    clock_us = start + INT64_C(2000000);
    ttl_idle(node);
    assert(!node->core.directory.receipt_count);
    wnrs_close(supplier);
    wnrs_node_reset(&owner);
    assert(!owner);
}
static void ttl_operator_lifecycle(void)
{
    if (TTL_TEST_COMPACT)
        return; /* The single-neighbour endpoint has no remote operator table. */
    struct wnrs_node *owner = NULL, *node = ttl_node(&owner);
    struct wnrs *supplier = ttl_attach(node, 1);
    struct wendy_pki_operator_peer identity = {.not_before = 1800000000,
                                               .expires = 1800010000};
    assert(snprintf(identity.principal, sizeof identity.principal,
                     "spiffe://wendy.sh/tenant/%s/operator/alice", tenant) > 0);
    memset(identity.leaf_hash, 9, sizeof identity.leaf_hash);
    uint8_t instance[16] = {1};
    uint8_t body[] = {0xa2, 0x61, 'v', 0x04, 0x61, 'r', 0x01};
    struct wno_manifest proof = {.principal = identity.principal,
                                 .principal_size = strlen(identity.principal),
                                 .body = body,
                                 .body_size = sizeof body,
                                 .revision = 1,
                                 .issued = ttl_issued,
                                 .expires = ttl_issued + 100,
                                 .hash_count = 1,
                                 .origin = {.router_id = 777, .seqno = 1}};
    memcpy(proof.instance, instance, sizeof instance);
    proof.hashes[0] = identity.leaf_hash;
    assert(!wno_address(proof.principal, proof.principal_size, instance, proof.address));
    /* This entry point receives worker-verified signature/path metadata. The
     * independent PKI fixture covers that worker's actual certificate crypto. */
    int64_t start = clock_us;
    assert(!wnr_operator_manifest_verified(&node->core, &proof, &identity, node_unix(node),
                                           clock_us));
    assert(node->core.operators && node->core.operators->count == 1);
    assert(wno_authorizes(node->core.operators, proof.address, 777, 1, clock_us));
    struct wg_id id = {.type = 1};
    assert(!wg_offer(&node->pool, 1, body, sizeof body, (uint64_t)clock_us / 1000 + 100,
                     (uint64_t)clock_us / 1000, &id));
    struct wno_entry *entry = node->core.operators->entries;
    memcpy(entry->gossip_hash, id.hash, sizeof id.hash);
    entry->gossip_cached = true;
    clock_us = start + 100000;
    ttl_idle(node);
    assert(!node->core.operators->count && !node->pool.payload_bytes &&
           !node->pool.object_count);
    const struct wno_receipt *receipt =
        wno_receipt_find(node->core.operators, identity.principal, strlen(identity.principal),
                          instance, clock_us);
    assert(receipt && receipt->receipt_deadline_us == start + 1000000);
    wnrs_close(supplier);
    assert(owner == node && !node->sessions);
    supplier = ttl_attach(node, 2);
    clock_us++;
    assert(wnr_operator_manifest_verified(&node->core, &proof, &identity, node_unix(node),
                                          clock_us) == 1);
    assert(!node->core.operators->count);
    proof.revision = 2;
    body[sizeof body - 1] = 2;
    assert(!wnr_operator_manifest_verified(&node->core, &proof, &identity, node_unix(node),
                                           clock_us));
    int64_t replacement = clock_us;
    assert(node->core.operators->count == 1);
    clock_us = replacement + 100000;
    ttl_idle(node);
    assert(!node->core.operators->count);
    clock_us = replacement + 1000000;
    ttl_idle(node);
    assert(!node->core.operators->receipt_count);
    assert(!wnr_operator_manifest_verified(&node->core, &proof, &identity, node_unix(node),
                                           clock_us));
    wnrs_close(supplier);
    wnrs_node_reset(&owner);
    assert(!owner);
}
static void ttl_publication_reserve(void)
{
    if (TTL_TEST_COMPACT)
        return; /* Constrained nodes do not cache foreign relay bodies. */
    struct wnrs_node *owner = NULL, *node = ttl_node(&owner);
    struct wnrs *supplier = ttl_attach(node, 1);
    node->pool.config.objects = 2;
    node->pool.config.reserve_objects = 1;
    node->pool.config.critical_object = own_route_artifact;
    node->pool.config.protected_object = protected_artifact;
    struct ttl_artifact ordinary, extra;
    ttl_identity(node, ids[1]);
    ttl_proof(&ordinary, ids[1], 1, 100, false);
    ttl_verify(supplier, &ordinary);
    struct wg_id id;
    assert(!wg_offer(&node->pool, 1, ordinary.wire, ordinary.size,
                     (uint64_t)clock_us / 1000 + 100, (uint64_t)clock_us / 1000, &id));
    assert(node->pool.object_count == 1 && !node->own_cached);
    ttl_identity(node, ids[2]);
    ttl_proof(&extra, ids[2], 1, 100, false);
    ttl_verify(supplier, &extra);
    assert(wg_offer(&node->pool, 1, extra.wire, extra.size,
                    (uint64_t)clock_us / 1000 + 100, (uint64_t)clock_us / 1000, &id) == 1);
    /* Publication identifies the pending own artifact before wg_offer. Its
     * reserved slot must be usable before own_cached becomes true. */
    struct wn_origin origin = {.router_id = 99, .seqno = 1};
    int result = 1;
    for (unsigned i = 0; result == 1 && i < 4; ++i)
        result = publish(node, &origin, node_unix(node), clock_us);
    assert(!result && node->own_cached && node->pool.object_count == 2);
    assert(own_route_artifact(node, &node->own_artifact) &&
           protected_artifact(node, &node->own_artifact));
    wnrs_close(supplier);
    wnrs_node_reset(&owner);
    assert(!owner);
}
static void ttl_certificate_revocation(void)
{
    const time_t issued = (time_t)(ttl_issued / 1000);
    for (unsigned mode = 0; mode < 4; ++mode) {
        wendy_pki_certificate_reset_certainty();
        struct wnrs_node *owner = NULL, *node = ttl_node(&owner);
        struct wnrs *supplier = ttl_attach(node, 1);
        time_t base = mode == 0 ? issued - 10 : mode == 2 ? issued + 100 : issued + 10;
        time_t leaf = mode == 0 ? issued : mode == 1 ? base - 20 : issued - 100;
        time_t issuer = mode == 0 ? base - 86400 : mode == 1 ? base - 5 : issued - 200;
        time_t expires = mode == 2 ? base + 5 : base + 1000;
        node->clock.certificate_time = (struct wendy_pki_certificate_time){
            .seconds = base,
            .floor = mode == 1 ? issuer - 1000 : base,
            .monotonic_us = clock_us,
            .uncertain = mode == 0,
            .follow_certainty = true,
            .generation = 100 + mode};
        node->clock.config_generation = 100 + mode;
        supplier->identity = node->clock;
        ttl_identity_path(node, ids[1], leaf, issuer, expires);
        struct ttl_artifact artifact;
        ttl_proof(&artifact, ids[1], 1, 60000, false);
        const int64_t start = clock_us;
        ttl_admit(supplier, &artifact);
        assert(node->catalog->records.count == 1);
        const int64_t receipt_deadline = start + INT64_C(600000000);
        assert(ttl_receipt(node, &artifact)->receipt_deadline_us == receipt_deadline);
        uint8_t address[16];
        wn_address(artifact.device, address);
        assert(wnd_authorizes(&node->core.directory, address, 101, 1, clock_us));
        if (mode == 3) {
            /* Dropping an optional cached key is not evidence that a verified
             * claim's certificate stopped being valid. Preserve its bounded
             * path metadata and lifetime independently of that cache slot. */
            assert(!wnd_key_limit(&node->core.directory, 1));
            ttl_identity(node, ids[2]);
            const struct wnd_entry *entry = node->core.directory.entries;
            while (entry && memcmp(entry->device, artifact.device, 16))
                entry = entry->next;
            assert(!entry || !entry->peer.spki_size);
            clock_us++;
            ttl_idle(node);
            assert(node->catalog->records.count == 1);
            if (TTL_TEST_COMPACT) {
                uint16_t port;
                assert(wne_endpoint(&node->core.endpoints, artifact.device, true, clock_us,
                                     &port) && port == 5054);
            } else
                assert(wnd_authorizes(&node->core.directory, address, 101, 1, clock_us));
            assert(ttl_receipt(node, &artifact)->receipt_deadline_us == receipt_deadline);
            clock_us = start + INT64_C(60000000);
            ttl_idle(node);
            ttl_empty_payloads(node);
        } else {
            if (mode == 0) {
                /* A genuine local certainty transition ends the boot-only leaf
                 * allowance without changing the receiver's TTL or its key. */
                assert(wendy_pki_certificate_is_uncertain(&node->clock.certificate_time));
                wendy_pki_certificate_mark_certain(node->clock.config_generation);
                assert(!wendy_pki_certificate_is_uncertain(&node->clock.certificate_time));
                clock_us++;
            } else if (mode == 1) {
                /* The fixture changes only the current local policy clock:
                 * leaf NB still passes, but a later issuer NB no longer does. */
                node->clock.certificate_time.seconds = issuer - 1;
                assert(wendy_pki_mesh_identity_time(&node->clock, clock_us) >= leaf);
                clock_us++;
            } else
                clock_us = start + INT64_C(5000000); /* Exact certificate NA, before 1x TTL. */
            assert(clock_us < start + INT64_C(60000000));
            ttl_idle(node);
            ttl_empty_payloads(node);
            assert(!wnd_authorizes(&node->core.directory, address, 101, 1, clock_us));
            assert(ttl_receipt(node, &artifact)->receipt_deadline_us == receipt_deadline);
            ttl_admit(supplier, &artifact);
            ttl_empty_payloads(node);
            assert(ttl_receipt(node, &artifact)->receipt_deadline_us == receipt_deadline);
        }
        wnrs_close(supplier);
        wnrs_node_reset(&owner);
        assert(!owner);
    }
    wendy_pki_certificate_reset_certainty();
}
int main(int argc, char **argv)
{
    assert((argc == 2 || argc == 3) && !wendy_pki_crypto_init());
    assert(argc == 2 || !strcmp(argv[2], "lifecycle") || !strcmp(argv[2], "cycles") ||
           !strcmp(argv[2], "dynamic") || !strcmp(argv[2], "operator") ||
           !strcmp(argv[2], "publication") || !strcmp(argv[2], "certificate"));
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    assert(wendy_net_memory_open(wendy_net_runtime_memory_ledger(), 160 * 1024, false));
#endif
    FILE *file = fopen(argv[1], "rb");
    assert(file);
    uint8_t der[512];
    size_t size = fread(der, 1, sizeof der, file);
    fclose(file);
    mbedtls_pk_init(&key);
    assert(!mbedtls_pk_parse_key(&key, der, size, NULL, 0));
    if (argc == 2 || !strcmp(argv[2], "lifecycle"))
        ttl_lifecycle();
    if (argc == 2 || !strcmp(argv[2], "cycles"))
        ttl_cycles();
    if (argc == 2 || !strcmp(argv[2], "dynamic"))
        ttl_dynamic_history();
    if (argc == 2 || !strcmp(argv[2], "operator"))
        ttl_operator_lifecycle();
    if (argc == 2 || !strcmp(argv[2], "publication"))
        ttl_publication_reserve();
    if (argc == 2 || !strcmp(argv[2], "certificate"))
        ttl_certificate_revocation();
    mbedtls_pk_free(&key);
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    wendy_net_memory_snapshot_t memory;
    wendy_net_runtime_memory_snapshot(&memory);
    printf("compact TTL ledger: peak=%zu bytes, compact receipt=%zu bytes, failures=%llu\n",
           memory.high_water_bytes, sizeof(struct wnd_receipt),
           (unsigned long long)memory.failed_admissions);
    assert(!memory.current_bytes && !memory.allocation_count && !memory.failed_admissions);
    wendy_net_runtime_memory_close();
    assert(wendy_net_runtime_memory_drained());
#endif
    puts("signed v4 local TTL: idle cleanup, reconnect, duplicates, supersession, dynamic history PASS");
    return 0;
}
