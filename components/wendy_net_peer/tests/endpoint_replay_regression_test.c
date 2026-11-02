/* A leaf's compact replay receipt outlives its bounded verified-key FIFO. */
#define main shared_router_fixture_main
#include "router_node_success_test.c"
#undef main
#include "catalog_internal.h"
static int replay_publish(void *ctx, const struct wn_origin *origin, int64_t wall, int64_t mono)
{
    (void)ctx;
    (void)origin;
    (void)wall;
    (void)mono;
    return 0;
}
static int replay_packet(void *ctx, uint64_t link, const void *bytes, size_t size)
{
    (void)ctx;
    (void)link;
    (void)bytes;
    (void)size;
    return 0;
}
static int replay_send(void *ctx, const void *bytes, size_t size, bool control)
{
    (void)ctx;
    (void)bytes;
    (void)size;
    (void)control;
    return 0;
}
static void replay_proof(struct wnrs *s, struct wnsc_node *source, uint64_t revision, bool present)
{
    char array[512], body[1024], wire[1500], principal[106];
    int count = present ? wnsc_services_write(source, array, sizeof array) : 1;
    if (!present)
        array[0] = (char)0x80;
    assert(count > 0);
    struct wn_origin origin = {.router_id = 101, .seqno = 1};
    int64_t wall = node_unix(s->node);
    int n =
        wn_manifest_services_write(source->self, &origin, revision, wall, wall + 60000, 5054, 43022,
                                   "peer", false, array, (size_t)count, body, sizeof body);
    assert(n > 0 && wn_principal(tenant, ids[1], principal) > 0);
    uint8_t signature[80];
    size_t signature_size = 0;
    assert(!wendy_pki_mesh_sign(NULL, principal, body, (size_t)n, signature, &signature_size));
    n = wn_manifest_wire_write(principal, body, (size_t)n, signature, signature_size, wire,
                               sizeof wire);
    assert(n > 0);
    /* Authenticate the exact artifact through production PKI before projecting it. */
    assert(!wnr_manifest(&s->node->core, wire, (size_t)n, wall, clock_us));
    struct wg_id id = {.type = 1};
    assert(!wn_gossip_identify(NULL, 1, wire, (size_t)n, id.hash));
    assert(!admit_complete(s, &id, wire, (size_t)n));
}
int main(int argc, char **argv)
{
    assert(argc == 2 && !wendy_pki_crypto_init());
    FILE *file = fopen(argv[1], "rb");
    assert(file);
    uint8_t der[512];
    size_t size = fread(der, 1, sizeof der, file);
    fclose(file);
    mbedtls_pk_init(&key);
    assert(!mbedtls_pk_parse_key(&key, der, size, NULL, 0));
    struct wnrs_node node = {0};
    node.clock.verified_seconds = 1800000000;
    node.clock.verified_monotonic_us = clock_us;
    strcpy(node.clock.tenant, tenant);
    strcpy(node.clock.device, ids[0]);
    struct wnr_config config = {.tenant = tenant,
                                .device = ids[0],
                                .router = 99,
                                .non_transit = true,
                                .endpoint_gateway = true,
                                .publish = replay_publish,
                                .send = replay_packet};
    assert(!wnr_init(&node.core, &config, clock_us, NULL, 0));
    assert(!wnd_key_limit(&node.core.directory, 8));
    assert(!wnr_start(&node.core, node_unix(&node), clock_us));
    assert(!catalog_open(&node));
    struct wnrs session = {.node = &node, .link = 1, .send = replay_send};
    node.sessions = &session;
    session.identity = node.clock;
    struct wendy_pki_mesh_peer peer = {.expires = 1800003600};
    uint8_t spki[128];
    int public_size = mbedtls_pk_write_pubkey_der(&key, spki, sizeof spki);
    assert(public_size > 0);
    peer.spki_size = (size_t)public_size;
    memcpy(peer.spki, spki + sizeof spki - public_size, (size_t)public_size);
    strcpy(peer.device, ids[1]);
    assert(!wnr_identity(&node.core, &peer, node_unix(&node), clock_us));
    struct wnsc_config source_config = {.tenant = tenant, .device = ids[1]};
    struct wnsc_node *source = NULL;
    assert(!wnsc_open(&source, &source_config));
    struct wns_record record = {.port = 8080};
    strcpy(record.app, WNS_GUEST_APP_ID);
    strcpy(record.service, "temperature");
    strcpy(record.type, "_sensorlink._tcp");
    strcpy(record.instance, "room");
    assert(!wnsc_publish(source, &record, NULL, node_unix(&node), 0));
    replay_proof(&session, source, 1, true);
    assert(node.catalog->records.count == 1);
    replay_proof(&session, source, 2, false);
    assert(!node.catalog->records.count);
    /* Eight other identities evict this origin's key and directory receipt. */
    for (unsigned i = 0; i < 8; ++i) {
        assert(snprintf(peer.device, sizeof peer.device, "00000000-0000-4000-8000-%012u",
                        100 + i) == 36);
        assert(!wnr_identity(&node.core, &peer, node_unix(&node), clock_us));
    }
    assert(node.core.endpoints.entries->revision == 2);
    strcpy(peer.device, ids[1]);
    assert(!wnr_identity(&node.core, &peer, node_unix(&node), clock_us));
    replay_proof(&session, source, 1, true);
    assert(node.core.endpoints.entries->revision == 2);
    assert(!node.catalog->records.count); /* A signed old service must stay withdrawn. */
    wnsc_close(source);
    wnsc_close(node.catalog);
    wnr_deinit(&node.core);
    mbedtls_pk_free(&key);
    puts("leaf retains service omission across key eviction and older signed replay PASS");
}
