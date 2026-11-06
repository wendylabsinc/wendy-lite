/* Owner-hook tests only. Existing fixtures supply admitted certificate keys;
 * the real P-256 verifier establishes the completed worker precondition. The
 * observer module's JSON and once-only latch are tested independently. */
#define WENDY_NET_REAL_OPERATOR_RELAY_TEST 1
#include "clock_observation_ttl_fixture.h"
#include <arpa/inet.h>

static unsigned observations;
static struct wnrs_node *expected_node;
static uint64_t expected_revision;
static bool expected_operator;

void wendy_pki_clock_observe_first_remote(const struct wendy_pki_mesh_identity *identity)
{
    assert(expected_node && identity == &expected_node->clock);
    assert(identity->config_generation == 17);
    assert(!identity->verified_seconds); /* Boot-policy identity is not fresh public time. */
    bool accepted = false;
    if (expected_operator) {
        assert(expected_node->core.operators);
        for (const struct wno_entry *entry = expected_node->core.operators->entries; entry;
             entry = entry->next)
            accepted |= entry->revision == expected_revision && entry->deadline_us > clock_us;
    } else {
        for (const struct wns_entry *entry = expected_node->catalog->records.entries; entry;
             entry = entry->next)
            accepted |= entry->generation == expected_revision && entry->deadline_us > clock_us;
    }
    assert(accepted); /* Calling before catalog/operator admission must fail this fixture. */
    ++observations;
}
int wnop_job_start(struct wnop_job **out, struct wncs_store *store, const void *wire, size_t size,
                   const struct wendy_pki_mesh_identity *clock,
                   const struct wnop_primary_key *cached)
{
    (void)out;
    (void)store;
    (void)wire;
    (void)size;
    (void)clock;
    (void)cached;
    assert(false); /* Each operator case explicitly supplies its verified completion. */
    return -1;
}
void wnop_job_release(struct wnop_job *job)
{
    if (job) {
        wendy_net_free(job->peer);
        wendy_net_free(job);
    }
}
static void observation_version(struct ttl_artifact *artifact, const char *device,
                                 uint64_t version)
{
    struct wn_doc doc;
    assert(!wn_doc_parse_array_view(&doc, artifact->body, artifact->body_size,
                                     WG_OBJECT_MAX, "s"));
    unsigned fields = 0;
    for (unsigned i = 1; i < doc.storage[0].next; i = doc.storage[i + 1].next)
        ++fields;
    char body[sizeof artifact->body];
    struct wn_writer writer = {
        .data = (uint8_t *)body, .capacity = sizeof body, .maximum = sizeof body};
    wn_map(&writer, fields);
    for (unsigned i = 1; i < doc.storage[0].next; i = doc.storage[i + 1].next) {
        if (wn_doc_equal(&doc, (int)i, wn_key_name("version"))) {
            wn_key(&writer, "version");
            wn_uint(&writer, version);
        } else
            wn_raw(&writer, doc.text + doc.storage[i].start,
                   doc.storage[i + 1].end - doc.storage[i].start);
    }
    int n = wn_finish(&writer);
    assert(n > 0);
    memcpy(artifact->body, body, (size_t)n);
    artifact->body_size = (size_t)n;
    ttl_sign(artifact, device);
}
static void device_observation_hooks(void)
{
    observations = 0;
    expected_node = NULL;
    ttl_publication_reserve();
    assert(!observations); /* Own publication is not a remote admission. */
    struct wnrs_node *owner = NULL, *node = ttl_node(&owner);
    struct wnrs *session = ttl_attach(node, 1);
    node->clock.config_generation = node->clock.certificate_time.generation = 17;
    session->identity = node->clock;
    expected_node = node;
    expected_operator = false;
    struct ttl_artifact self, future, withdraw, live;
    ttl_proof(&self, ids[0], 1, 100, false);
    assert(!complete(session, &self.id, self.wire, self.size));
    assert(!observations);
    ttl_identity(node, ids[1]);
    ttl_proof(&future, ids[1], 1, 100, false);
    observation_version(&future, ids[1], 5);
    assert(!complete(session, &future.id, future.wire, future.size));
    assert(!observations);
    ttl_proof(&withdraw, ids[1], 1, 100, true);
    ttl_admit(session, &withdraw);
    assert(!observations && !node->catalog->records.count);
    ttl_proof(&live, ids[1], 2, 100, false);
    expected_revision = 2;
    ttl_admit(session, &live);
    assert(observations == 1 && node->catalog->records.count == 1);
    clock_us += 100000;
    ttl_idle(node);
    assert(!node->catalog->records.count);
    assert(!complete(session, &live.id, live.wire, live.size));
    assert(observations == 1); /* Expired duplicate is rejected before repair/projection. */
    wnrs_close(session);
    wnrs_node_reset(&owner);
    expected_node = NULL;
}
struct observation_operator_artifact {
    struct wg_id id;
    uint8_t wire[2048];
    size_t size;
};
static void operator_proof(struct observation_operator_artifact *artifact,
                            const struct wendy_pki_operator_peer *identity,
                            const uint8_t instance[16], uint64_t revision, unsigned version,
                            bool withdraw)
{
    uint8_t address[16], body[1024], signature[80], preimage[2048], digest[32];
    char instance_text[37], prefix[INET6_ADDRSTRLEN + 5];
    wn_uuid_format(instance, instance_text);
    assert(!wno_address(identity->principal, strlen(identity->principal), instance, address));
    assert(inet_ntop(AF_INET6, address, prefix, sizeof prefix));
    strcat(prefix, "/128");
    struct wn_writer writer = {
        .data = body, .capacity = sizeof body, .maximum = sizeof body};
    wn_map(&writer, 9);
    wn_key(&writer, "version"); wn_uint(&writer, version);
    wn_key(&writer, "owner"); wn_map(&writer, 3);
    wn_key(&writer, "principal"); wn_text(&writer, identity->principal);
    wn_key(&writer, "instance"); wn_text(&writer, instance_text);
    wn_key(&writer, "hashes"); wn_array(&writer, 1); wn_bytes(&writer, identity->leaf_hash, 32);
    wn_key(&writer, "device"); wn_text(&writer, "00000000-0000-0000-0000-000000000000");
    wn_key(&writer, "agentPort"); wn_uint(&writer, 0);
    wn_key(&writer, "revision"); wn_uint(&writer, revision);
    wn_key(&writer, "Issued"); wn_uint(&writer, (uint64_t)ttl_issued);
    wn_key(&writer, "Expires"); wn_uint(&writer, (uint64_t)ttl_issued + 100);
    wn_key(&writer, "route"); wn_map(&writer, 3);
    wn_key(&writer, "routerId"); wn_uint(&writer, 777);
    wn_key(&writer, "seqno"); wn_uint(&writer, 1);
    wn_key(&writer, "prefix"); wn_text(&writer, prefix);
    wn_key(&writer, "withdraw"); wn_bool(&writer, withdraw);
    int body_size = wn_finish(&writer);
    assert(body_size > 0);
    static const uint8_t domain[] = "wendy-local-mesh/manifest/4";
    size_t principal_size = strlen(identity->principal);
    size_t prefix_size = sizeof domain + 4 + principal_size;
    assert(prefix_size + (size_t)body_size <= sizeof preimage);
    memcpy(preimage, domain, sizeof domain);
    wn_put32(preimage + sizeof domain, (uint32_t)principal_size);
    memcpy(preimage + sizeof domain + 4, identity->principal, principal_size);
    memcpy(preimage + prefix_size, body, (size_t)body_size);
    assert(!wendy_pki_sha256(preimage, prefix_size + (size_t)body_size, digest));
    size_t signature_size;
    assert(!mbedtls_pk_sign(&key, MBEDTLS_MD_SHA256, digest, sizeof digest, signature,
                            sizeof signature, &signature_size));
    assert(!wendy_pki_operator_manifest_verify(identity, body, (size_t)body_size, signature,
                                               signature_size));
    writer = (struct wn_writer){.data = artifact->wire,
                                 .capacity = sizeof artifact->wire,
                                 .maximum = sizeof artifact->wire};
    wn_map(&writer, 3);
    wn_key(&writer, "body"); wn_raw(&writer, body, (size_t)body_size);
    wn_key(&writer, "principal"); wn_text(&writer, identity->principal);
    wn_key(&writer, "signature"); wn_bytes(&writer, signature, signature_size);
    int n = wn_finish(&writer);
    assert(n > 0);
    artifact->size = (size_t)n;
    artifact->id.type = 1;
    assert(!wn_gossip_identify(NULL, 1, artifact->wire, artifact->size, artifact->id.hash));
}
static void operator_completion(struct wnrs *session,
                                 const struct observation_operator_artifact *artifact,
                                 const struct wendy_pki_operator_peer *identity)
{
    struct wnop_job *job = wendy_net_calloc(1, sizeof *job);
    assert(job);
    job->peer = wendy_net_calloc(1, sizeof *job->peer);
    assert(job->peer);
    *job->peer = *identity;
    job->clock = session->node->clock;
    atomic_init(&job->done, true);
    job->result = 0; /* Signature was independently verified above; chain is the fixture input. */
    session->operator_verification = job;
    memcpy(session->operator_record, artifact->id.hash, 32);
    assert(!complete_operator(session, &artifact->id, artifact->wire, artifact->size));
    assert(!session->operator_verification);
}
static void operator_observation_hooks(void)
{
    observations = 0;
    struct wnrs_node *owner = NULL, *node = ttl_node(&owner);
    struct wnrs *session = ttl_attach(node, 1);
    node->clock.config_generation = node->clock.certificate_time.generation = 17;
    session->identity = node->clock;
    expected_node = node;
    expected_operator = true;
    struct wendy_pki_operator_peer identity = {.not_before = 1800000000,
                                               .signing_not_before = 1800000000,
                                               .issuer_not_before = 1800000000,
                                               .expires = 1800010000};
    assert(snprintf(identity.principal, sizeof identity.principal,
                     "spiffe://wendy.sh/tenant/%s/operator/alice", tenant) > 0);
    memset(identity.leaf_hash, 9, sizeof identity.leaf_hash);
    uint8_t spki[128], instance[16] = {1};
    int public_size = mbedtls_pk_write_pubkey_der(&key, spki, sizeof spki);
    assert(public_size > 0);
    identity.spki_size = (size_t)public_size;
    memcpy(identity.spki, spki + sizeof spki - public_size, (size_t)public_size);
    struct observation_operator_artifact future, withdraw, live;
    operator_proof(&future, &identity, instance, 1, 5, false);
    assert(!complete_operator(session, &future.id, future.wire, future.size));
    assert(!observations);
    operator_proof(&withdraw, &identity, instance, 1, 4, true);
    operator_completion(session, &withdraw, &identity);
    assert(!observations);
    operator_proof(&live, &identity, instance, 2, 4, false);
    expected_revision = 2;
    operator_completion(session, &live, &identity);
    assert(observations == 1 && node->core.operators->count == 1);
    clock_us += 100000;
    ttl_idle(node);
    assert(!node->core.operators->count);
    operator_completion(session, &live, &identity);
    assert(observations == 1);
    wnrs_close(session);
    wnrs_node_reset(&owner);
    expected_node = NULL;
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
    device_observation_hooks();
    if (!TTL_TEST_COMPACT)
        operator_observation_hooks();
    mbedtls_pk_free(&key);
    puts("clock observation owner hooks: admitted foreign live records only PASS");
    return 0;
}
