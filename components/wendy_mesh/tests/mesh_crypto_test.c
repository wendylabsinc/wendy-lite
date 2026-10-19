#include "wendy_mesh_directory.h"
#include "wendy_pki_crypto.h"
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void* load(const char* path, size_t* size)
{
    FILE* f = fopen(path, "rb");
    assert(f);
    assert(!fseek(f, 0, SEEK_END));
    long n = ftell(f);
    assert(n > 0 && n <= 65536);
    rewind(f);
    uint8_t* out = calloc(1, n + 1);
    assert(out && fread(out, 1, n, f) == (size_t)n);
    fclose(f);
    *size = n;
    return out;
}
static int proof(mbedtls_pk_context* key, const char* tenant, struct wm_manifest* m, char out[1200],
    struct wm_json* doc)
{
    char body[768], device[37], principal[106], b64[113];
    uint8_t hash[32], sig[80];
    size_t size, encoded;
    wm_uuid_format(m->device, device);
    assert(wm_principal(tenant, device, principal) == 105);
    int n = wm_manifest_write(m, body, sizeof body);
    assert(n > 0 && !wendy_pki_mesh_digest(principal, body, n, hash));
    assert(!mbedtls_pk_sign(key, MBEDTLS_MD_SHA256, hash, sizeof hash, sig, sizeof sig, &size));
    assert(!mbedtls_base64_encode((unsigned char*)b64, sizeof b64, &encoded, sig, size));
    n = snprintf(
        out, 1200, "{\"principal\":\"%s\",\"body\":%s,\"signature\":\"%s\"}", principal, body, b64);
    assert(n > 0 && n < 1200 && !wm_json_parse(doc, out, n));
    return n;
}
int main(int argc, char** argv)
{
    assert(argc == 6);
    assert(!wendy_pki_crypto_init());
    size_t keysize, certsize, rootsize;
    uint8_t *keyder = load(argv[1], &keysize), *certpem = load(argv[2], &certsize),
            *roots = load(argv[3], &rootsize);
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    assert(!mbedtls_pk_parse_key(&key, keyder, keysize, NULL, 0));
    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    assert(!mbedtls_x509_crt_parse(&chain, certpem, certsize + 1));
    const uint8_t* certs[8];
    size_t sizes[8], count = 0;
    for (mbedtls_x509_crt* c = &chain; c && c->raw.len; c = c->next)
    {
        assert(count < 8);
        certs[count] = c->raw.p;
        sizes[count++] = c->raw.len;
    }
    time_t now = time(NULL);
    struct wendy_pki_mesh_peer peer;
    assert(!wendy_pki_mesh_chain(certs, sizes, count, roots, rootsize, argv[4], now, &peer));
    assert(!strcmp(peer.device, argv[5]));
    time_t leaf_expires;
    assert(!wendy_lite_peer_expiry(certs[0], sizes[0], &leaf_expires));
    const char* expected_expiry = getenv("EXPECTED_MESH_EXPIRY");
    assert(expected_expiry && peer.expires == (time_t)strtoll(expected_expiry, NULL, 10));
    assert(peer.expires < leaf_expires); /* Issuer expires before root and leaf. */
    struct wendy_pki_mesh_peer unused;
    assert(wendy_pki_mesh_chain(certs, sizes, count, roots, rootsize, argv[5], now, &unused));
    assert(
        wendy_pki_mesh_chain(certs, sizes, count, roots, rootsize, argv[4], peer.expires, &unused));
    struct wm_directory directory = { 0 };
    assert(!wm_directory_add(&directory, &peer));
    struct wm_manifest manifest = { .revision = UINT64_C(9007199254740993),
        .router_id = UINT64_MAX - 1,
        .seqno = 65535,
        .issued = (int64_t)now * 1000,
        .expires = (int64_t)now * 1000 + 60000,
        .agent_port = 5054 };
    assert(!wm_uuid_parse(argv[5], manifest.device));
    uint8_t address[16];
    wm_address(manifest.device, address);
    char text[1200];
    struct wm_json doc;
    proof(&key, argv[4], &manifest, text, &doc);
    assert(!wm_directory_apply(&directory, argv[4], &doc, 0, (int64_t)now * 1000, 100));
    assert(wm_directory_address(&directory, address, 100));
    /* The CA may certify the same UUID and key for a different tenant. An
     * unsigned envelope relabel must not transplant the old tenant's proof. */
    const char* rebound_path = getenv("WENDY_MESH_REBOUND_CHAIN");
    const char* rebound_tenant = getenv("WENDY_MESH_REBOUND_TENANT");
    assert(rebound_path && rebound_tenant);
    size_t rebound_size;
    uint8_t* rebound_pem = load(rebound_path, &rebound_size);
    mbedtls_x509_crt rebound_chain;
    mbedtls_x509_crt_init(&rebound_chain);
    assert(!mbedtls_x509_crt_parse(&rebound_chain, rebound_pem, rebound_size + 1));
    count = 0;
    for (mbedtls_x509_crt* c = &rebound_chain; c && c->raw.len; c = c->next)
    {
        assert(count < 8);
        certs[count] = c->raw.p;
        sizes[count++] = c->raw.len;
    }
    struct wendy_pki_mesh_peer rebound_peer;
    assert(!wendy_pki_mesh_chain(
        certs, sizes, count, roots, rootsize, rebound_tenant, now, &rebound_peer));
    assert(!strcmp(rebound_peer.device, peer.device) && rebound_peer.spki_size == peer.spki_size
        && !memcmp(rebound_peer.spki, peer.spki, peer.spki_size));
    struct wm_directory rebound_directory = { 0 };
    assert(!wm_directory_add(&rebound_directory, &rebound_peer));
    int principal_token = wm_json_member(&doc, 0, "principal");
    memcpy(text + doc.tokens[principal_token].start + 1 + 25, rebound_tenant, 36);
    assert(wm_directory_apply(&rebound_directory, rebound_tenant, &doc, 0, (int64_t)now * 1000, 100)
        == -1);
    assert(!wm_directory_address(&rebound_directory, address, 100));
    proof(&key, rebound_tenant, &manifest, text, &doc);
    assert(
        !wm_directory_apply(&rebound_directory, rebound_tenant, &doc, 0, (int64_t)now * 1000, 100));
    assert(wm_directory_address(&rebound_directory, address, 100));
    proof(&key, argv[4], &manifest, text, &doc);
    free(rebound_pem);
    mbedtls_x509_crt_free(&rebound_chain);
    puts("same-key same-UUID cross-tenant relabel rejected; legitimate tenant proof accepted");
    int64_t deadline = directory.origins[0].expires_us;
    assert(!wm_directory_apply(
        &directory, argv[4], &doc, 0, (int64_t)now * 1000 + 20000, INT64_C(20000100)));
    assert(directory.origins[0].expires_us == deadline);
    assert(!wm_directory_address(&directory, address, deadline));
    /* A same-revision, independently signed replacement is equivocation. */
    manifest.seqno--;
    proof(&key, argv[4], &manifest, text, &doc);
    assert(wm_directory_apply(&directory, argv[4], &doc, 0, (int64_t)now * 1000, 100) == -1);
    manifest.revision--;
    proof(&key, argv[4], &manifest, text, &doc);
    assert(wm_directory_apply(&directory, argv[4], &doc, 0, (int64_t)now * 1000, 100) == 1);
    assert(wm_directory_apply(&directory, argv[4], &doc, 0, manifest.expires, 100) == 1);
    struct wm_directory unknown = { 0 };
    assert(wm_directory_apply(&unknown, argv[4], &doc, 0, (int64_t)now * 1000, 100)
        == WM_DIRECTORY_IDENTITY_NEEDED);
    assert(!wm_directory_address(&unknown, address, 100));
    /* A router can omit a previously sent bundle after a leaf reboot. The
     * repaired cache must still verify a replayed proof, retaining its expiry. */
    assert(!wm_directory_add(&unknown, &peer));
    assert(!wm_directory_apply(&unknown, argv[4], &doc, 0, (int64_t)now * 1000 + 1000, 1000100));
    assert(wm_directory_address(&unknown, address, 1000100));
    assert(unknown.origins[0].expires_us == deadline);
    struct wm_identity_requests requests = { 0 };
    uint8_t requested[16];
    memcpy(requested, manifest.device, 16);
    assert(wm_identity_request_due(&requests, requested, 100));
    assert(!wm_identity_request_due(&requests, requested, 101));
    for (unsigned i = 1; i < WENDY_MESH_ORIGINS_MAX; i++)
    {
        requested[0] = manifest.device[0] ^ i;
        assert(wm_identity_request_due(&requests, requested, 100));
    }
    requested[0] = manifest.device[0] ^ WENDY_MESH_ORIGINS_MAX;
    assert(!wm_identity_request_due(&requests, requested, 100));
    assert(wm_identity_request_due(&requests, requested, 5000100));
    assert(!wm_identity_request_due(&requests, requested, INT64_MAX));
    puts("missing identity repair preserves proof verification, expiry and bounded retries");
    manifest.revision += 2;
    manifest.withdraw = true;
    proof(&key, argv[4], &manifest, text, &doc);
    assert(!wm_directory_apply(&directory, argv[4], &doc, 0, (int64_t)now * 1000, 100));
    assert(!wm_directory_address(&directory, address, 100));
    manifest.withdraw = false;
    manifest.revision++;
    manifest.issued += 6000;
    manifest.expires += 6000;
    proof(&key, argv[4], &manifest, text, &doc);
    assert(wm_directory_apply(&directory, argv[4], &doc, 0, (int64_t)now * 1000, 100) == -1);
    manifest.issued -= 6000;
    manifest.expires -= 6000;
    proof(&key, argv[4], &manifest, text, &doc);
    int body = wm_json_member(&doc, 0, "body"), route = wm_json_member(&doc, body, "route"),
        seq = wm_json_member(&doc, route, "seqno");
    text[doc.tokens[seq].start] = '5';
    assert(wm_directory_apply(&directory, argv[4], &doc, 0, (int64_t)now * 1000, 100) == -1);
    /* Replacing a certified public key never carries forward its old proof. */
    assert(!wm_directory_add(&directory, &peer));
    assert(directory.origins[0].revision == UINT64_C(9007199254740994));
    for (unsigned i = 1; i < 32; i++)
    {
        uint8_t id[16];
        memcpy(id, manifest.device, 16);
        id[0] ^= i;
        wm_uuid_format(id, peer.device);
        assert(!wm_directory_add(&directory, &peer));
    }
    peer.device[0] = peer.device[0] == 'a' ? 'b' : 'a';
    assert(wm_directory_add(&directory, &peer) == 1);
    assert(directory.count == 32);
    printf("mesh chain, signature, replay, exact integers, monotonic expiry and 32-origin cap "
           "passed; directory_bytes=%zu\n",
        sizeof directory);
    /* UUIDs differing only in their first 48 bits collide in the ULA. */
    directory.count = 2;
    directory.origins[1] = directory.origins[0];
    directory.origins[1].device[0] ^= 1;
    directory.origins[0].expires_us = directory.origins[1].expires_us = 1000;
    wm_address(directory.origins[0].device, address);
    assert(!wm_directory_address(&directory, address, 100));
    directory.origins[1].expires_us = 0;
    assert(wm_directory_address(&directory, address, 100));
    directory.origins[1].expires_us = 99;
    assert(wm_directory_address(&directory, address, 100));
    assert(!wm_directory_address(&directory, address, 1000));
    struct wm_epoch epoch = { 0 };
    struct wendy_pki_mesh_identity identity
        = { .verified_seconds = now, .verified_monotonic_us = 100 };
    strcpy(identity.tenant, argv[4]);
    strcpy(identity.device, argv[5]);
    identity.trust_hash[0] = 1;
    assert(!wm_directory_bind(&directory, &epoch, &identity) && directory.count == 0);
    assert(!wm_epoch_ready(&epoch, INT64_C(125000099)));
    assert(wm_epoch_ready(&epoch, INT64_C(125000100)));
    directory.count = 1;
    directory.origins[0].revision = 99;
    identity.verified_monotonic_us += 1000;
    assert(!wm_directory_bind(&directory, &epoch, &identity));
    assert(directory.count == 1 && directory.origins[0].revision == 99
        && epoch.ready_after_us == INT64_C(125000100));
    identity.trust_hash[0] = 2;
    assert(!wm_directory_bind(&directory, &epoch, &identity) && directory.count == 0
        && epoch.ready_after_us == INT64_C(125001100));
    directory.count = 1;
    strcpy(identity.tenant, argv[5]);
    assert(!wm_directory_bind(&directory, &epoch, &identity) && directory.count == 0);
    puts("mesh collision handling, cold-boot quarantine and tenant/root cache binding passed");
    /* A fresh reply issued at100s but received at130s cannot revive a proof
     * expiring at125s after the original cold-boot barrier has passed. */
    epoch = (struct wm_epoch) { 0 };
    directory = (struct wm_directory) { 0 };
    identity.verified_seconds = now;
    identity.verified_monotonic_us = 0;
    assert(!wm_directory_bind(&directory, &epoch, &identity));
    directory.count = 1;
    directory.origins[0].expires_unix_ms = (int64_t)now * 1000 + 125000;
    directory.origins[0].expires_us = INT64_C(125000000);
    identity.verified_seconds = now + 100;
    identity.verified_monotonic_us = INT64_C(130000000);
    assert(!wm_directory_bind(&directory, &epoch, &identity));
    assert(wm_epoch_time(&epoch, INT64_C(130000000)) == (int64_t)now * 1000 + 130000);
    assert(directory.origins[0].expires_us == 0);
    directory.origins[0].expires_unix_ms = (int64_t)now * 1000 + 190000;
    directory.origins[0].expires_us = INT64_C(190000000);
    identity.verified_seconds = now + 180;
    identity.verified_monotonic_us = INT64_C(140000000);
    assert(!wm_directory_bind(&directory, &epoch, &identity));
    assert(directory.origins[0].expires_us == INT64_C(150000000));
    puts("mesh signed-time reanchor never revives or extends proofs");
    memset(keyder, 0, keysize);
    free(keyder);
    free(certpem);
    free(roots);
    mbedtls_pk_free(&key);
    mbedtls_x509_crt_free(&chain);
    return 0;
}
