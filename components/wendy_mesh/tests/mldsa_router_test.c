/* Linux router identities and manifests, as produced by the WendyOS router's
 * own signer (see mldsa-router-fixtures/README.md). Control messages are fed
 * through the leaf's JSON, chain and directory code without modification. */
#include "wendy_mesh_directory.h"
#include "wendy_pki_crypto.h"
#include <mbedtls/base64.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* fixtures;
static char* load(const char* name, size_t* size)
{
    char path[512];
    assert(snprintf(path, sizeof path, "%s/%s", fixtures, name) < (int)sizeof path);
    FILE* f = fopen(path, "rb");
    assert(f);
    assert(!fseek(f, 0, SEEK_END));
    long n = ftell(f);
    assert(n > 0 && n <= WENDY_MESH_CONTROL_MAX);
    rewind(f);
    char* out = calloc(1, n + 1);
    assert(out && fread(out, 1, n, f) == (size_t)n);
    fclose(f);
    *size = n;
    return out;
}

static char tenant[37], mldsa_router[37], ecdsa_router[37];
static int64_t now_s, leaf_expires;
static char* roots;
static size_t roots_size;
static uint8_t scratch[32768];

/* Same bundle decoding as the mesh task's receive_control(). */
static int bundle(const char* name, struct wendy_pki_mesh_peer* peer)
{
    static const char* const fields[] = { "kind", "bundle", NULL };
    static struct wm_json doc;
    size_t size, total = 0, count = 0, sizes[8];
    const uint8_t* der[8];
    char* text = load(name, &size);
    int result = -1;
    if (wm_json_parse(&doc, text, size) || !wm_json_fields(&doc, 0, fields)
        || !wm_json_equal(&doc, wm_json_member(&doc, 0, "kind"), "bundle"))
        goto done;
    int list = wm_json_member(&doc, 0, "bundle");
    if (list < 0 || doc.tokens[list].type != '[')
        goto done;
    for (unsigned i = list + 1; i < doc.tokens[list].next; i = doc.tokens[i].next)
    {
        const struct wm_token* t = &doc.tokens[i];
        if (count == 8 || t->type != '"'
            || mbedtls_base64_decode(scratch + total, sizeof scratch - total, &sizes[count],
                (const unsigned char*)doc.text + t->start + 1, t->end - t->start - 2))
            goto done;
        der[count] = scratch + total;
        total += sizes[count++];
    }
    result = wendy_pki_mesh_chain(
        der, sizes, count, (const uint8_t*)roots, roots_size, tenant, (time_t)now_s, peer);
done:
    free(text);
    return result;
}

/* Same manifest admission as receive_control(), on caller-owned text. */
static int apply(struct wm_directory* d, const char* text, size_t size, int64_t now_us)
{
    static const char* const fields[] = { "kind", "manifest", NULL };
    static struct wm_json doc;
    if (wm_json_parse(&doc, text, size) || !wm_json_fields(&doc, 0, fields)
        || !wm_json_equal(&doc, wm_json_member(&doc, 0, "kind"), "manifest"))
        return -3;
    return wm_directory_apply(
        d, tenant, &doc, wm_json_member(&doc, 0, "manifest"), now_s * 1000, now_us);
}
static int apply_file(struct wm_directory* d, const char* name)
{
    size_t size;
    char* text = load(name, &size);
    int result = apply(d, text, size, 100);
    free(text);
    return result;
}
static char* signature_text(char* text, size_t* size)
{
    char* p = strstr(text, "\"signature\":\"");
    assert(p);
    p += strlen("\"signature\":\"");
    char* end = strchr(p, '"');
    assert(end);
    *size = end - p;
    return p;
}
static bool member(const struct wm_directory* d, const char* device)
{
    struct wendy_mesh_member members[WENDY_MESH_ORIGINS_MAX];
    unsigned count = wm_directory_members(d, 100, members, WENDY_MESH_ORIGINS_MAX);
    for (unsigned i = 0; i < count; i++)
        if (!strcmp(members[i].device, device))
            return true;
    return false;
}

int main(int argc, char** argv)
{
    assert(argc == 2);
    fixtures = argv[1];
    assert(!wendy_pki_crypto_init());
    size_t size;
    char* vector = load("vector.txt", &size);
    assert(sscanf(vector, "%36s %36s %36s %" SCNd64 " %" SCNd64, tenant, mldsa_router,
               ecdsa_router, &now_s, &leaf_expires)
        == 5);
    free(vector);
    roots = load("roots.pem", &roots_size);
    struct wendy_pki_mesh_peer* mldsa = calloc(1, sizeof *mldsa);
    struct wendy_pki_mesh_peer* ecdsa = calloc(1, sizeof *ecdsa);
    struct wm_directory* d = calloc(1, sizeof *d);
    assert(mldsa && ecdsa && d);

    /* An ML-DSA-65 device leaf under ML-DSA-87/65 CAs, the router's TLS chain. */
    assert(!bundle("mldsa-router-bundle.json", mldsa));
    assert(!strcmp(mldsa->device, mldsa_router) && mldsa->expires == leaf_expires);
    assert(mldsa->spki_size == WENDY_PKI_MESH_SPKI_MAX);
    assert(!wm_directory_add(d, mldsa));
    uint8_t uuid[16], address[16];
    assert(!wm_uuid_parse(mldsa_router, uuid));
    wm_address(uuid, address);
    assert(!wm_directory_address(d, address, 100));
    assert(!apply_file(d, "mldsa-router-manifest.json"));
    assert(wm_directory_address(d, address, 100) && member(d, mldsa_router));
    assert(d->origins[0].revision == 42 && d->origins[0].seqno == 7
        && d->origins[0].router_id == UINT64_C(0x0123456789abcdef));
    /* Idempotent redelivery, as on every router reconciliation. */
    assert(!apply_file(d, "mldsa-router-manifest.json"));
    puts("ML-DSA-65 router chain and pure ML-DSA manifest accepted");

    /* Valid ML-DSA-65 signatures over the wrong message. A fresh directory
     * holds each, so a rejection is not caused by replay state. */
    const char* rejected[] = { "mldsa-router-manifest-hashed.json",
        "mldsa-router-manifest-context.json", "mldsa-router-manifest-other-key.json",
        "mldsa-router-manifest-no-principal.json" };
    for (unsigned i = 0; i < sizeof rejected / sizeof *rejected; i++)
    {
        struct wm_directory* fresh = calloc(1, sizeof *fresh);
        assert(fresh && !wm_directory_add(fresh, mldsa));
        assert(apply_file(fresh, rejected[i]) == -1);
        assert(!wm_directory_address(fresh, address, 100));
        free(fresh);
        printf("rejected %s\n", rejected[i]);
    }

    /* Damaged signatures, bodies and envelopes. */
    char* valid = load("mldsa-router-manifest.json", &size);
    char* text = malloc(size + 1);
    assert(text);
    size_t encoded;
    char* signature;
    struct wm_directory* fresh = calloc(1, sizeof *fresh);
    assert(fresh && !wm_directory_add(fresh, mldsa));
    memcpy(text, valid, size + 1);
    signature = signature_text(text, &encoded);
    assert(encoded == 4412);
    signature[2000] = signature[2000] == 'A' ? 'B' : 'A';
    assert(apply(fresh, text, size, 100) == -1);
    memcpy(text, valid, size + 1);
    signature = signature_text(text, &encoded);
    /* Drop one base64 quantum: a 3306-byte signature. */
    char* tail = signature + encoded;
    memmove(tail - 4, tail, size + 1 - (tail - text));
    assert(apply(fresh, text, size - 4, 100) == -1);
    memcpy(text, valid, size + 1);
    memcpy(strstr(text, "\"seqno\":7") + strlen("\"seqno\":"), "8", 1);
    assert(apply(fresh, text, size, 100) == -1);
    memcpy(text, valid, size + 1);
    char* architecture = strstr(text, "\"cpuArchitecture\":\"arm64\"");
    assert(architecture);
    memcpy(architecture + strlen("\"cpuArchitecture\":\""), "amd64", 5);
    assert(apply(fresh, text, size, 100) == -1);
    memcpy(text, valid, size + 1);
    memcpy(strstr(text, "\"cpuArchitecture\"") + 1, "cpuArchitectury", 15);
    assert(apply(fresh, text, size, 100) == -1);
    assert(!wm_directory_address(fresh, address, 100));
    /* The untouched record still verifies in the same directory. */
    assert(!apply(fresh, valid, size, 100) && wm_directory_address(fresh, address, 100));
    free(fresh);
    puts("damaged ML-DSA signature, body, agent metadata and truncation rejected");

    /* A P-256 router through the same router signer: ECDSA over SHA-256. */
    assert(!bundle("ecdsa-router-bundle.json", ecdsa));
    assert(!strcmp(ecdsa->device, ecdsa_router) && ecdsa->spki_size == 91);
    assert(!wm_directory_add(d, ecdsa));
    assert(!apply_file(d, "ecdsa-router-manifest.json"));
    assert(member(d, ecdsa_router) && member(d, mldsa_router) && d->count == 2);
    puts("P-256 router chain and ECDSA manifest accepted alongside ML-DSA-65");

    /* The certified key alone selects the algorithm: neither key accepts the
     * other's signature encoding, and the principal must name the peer. */
    struct record
    {
        char* text;
        struct wm_json doc;
        char principal[106];
        const char* body;
        size_t body_size;
        uint8_t signature[WENDY_PKI_MESH_SIGNATURE_MAX];
        size_t signature_size;
    } *records = calloc(2, sizeof *records);
    assert(records);
    const char* names[] = { "mldsa-router-manifest.json", "ecdsa-router-manifest.json" };
    for (unsigned i = 0; i < 2; i++)
    {
        struct record* r = &records[i];
        r->text = load(names[i], &size);
        assert(!wm_json_parse(&r->doc, r->text, size));
        int envelope = wm_json_member(&r->doc, 0, "manifest"),
            body = wm_json_member(&r->doc, envelope, "body");
        assert(wm_json_string(&r->doc, wm_json_member(&r->doc, envelope, "principal"),
                   r->principal, sizeof r->principal)
            == 105);
        r->body = r->doc.text + r->doc.tokens[body].start;
        r->body_size = r->doc.tokens[body].end - r->doc.tokens[body].start;
        signature = signature_text(r->text, &encoded);
        assert(!mbedtls_base64_decode(r->signature, sizeof r->signature, &r->signature_size,
            (const unsigned char*)signature, encoded));
    }
    struct record *m = &records[0], *e = &records[1];
    assert(m->signature_size == WENDY_PKI_MESH_SIGNATURE_MAX && e->signature_size <= 72);
    assert(!wendy_pki_mesh_verify(mldsa, m->principal, m->body, m->body_size, m->signature,
        m->signature_size));
    assert(!wendy_pki_mesh_verify(ecdsa, e->principal, e->body, e->body_size, e->signature,
        e->signature_size));
    /* Each key rejects the other algorithm's signature over its own record. */
    assert(wendy_pki_mesh_verify(mldsa, m->principal, m->body, m->body_size, e->signature,
        e->signature_size));
    assert(wendy_pki_mesh_verify(ecdsa, e->principal, e->body, e->body_size, m->signature,
        m->signature_size));
    /* A key certified for another device cannot vouch for this principal. */
    struct wendy_pki_mesh_peer* relabeled = calloc(1, sizeof *relabeled);
    assert(relabeled);
    *relabeled = *mldsa;
    memcpy(relabeled->device, ecdsa_router, 36);
    assert(wendy_pki_mesh_verify(relabeled, m->principal, m->body, m->body_size, m->signature,
        m->signature_size));
    puts("algorithm selection follows the certified key");

    /* The router chain must stay anchored, in the tenant and unexpired. */
    struct wendy_pki_mesh_peer* unused = calloc(1, sizeof *unused);
    assert(unused);
    const char* other_tenant = "7c1e4a52-9d3b-4f60-8a21-5e0f3c9b2d15";
    memcpy(tenant, other_tenant, 37);
    assert(bundle("mldsa-router-bundle.json", unused));
    char* saved = vector = load("vector.txt", &size);
    assert(sscanf(vector, "%36s", tenant) == 1);
    free(saved);
    int64_t saved_now = now_s;
    now_s = leaf_expires;
    assert(bundle("mldsa-router-bundle.json", unused));
    now_s = saved_now;
    /* Same root name and algorithm, different key. */
    char* saved_roots = roots;
    size_t saved_roots_size = roots_size;
    roots = load("other-root.pem", &roots_size);
    assert(bundle("mldsa-router-bundle.json", unused));
    free(roots);
    roots = saved_roots;
    roots_size = saved_roots_size;
    assert(!bundle("mldsa-router-bundle.json", unused));
    assert(!strcmp(unused->device, mldsa->device) && unused->expires == mldsa->expires
        && unused->spki_size == mldsa->spki_size
        && !memcmp(unused->spki, mldsa->spki, mldsa->spki_size));
    printf("router chain tenant, expiry and trust checks passed; peer_bytes=%zu "
           "directory_bytes=%zu\n",
        sizeof *mldsa, sizeof *d);

    free(unused);
    free(relabeled);
    free(records[0].text);
    free(records[1].text);
    free(records);
    free(text);
    free(valid);
    free(roots);
    free(d);
    free(ecdsa);
    free(mldsa);
    return 0;
}
