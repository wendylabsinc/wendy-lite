/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_router.h"
#include "wendy_pki_crypto.h"
#include <assert.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char tenant[] = "2558fd76-afc7-466e-9613-6b715296a526";
static const char *ids[] = {"00000000-0000-4000-8000-000000000001",
                            "00000000-0000-4000-8000-000000000002",
                            "00000000-0000-4000-8000-000000000003"};
static const int64_t wall = INT64_C(1800000000000);
static const int64_t epoch = INT64_C(3600000000);
struct node
{
    struct wnr_core core;
    struct wnr_core *active;
    struct wnr_config config;
    unsigned index, writes, sends, publications;
    uint8_t journal[WNR_JOURNAL_MAX], address[16];
    size_t journal_size;
    uint64_t links[3], revision, seen[3];
    bool fail_storage, agent_disabled;
    char proof[2048];
    size_t proof_size;
    uint16_t app_port;
};
static struct node nodes[3];
static mbedtls_pk_context key;
static uint64_t ms;
struct packet
{
    unsigned from, to;
    size_t size;
    uint8_t bytes[WB_PACKET_MAX];
};
static struct packet packets[512];
static unsigned written, consumed;
static int persist(void *ctx, const void *bytes, size_t size)
{
    struct node *n = ctx;
    assert(!n->active->ready && size <= sizeof n->journal);
    if (n->fail_storage)
        return -1;
    memcpy(n->journal, bytes, size);
    n->journal_size = size;
    n->writes++;
    return 0;
}
static int sign_proof(void *ctx, const struct wn_origin *origin, int64_t now,
                      int64_t monotonic)
{
    struct node *n = ctx;
    (void)monotonic;
    char body[768], principal[106], encoded[113];
    uint8_t uuid[16], hash[32], sig[80];
    size_t sig_size, b64_size;
    assert(!wn_uuid_parse(ids[n->index], uuid));
    int size =
        wn_manifest_app_write(uuid, origin, ++n->revision, now, now + 60000,
                              5054, n->app_port, body, sizeof body);
    assert(size > 0 && wn_principal(tenant, ids[n->index], principal) == 105);
    if (n->agent_disabled) {
        char *transport = strstr(body, "mtls-v1");
        assert(transport);
        memmove(transport, transport+7, strlen(transport+7)+1);
        size -= 7;
    }
    assert(!wendy_pki_mesh_digest(principal, body, size, hash));
    assert(!mbedtls_pk_sign(&key, MBEDTLS_MD_SHA256, hash, sizeof hash, sig,
                            sizeof sig, &sig_size));
    assert(!mbedtls_base64_encode((unsigned char *)encoded, sizeof encoded,
                                  &b64_size, sig, sig_size));
    size = snprintf(n->proof, sizeof n->proof,
                    "{\"principal\":\"%s\",\"body\":%s,\"signature\":\"%s\"}",
                    principal, body, encoded);
    assert(size > 0 && (size_t)size < sizeof n->proof);
    n->proof_size = size;
    n->publications++;
    return 0;
}
static int publish(void *ctx, const struct wn_origin *origin, int64_t now,
                   int64_t monotonic)
{
    struct node *n = ctx;
    assert(n->writes && !n->active->ready);
    return sign_proof(ctx, origin, now, monotonic);
}
static int send_packet(void *ctx, uint64_t link, const void *bytes, size_t size)
{
    struct node *n = ctx;
    assert(n->writes && n->publications && !n->active->ready);
    unsigned destination;
    for (destination = 0; destination < 3; destination++)
        if (n->links[destination] == link)
            break;
    /* attach exports before returning its new ID to the caller. */
    if (destination == 3)
        for (destination = 0; destination < 3; destination++)
            if (destination != n->index && n->links[destination] == UINT64_MAX)
            {
                n->links[destination] = link;
                break;
            }
    assert(destination < 3 && written - consumed < 512 &&
           size <= WB_PACKET_MAX);
    struct packet *p = &packets[written++ % 512];
    p->from = n->index;
    p->to = destination;
    p->size = size;
    memcpy(p->bytes, bytes, size);
    n->sends++;
    return 0;
}
static void pump(void)
{
    unsigned iterations = 0;
    for (;;)
    {
        bool changed = false;
        for (unsigned i = 0; i < 3; i++)
            for (unsigned j = 0; j < 3; j++)
                if (i != j && nodes[j].revision > nodes[i].seen[j])
                {
                    assert(!wnr_manifest(&nodes[i].core, nodes[j].proof,
                                         nodes[j].proof_size, wall + ms,
                                         epoch + (int64_t)ms * 1000));
                    nodes[i].seen[j] = nodes[j].revision;
                    changed = true;
                }
        if (consumed < written)
        {
            struct packet p = packets[consumed++ % 512];
            uint64_t incoming = nodes[p.to].links[p.from];
            assert(incoming && incoming != UINT64_MAX);
            assert(!wnr_receive(&nodes[p.to].core, incoming, p.bytes, p.size,
                                wall + ms, epoch + (int64_t)ms * 1000));
            changed = true;
        }
        assert(++iterations < 10000);
        if (!changed)
            break;
    }
    consumed = written = 0;
}
static void advance(uint64_t until)
{
    while (ms < until)
    {
        ms += 20;
        for (unsigned i = 0; i < 3; i++)
            assert(!wnr_tick(&nodes[i].core, wall + ms,
                             epoch + (int64_t)ms * 1000));
        pump();
    }
}
static void connect_nodes(unsigned a, unsigned b, uint16_t cost)
{
    nodes[a].links[b] = nodes[b].links[a] = UINT64_MAX;
    assert(!wnr_attach(&nodes[a].core, ids[b], cost, wall + ms,
                       epoch + (int64_t)ms * 1000, &nodes[a].links[b]));
    assert(!wnr_attach(&nodes[b].core, ids[a], cost, wall + ms,
                       epoch + (int64_t)ms * 1000, &nodes[b].links[a]));
    pump();
}
static struct wb_route route(unsigned from, unsigned to)
{
    struct wb_route r;
    assert(wnr_lookup(&nodes[from].core, nodes[to].address,
                      epoch + (int64_t)ms * 1000, &r));
    return r;
}
int main(int argc, char **argv)
{
    assert(argc == 2 && !wendy_pki_crypto_init());
    FILE *f = fopen(argv[1], "rb");
    uint8_t keybytes[1024];
    assert(f);
    size_t size = fread(keybytes, 1, sizeof keybytes, f);
    assert(feof(f));
    fclose(f);
    mbedtls_pk_init(&key);
    assert(!mbedtls_pk_parse_key(&key, keybytes, size, NULL, 0));
    uint8_t spki[128];
    int spki_size = mbedtls_pk_write_pubkey_der(&key, spki, sizeof spki);
    assert(spki_size > 0);
    for (unsigned i = 0; i < 3; i++)
    {
        struct node *n = &nodes[i];
        n->index = i;
        n->app_port = 43022;
        n->active = &n->core;
        n->config = (struct wnr_config){.tenant = tenant,
                                        .device = ids[i],
                                        .router = i + 1,
                                        .context = n,
                                        .persist = persist,
                                        .publish = publish,
                                        .send = send_packet};
        memset(n->config.trust_hash, 42, 32);
        assert(!wnr_init(&n->core, &n->config, epoch, NULL, 0));
        assert(wnr_memory(&n->core) == sizeof n->core);
        printf("native router idle=%zu\n", wnr_memory(&n->core));
        assert(!wnr_start(&n->core, wall, epoch));
        uint8_t uuid[16];
        assert(!wn_uuid_parse(ids[i], uuid));
        wn_address(uuid, n->address);
        for (unsigned j = 0; j < 3; j++)
            if (i != j)
            {
                struct wendy_pki_mesh_peer peer = {.expires = 1800003600};
                memcpy(peer.device, ids[j], 37);
                memcpy(peer.spki, spki + sizeof spki - spki_size, spki_size);
                peer.spki_size = spki_size;
                assert(!wnr_identity(&n->core, &peer, wall, epoch));
            }
    }
    connect_nodes(0, 1, WNR_LAN_COST);
    connect_nodes(1, 2, WNR_LAN_COST);
    advance(12000);
    struct wb_route r = route(0, 2);
    assert(r.metric == 256 && r.link == nodes[0].links[1]);
    uint8_t target[16]; uint16_t app_port;
    assert(!wn_uuid_parse(ids[2], target));
    assert(wnr_app_endpoint(&nodes[0].core, target, epoch + (int64_t)ms*1000, &app_port));
    assert(app_port == 43022);
    uint16_t agent_port;
    assert(wnr_agent_endpoint(&nodes[0].core, target, epoch+(int64_t)ms*1000, &agent_port));
    assert(agent_port == 5054);
    assert(!wnr_agent_endpoint(&nodes[0].core, nodes[0].core.directory.self,
                               epoch+(int64_t)ms*1000, &agent_port));
    assert(!agent_port);
    assert(!wnr_app_endpoint(&nodes[0].core, target,
                             epoch + (int64_t)ms*1000 + INT64_C(10000000), &app_port));
    assert(!app_port); /* Timed-out link cannot expose a cached capability. */
    nodes[2].app_port = 0;
    struct wn_origin service_origin = {.router_id = 3, .seqno = nodes[2].core.babel.seqno};
    assert(!sign_proof(&nodes[2], &service_origin, wall+ms, epoch+(int64_t)ms*1000));
    pump();
    assert(!wnr_app_endpoint(&nodes[0].core, target, epoch+(int64_t)ms*1000, &app_port));
    assert(route(0,2).metric == 256); /* Route exists; signed TLS endpoint was removed. */
    assert(wnr_agent_endpoint(&nodes[0].core, target, epoch+(int64_t)ms*1000, &agent_port));
    nodes[2].app_port = 43022;
    assert(!sign_proof(&nodes[2], &service_origin, wall+ms, epoch+(int64_t)ms*1000));
    pump();
    assert(wnr_app_endpoint(&nodes[0].core, target, epoch+(int64_t)ms*1000, &app_port));
    nodes[2].agent_disabled = true;
    assert(!sign_proof(&nodes[2], &service_origin, wall+ms, epoch+(int64_t)ms*1000));
    pump();
    assert(!wnr_agent_endpoint(&nodes[0].core, target, epoch+(int64_t)ms*1000, &agent_port));
    assert(!agent_port && route(0,2).metric == 256);
    assert(wnr_app_endpoint(&nodes[0].core, target, epoch+(int64_t)ms*1000, &app_port));
    nodes[2].agent_disabled = false;
    assert(!sign_proof(&nodes[2], &service_origin, wall+ms, epoch+(int64_t)ms*1000));
    pump();
    assert(wnr_agent_endpoint(&nodes[0].core, target, epoch+(int64_t)ms*1000, &agent_port));
    /* Even a blocked actor cannot keep a stale selected link forwarding. */
    assert(!wnr_lookup(&nodes[0].core, nodes[2].address,
                       epoch + (int64_t)ms * 1000 + INT64_C(10000000), &r));
    uint8_t ip[40] = {0x60};
    ip[7] = 64;
    memcpy(ip + 8, nodes[0].address, 16);
    memcpy(ip + 24, nodes[2].address, 16);
    uint64_t outgoing;
    int64_t now = epoch + (int64_t)ms * 1000;
    assert(wnr_packet(&nodes[1].core, nodes[1].links[0], ip, sizeof ip, now,
                      &outgoing) == 1);
    assert(ip[7] == 63 && outgoing == nodes[1].links[2]);
    assert(wnr_packet(&nodes[2].core, nodes[2].links[1], ip, sizeof ip, now,
                      &outgoing) == 0 &&
           !outgoing);
    ip[7] = 1;
    assert(wnr_packet(&nodes[1].core, nodes[1].links[0], ip, sizeof ip, now,
                      &outgoing) == -2 &&
           ip[7] == 1);
    ip[7] = 64;
    assert(wnr_packet(&nodes[1].core, 999, ip, sizeof ip, now, &outgoing) < 0);
    ip[23] ^= 0x10;
    assert(wnr_packet(&nodes[1].core, nodes[1].links[0], ip, sizeof ip, now,
                      &outgoing) < 0);
    assert(!wnr_lookup(&nodes[0].core, nodes[2].address,
                       now + INT64_C(61000000), &r));
    assert(!wnr_app_endpoint(&nodes[0].core, target, now + INT64_C(61000000), &app_port));
    assert(!wnr_agent_endpoint(&nodes[0].core, target, now + INT64_C(61000000), &agent_port));

    connect_nodes(0, 2, WNR_BLE_COST);
    advance(22000);
    assert(route(0, 2).metric == 256);
    assert(!wnr_detach(&nodes[1].core, nodes[1].links[2], wall + ms,
                       epoch + (int64_t)ms * 1000));
    assert(!wnr_detach(&nodes[2].core, nodes[2].links[1], wall + ms,
                       epoch + (int64_t)ms * 1000));
    pump();
    advance(42000);
    r = route(0, 2);
    assert(r.metric == WNR_BLE_COST && r.link == nodes[0].links[2]);
    printf("native signed transit/fallback: router=%zu journal=%zu writes=%u\n",
           wnr_memory(&nodes[0].core), nodes[0].journal_size, nodes[0].writes);

    struct wnr_core restored = {0};
    nodes[0].active = &restored;
    int64_t reboot = epoch + INT64_C(7200000000);
    assert(!wnr_init(&restored, &nodes[0].config, reboot, nodes[0].journal,
                     nodes[0].journal_size));
    assert(!restored.babel.route_count && !restored.babel.links_capacity);
    assert(!wnr_lookup(&restored, nodes[2].address, reboot, &r));
    assert(!wnr_start(&restored, wall + ms, reboot));
    assert(restored.babel.now == 0);
    for (size_t i = 0; i < restored.babel.drops_capacity; i++)
        if (restored.babel.drops[i].used)
            assert(restored.babel.drops[i].expires > restored.babel.now);
    wnr_deinit(&restored);
    uint8_t corrupted[WNR_JOURNAL_MAX];
    memcpy(corrupted, nodes[0].journal, nodes[0].journal_size);
    corrupted[90] ^= 1;
    assert(wnr_init(&restored, &nodes[0].config, reboot, corrupted,
                    nodes[0].journal_size) < 0 &&
           restored.stopped);
    wnr_deinit(&restored);
    struct wnr_config wrong = nodes[0].config;
    wrong.trust_hash[0] ^= 1;
    assert(wnr_init(&restored, &wrong, reboot, nodes[0].journal,
                    nodes[0].journal_size) < 0);
    wnr_deinit(&restored);

    nodes[0].active = &nodes[0].core;
    unsigned sends = nodes[0].sends;
    nodes[0].fail_storage = true;
    /* A changed, signed sequence proof requires a new durable replay receipt.
     */
    struct wn_origin changed = {.router_id = 3,
                                .seqno = nodes[2].core.babel.seqno};
    assert(!sign_proof(&nodes[2], &changed, wall + ms,
                       epoch + (int64_t)ms * 1000));
    assert(wnr_manifest(&nodes[0].core, nodes[2].proof, nodes[2].proof_size,
                        wall + ms, epoch + (int64_t)ms * 1000) == WB_STOPPED);
    assert(nodes[0].sends == sends && !nodes[0].core.ready);
    assert(!wnr_lookup(&nodes[0].core, nodes[2].address,
                       epoch + (int64_t)ms * 1000, &r));
    for (unsigned i = 0; i < 3; i++)
        wnr_deinit(&nodes[i].core);
    mbedtls_pk_free(&key);
    puts("signed routing journal, transit, expiry and failed durability pass");
    return 0;
}
