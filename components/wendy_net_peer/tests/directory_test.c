#include "wendy_net_directory.h"
#include "wendy_pki_crypto.h"
#include <assert.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char tenant[] = "2558fd76-afc7-466e-9613-6b715296a526";
static const char self[] = "00000000-0000-4000-8000-000000000005";
static const char peer_id[] = "00000000-0000-4000-8000-000000000004";
static int envelope(mbedtls_pk_context *key, const char *body, char out[2048])
{
    char principal[106], encoded[113];
    uint8_t hash[32], signature[80];
    size_t n = 0, written = 0;
    assert(wn_principal(tenant, peer_id, principal) == 105);
    assert(!wendy_pki_mesh_digest(principal, body, strlen(body), hash));
    assert(!mbedtls_pk_sign(key, MBEDTLS_MD_SHA256, hash, 32, signature,
                            sizeof signature, &n));
    assert(!mbedtls_base64_encode((unsigned char *)encoded, sizeof encoded,
                                  &written, signature, n));
    int size = snprintf(
        out, 2048, "{\"principal\":\"%s\",\"body\":%s,\"signature\":\"%s\"}",
        principal, body, encoded);
    assert(size > 0 && size < 2048);
    return size;
}
int main(int argc, char **argv)
{
    assert(argc == 2 && !wendy_pki_crypto_init());
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
    memcpy(peer.spki, spki + sizeof spki - spki_size, spki_size);
    peer.spki_size = spki_size;
    struct wnd_directory d;
    assert(!wnd_init(&d, tenant, self));
    size_t idle = wnd_memory(&d);
    assert(!d.count && !d.entries && idle == sizeof d);
    uint8_t uuid[16], address[16];
    assert(!wn_uuid_parse(peer_id, uuid));
    wn_address(uuid, address);
    struct wn_origin origin = {.router_id = UINT64_MAX - 1, .seqno = 65535};
    char body[768], text[2048], old[2048];
    uint64_t revision = UINT64_C(9007199254740993);
    int n = wn_manifest_app_write(
        uuid, &origin, revision, INT64_C(1800000000000), INT64_C(1800000060000),
        5054, 43022, body, sizeof body);
    assert(n > 0);
    int size = envelope(&key, body, text);
    memcpy(old, text, size + 1);
    int old_size = size;
    assert(wnd_accept(&d, text, size, INT64_C(1800000000000), 100) == 2 &&
           !d.count);
    assert(!wnd_identity(&d, &peer) && d.count == 1);
    assert(!wnd_accept(&d, text, size, INT64_C(1800000000000), 100));
    assert(wnd_authorizes(&d, address, origin.router_id, origin.seqno, 100));
    assert(!wnd_authorizes(&d, address, origin.router_id, 0, 100));
    assert(d.entries->manifest.agent_mtls &&
           d.entries->manifest.tls_app_port == 43022);
    assert(d.entries->revision == revision);
    int64_t deadline = d.entries->deadline_us;
    assert(!wnd_accept(&d, text, size, INT64_C(1800000000000), 1000));
    assert(d.entries->deadline_us ==
           deadline); /* Same proof never extends its lease. */
    char *port = strstr(text, "5054");
    assert(port);
    port[3] = '5';
    assert(wnd_accept(&d, text, size, INT64_C(1800000000000), 100) < 0);
    port[3] = '4';
    origin.seqno = 0;
    n = wn_manifest_app_write(uuid, &origin, revision, INT64_C(1800000000000),
                              INT64_C(1800000060000), 5054, 43022, body,
                              sizeof body);
    assert(n > 0);
    size = envelope(&key, body, text);
    assert(wnd_accept(&d, text, size, INT64_C(1800000000000), 100) <
           0); /* Same revision equivocation. */
    n = wn_manifest_app_write(uuid, &origin, revision + 1,
                              INT64_C(1800000000000), INT64_C(1800000060000),
                              5054, 43022, body, sizeof body);
    assert(n > 0);
    assert(body[n - 1] == '}');
    strcpy(body + n - 1, ",\"withdraw\":true}");
    size = envelope(&key, body, text);
    assert(!wnd_accept(&d, text, size, INT64_C(1800000000000), 100));
    assert(!wnd_address(&d, address, 100));
    uint8_t receipts[WND_RECEIPTS_MAX];
    int saved = wnd_save(&d, receipts, sizeof receipts);
    assert(saved == 62);
    struct wnd_directory restarted;
    assert(!wnd_init(&restarted, tenant, self));
    assert(!wnd_restore(&restarted, receipts, saved));
    assert(!wnd_address(&restarted, address, 100) &&
           restarted.entries->revision == revision + 1);
    assert(!wnd_identity(&restarted, &peer));
    assert(wnd_accept(&restarted, old, old_size, INT64_C(1800000000000), 100) ==
           1);
    assert(!wnd_accept(&restarted, text, size, INT64_C(1800000000000), 100));
    assert(!wnd_address(&restarted, address, 100));
    assert(wnd_accept(&d, text, size, INT64_C(1800000060000), 100) == 1);
    assert(wnd_accept(&d, text, size, INT64_C(1800000000000), INT64_MAX) < 0);
    printf("sparse signed directory idle=%zu one=%zu receipts=%d\n", idle,
           wnd_memory(&d), saved);
    wnd_deinit(&d);
    wnd_deinit(&restarted);
    mbedtls_pk_free(&key);
    return 0;
}
