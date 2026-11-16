/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_control.h"
#include "wendy_pki_crypto.h"
#include <inttypes.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

int wn_operator_hello_read(const void *data, size_t size, uint8_t instance[16])
{
    uint32_t selected;
    return wn_operator_hello_read_direct(data, size, instance, 0, &selected);
}
int wn_operator_hello_read_direct(const void *data, size_t size, uint8_t instance[16],
                                  uint32_t local, uint32_t *selected)
{
    bool parked;
    return wn_operator_hello_read_deferred(data, size, instance, local, 0, selected, &parked);
}
int wn_operator_hello_read_deferred(const void *data, size_t size, uint8_t instance[16],
                                    uint32_t local, uint32_t deferred, uint32_t *selected,
                                    bool *parked)
{
    if (!selected || !parked || !wn_direct_capability_valid(local) ||
        !wn_direct_capability_valid(deferred))
        return -1;
    *selected = 0;
    *parked = false;
    struct wn_doc d;
    size_t n = 0;
    uint8_t id[16], nonzero = 0;
    if (!instance || size > WN_OPERATOR_HELLO_MAX || wn_doc_parse(&d, data, size) ||
        !wn_doc_equal(&d, wn_doc_member(&d, 0, "k"), "operator-router-hello") ||
        wn_doc_copy_bytes(&d, wn_doc_member(&d, 0, "n"), id, sizeof id, &n) || n != 16)
        return -1;
    for (unsigned i = 0; i < 16; i++)
        nonzero |= id[i];
    if (!nonzero)
        return -1;
    int direct = wn_doc_member(&d, 0, "direct");
    uint64_t remote = 0;
    if (direct >= 0 && (wn_doc_u64(&d, direct, &remote) || remote > UINT32_MAX))
        return -1;
    int field = wn_doc_member(&d, 0, "directDeferred");
    uint64_t remote_deferred = 0;
    if (field >= 0 && (wn_doc_u64(&d, field, &remote_deferred) || remote_deferred > UINT32_MAX))
        return -1;
    *selected = wn_direct_carrier_negotiate(local, deferred, (uint32_t)remote,
                                            (uint32_t)remote_deferred, parked);
    memcpy(instance, id, 16);
    return 0;
}
int wn_operator_ready_write(void *out, size_t cap)
{
    return wn_operator_ready_write_direct(out, cap, 0);
}
int wn_operator_ready_write_direct(void *out, size_t cap, uint32_t selected)
{
    return wn_operator_ready_write_deferred(out, cap, selected, false);
}
int wn_operator_ready_write_deferred(void *out, size_t cap, uint32_t selected, bool parked)
{
    if (!out || !wn_direct_capability_valid(selected) ||
        ((selected & WN_DIRECT_CAP_TLS) && (selected & WN_DIRECT_CAP_QUIC)))
        return -1;
    struct wn_writer w = {.data = out, .capacity = cap, .maximum = WN_OPERATOR_HELLO_MAX};
    wn_map(&w, selected ? 2 : 1);
    if (selected) {
        wn_key(&w, parked ? "directDeferred" : "direct");
        wn_uint(&w, selected);
    }
    wn_key(&w, "k");
    wn_text(&w, "operator-router-ready");
    return wn_finish(&w);
}

bool wn_direct_capability_valid(uint32_t c)
{
    return !c || ((c & 255) == WN_DIRECT_CAP_VERSION &&
                  !(c & ~(UINT32_C(255) | WN_DIRECT_CAP_TLS | WN_DIRECT_CAP_QUIC)) &&
                  (c & (WN_DIRECT_CAP_TLS | WN_DIRECT_CAP_QUIC)));
}
uint32_t wn_direct_capability_negotiate(uint32_t local, uint32_t remote)
{
    if (!local || !wn_direct_capability_valid(local) || !remote || !wn_direct_capability_valid(remote))
        return 0;
    uint32_t common = local & remote;
    if (common & WN_DIRECT_CAP_QUIC)
        return WN_DIRECT_CAP_VERSION | WN_DIRECT_CAP_QUIC;
    if (common & WN_DIRECT_CAP_TLS)
        return WN_DIRECT_CAP_VERSION | WN_DIRECT_CAP_TLS;
    return 0;
}
uint32_t wn_direct_carrier_negotiate(uint32_t local, uint32_t local_deferred, uint32_t remote,
                                     uint32_t remote_deferred, bool *deferred)
{
    *deferred = false;
    uint32_t selected = wn_direct_capability_negotiate(local, remote);
    if (selected)
        return selected;
    if (!local)
        local = local_deferred;
    if (!remote)
        remote = remote_deferred;
    selected = wn_direct_capability_negotiate(local, remote);
    if (!selected)
        return 0;
    *deferred = true;
    return selected;
}
int wn_router_hello_write(const char *self, const char *peer, char *out, size_t cap)
{
    return wn_router_hello_write_direct(self, peer, out, cap, 0);
}
int wn_router_hello_write_direct(const char *self, const char *peer, char *out, size_t cap,
                                 uint32_t direct)
{
    return wn_router_hello_write_deferred(self, peer, out, cap, direct, 0);
}
int wn_router_hello_write_deferred(const char *self, const char *peer, char *out, size_t cap,
                                   uint32_t direct, uint32_t deferred)
{
    uint8_t uuid[16];
    if (!out || !wn_direct_capability_valid(direct) || !wn_direct_capability_valid(deferred) ||
        wn_uuid_parse(self, uuid) || wn_uuid_parse(peer, uuid) || !strcmp(self, peer))
        return -1;
    struct wn_writer w = {.data = (uint8_t *)out, .capacity = cap, .maximum = WN_CONTROL_MAX};
    wn_map(&w, 2);
    wn_key(&w, "kind");
    wn_text(&w, "hello");
    wn_key(&w, "hello");
    wn_map(&w, 5 + (direct != 0) + (deferred != 0));
    if (deferred) {
        wn_key(&w, "directDeferred");
        wn_uint(&w, deferred);
    }
    if (direct) {
        wn_key(&w, "direct");
        wn_uint(&w, direct);
    }
    wn_key(&w, "mtu");
    wn_uint(&w, WN_MTU);
    wn_key(&w, "peer");
    wn_text(&w, peer);
    wn_key(&w, "device");
    wn_text(&w, self);
    wn_key(&w, "version");
    wn_uint(&w, 1);
    wn_key(&w, "datagram");
    wn_uint(&w, WN_DATAGRAM_MAX);
    return wn_finish(&w);
}
static int number(const struct wn_doc *d, unsigned object, const char *name, uint64_t *value)
{
    return wn_doc_u64(d, wn_doc_member(d, object, name), value);
}
int wn_router_hello_check(const void *data, size_t size, const char *self, const char *peer)
{
    uint32_t selected;
    return wn_router_hello_check_direct(data, size, self, peer, 0, &selected);
}
int wn_router_hello_check_direct(const void *data, size_t size, const char *self, const char *peer,
                                 uint32_t local, uint32_t *selected)
{
    bool parked;
    return wn_router_hello_check_deferred(data, size, self, peer, local, 0, selected, &parked);
}
int wn_router_hello_check_deferred(const void *data, size_t size, const char *self,
                                   const char *peer, uint32_t local, uint32_t deferred,
                                   uint32_t *selected, bool *parked)
{
    if (!selected || !parked || !wn_direct_capability_valid(local) ||
        !wn_direct_capability_valid(deferred))
        return -1;
    *selected = 0;
    *parked = false;
    struct wn_doc d;
    uint8_t uuid[16];
    uint64_t version, mtu, datagram;
    if (wn_uuid_parse(self, uuid) || wn_uuid_parse(peer, uuid) || !strcmp(self, peer) ||
        wn_doc_parse(&d, data, size) || !wn_doc_equal(&d, wn_doc_member(&d, 0, "kind"), "hello"))
        return -1;
    int h = wn_doc_member(&d, 0, "hello");
    /* The negotiated version owns the required fields; optional additions do
     * not change this peer's existing identity and capacity requirements. */
    if (h < 0 || number(&d, h, "version", &version) || version != 1 || number(&d, h, "mtu", &mtu) ||
        mtu != WN_MTU || number(&d, h, "datagram", &datagram) || datagram != WN_DATAGRAM_MAX ||
        !wn_doc_equal(&d, wn_doc_member(&d, h, "device"), peer) ||
        !wn_doc_equal(&d, wn_doc_member(&d, h, "peer"), self))
        return -1;
    int role = wn_doc_member(&d, h, "role");
    if (!(role < 0 || wn_doc_equal(&d, role, "") || wn_doc_equal(&d, role, "router")))
        return -1;
    int direct = wn_doc_member(&d, h, "direct");
    uint64_t remote = 0;
    if (direct >= 0 && (wn_doc_u64(&d, direct, &remote) || remote > UINT32_MAX))
        return -1;
    int field = wn_doc_member(&d, h, "directDeferred");
    uint64_t remote_deferred = 0;
    if (field >= 0 && (wn_doc_u64(&d, field, &remote_deferred) || remote_deferred > UINT32_MAX))
        return -1;
    *selected = wn_direct_carrier_negotiate(local, deferred, (uint32_t)remote,
                                            (uint32_t)remote_deferred, parked);
    return 0;
}
int wn_gossip_write(const struct wg_message *m, char *out, size_t cap)
{
    static const char *ops[] = {"have", "want", "unavailable", "data", "gone"};
    if (!out || wg_validate(m) || m->id.type != 1)
        return -1;
    struct wn_writer w = {.data = (uint8_t *)out, .capacity = cap, .maximum = WN_CONTROL_MAX};
    wn_map(&w, 2);
    wn_key(&w, "kind");
    wn_text(&w, "gossip");
    wn_key(&w, "gossip");
    wn_map(&w, 8);
    wn_key(&w, "v");
    wn_uint(&w, 1);
    wn_key(&w, "op");
    wn_text(&w, ops[m->op]);
    wn_key(&w, "data");
    wn_bytes(&w, m->data, m->size);
    wn_key(&w, "type");
    wn_uint(&w, m->id.type);
    wn_key(&w, "total");
    wn_uint(&w, m->total);
    wn_key(&w, "digest");
    wn_bytes(&w, m->id.hash, 32);
    wn_key(&w, "offset");
    wn_uint(&w, m->offset);
    wn_key(&w, "request");
    wn_uint(&w, m->request);
    return wn_finish(&w);
}
static int binary(const struct wn_doc *d, int token, uint8_t *out, size_t cap, size_t *size)
{
    if (token < 0) {
        *size = 0;
        return 0;
    }
    return wn_doc_copy_bytes(d, token, out, cap, size);
}
static int gossip_read(const void *data, size_t size, struct wg_message *out,
                       uint8_t bytes[WG_CHUNK])
{
    static const char *ops[] = {"have", "want", "unavailable", "data", "gone"};
    struct wn_doc d;
    uint64_t version, type, request = 0, offset = 0, total = 0;
    size_t n = 0;
    if (!out || wn_doc_parse(&d, data, size))
        return -1;
    if (!wn_doc_equal(&d, wn_doc_member(&d, 0, "kind"), "gossip"))
        return 1;
    int g = wn_doc_member(&d, 0, "gossip");
    const struct wn_token *group = wn_doc_token(&d, g);
    if (!group || group->type != '{')
        return -1;
    /* Select the envelope and artifact schema before decoding their fields. */
    if (number(&d, g, "v", &version))
        return -1;
    if (version != 1)
        return 1;
    if (number(&d, g, "type", &type))
        return -1;
    if (type != 1)
        return 1;
    int op = wn_doc_member(&d, g, "op");
    const struct wn_token *operation = wn_doc_token(&d, op);
    if (!operation || operation->type != '"' ||
        operation->end <= operation->start + operation->header)
        return -1;
    unsigned i = 0;
    for (; i < sizeof ops / sizeof *ops; i++)
        if (wn_doc_equal(&d, op, ops[i]))
            break;
    if (i == sizeof ops / sizeof *ops)
        return 1;
    /* Unknown additive transport fields are ignored. Signed object fields are
     * still validated independently by their exact existing parsers. */
    struct wg_message m = {.id.type = (uint8_t)type, .data = bytes};
    m.op = (enum wg_op)i;
    const char *names[] = {"request", "offset", "total"};
    uint64_t *values[] = {&request, &offset, &total};
    for (i = 0; i < 3; i++) {
        int t = wn_doc_member(&d, g, names[i]);
        if (t >= 0 && wn_doc_u64(&d, t, values[i]))
            return -1;
    }
    if (offset > UINT32_MAX || total > UINT32_MAX ||
        binary(&d, wn_doc_member(&d, g, "digest"), m.id.hash, 32, &n) || n != 32)
        return -1;
    int payload = wn_doc_member(&d, g, "data");
    if (bytes) {
        if (binary(&d, payload, bytes, WG_CHUNK, &m.size))
            return -1;
    } else if (payload >= 0 && wn_doc_bytes(&d, payload, &m.data, &m.size))
        return -1;
    m.request = request;
    m.offset = (uint32_t)offset;
    m.total = (uint32_t)total;
    if (wg_validate(&m))
        return -1;
    *out = m;
    return 0;
}
int wn_gossip_read(const void *data, size_t size, struct wg_message *out, uint8_t bytes[WG_CHUNK])
{
    return bytes ? gossip_read(data, size, out, bytes) : -1;
}
int wn_gossip_read_view(const void *data, size_t size, struct wg_message *out)
{
    return gossip_read(data, size, out, NULL);
}
int wn_gossip_identify(void *context, uint8_t type, const void *data, size_t size, uint8_t hash[32])
{
    (void)context;
    static const uint8_t domain[] = "wendy-mesh-artifact/1";
    if (!data || !size || size > WG_OBJECT_MAX || !hash || type != 1 || wendy_pki_crypto_init())
        return -1;
    uint8_t length[4];
    wn_put32(length, (uint32_t)size);
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    size_t written = 0;
    int result = psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS &&
                         psa_hash_update(&op, domain, sizeof domain) == PSA_SUCCESS &&
                         psa_hash_update(&op, &type, 1) == PSA_SUCCESS &&
                         psa_hash_update(&op, length, sizeof length) == PSA_SUCCESS &&
                         psa_hash_update(&op, data, size) == PSA_SUCCESS &&
                         psa_hash_finish(&op, hash, 32, &written) == PSA_SUCCESS && written == 32
                     ? 0
                     : -1;
    psa_hash_abort(&op);
    return result;
}
