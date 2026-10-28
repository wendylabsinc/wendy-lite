/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_control.h"
#include "wendy_pki_crypto.h"
#include <inttypes.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

int wn_router_hello_write(const char *self,const char *peer,char *out,size_t cap)
{
    uint8_t uuid[16];if(!out || wn_uuid_parse(self,uuid) || wn_uuid_parse(peer,uuid) || !strcmp(self,peer))return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,"hello");wn_key(&w,"hello");wn_map(&w,5);
    wn_key(&w,"mtu");wn_uint(&w,WN_MTU);wn_key(&w,"peer");wn_text(&w,peer);
    wn_key(&w,"device");wn_text(&w,self);wn_key(&w,"version");wn_uint(&w,1);
    wn_key(&w,"datagram");wn_uint(&w,WN_DATAGRAM_MAX);return wn_finish(&w);
}
static int number(const struct wn_doc *d, unsigned object, const char *name,
                  uint64_t *value)
{
    return wn_doc_u64(d, wn_doc_member(d, object, name), value);
}
int wn_router_hello_check(const void *data, size_t size, const char *self,
                          const char *peer)
{
    static const char *const fields[] = {"kind", "hello", NULL};
    static const char *const hello_fields[] = {
        "version", "role", "device", "peer", "mtu", "datagram", NULL};
    struct wn_doc d;
    uint8_t uuid[16];
    uint64_t version, mtu, datagram;
    if (wn_uuid_parse(self, uuid) || wn_uuid_parse(peer, uuid) ||
        !strcmp(self, peer) || wn_doc_parse(&d, data, size) ||
        !wn_doc_fields(&d, 0, fields) ||
        !wn_doc_equal(&d, wn_doc_member(&d, 0, "kind"), "hello"))
        return -1;
    int h = wn_doc_member(&d, 0, "hello");
    if (h < 0 || !wn_doc_fields(&d, h, hello_fields) ||
        number(&d, h, "version", &version) || version != 1 ||
        number(&d, h, "mtu", &mtu) || mtu != WN_MTU ||
        number(&d, h, "datagram", &datagram) || datagram != WN_DATAGRAM_MAX ||
        !wn_doc_equal(&d, wn_doc_member(&d, h, "device"), peer) ||
        !wn_doc_equal(&d, wn_doc_member(&d, h, "peer"), self))
        return -1;
    int role = wn_doc_member(&d, h, "role");
    return role < 0 || wn_doc_equal(&d, role, "") ||
                   wn_doc_equal(&d, role, "router")
               ? 0
               : -1;
}
int wn_gossip_write(const struct wg_message *m,char *out,size_t cap)
{
    static const char *ops[]={"have","want","unavailable","data","gone"};
    if(!out || wg_validate(m) || (m->id.type!=1 && m->id.type!=2 && m->id.type!=3))return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,m->id.type==3 ? "operator-gossip":"gossip");wn_key(&w,m->id.type==3 ? "operator":"gossip");
    wn_map(&w,8);wn_key(&w,"v");wn_uint(&w,1);wn_key(&w,"op");wn_text(&w,ops[m->op]);
    wn_key(&w,"data");wn_bytes(&w,m->data,m->size);wn_key(&w,"type");wn_uint(&w,m->id.type);
    wn_key(&w,"total");wn_uint(&w,m->total);wn_key(&w,"digest");wn_bytes(&w,m->id.hash,32);
    wn_key(&w,"offset");wn_uint(&w,m->offset);wn_key(&w,"request");wn_uint(&w,m->request);
    return wn_finish(&w);
}
static int binary(const struct wn_doc *d,int token,uint8_t *out,size_t cap,size_t *size)
{if(token<0){*size=0;return 0;}return wn_doc_copy_bytes(d,token,out,cap,size);}
static int gossip_read(const void *data, size_t size, struct wg_message *out,
                   uint8_t bytes[WG_CHUNK])
{
    static const char *ops[] = {"have", "want", "unavailable", "data", "gone"};
    struct wn_doc d;
    uint64_t version, type, request = 0, offset = 0, total = 0;
    size_t n = 0;
    if (!out || wn_doc_parse(&d, data, size))return -1;
    bool operator=wn_doc_equal(&d,wn_doc_member(&d,0,"kind"),"operator-gossip");
    if(!operator && !wn_doc_equal(&d,wn_doc_member(&d,0,"kind"),"gossip"))return -1;
    int g = wn_doc_member(&d, 0, operator ? "operator":"gossip");
    if (g < 0 || d.tokens[g].type!='{')
        return -1;
    int op = wn_doc_member(&d, g, "op");
    if(op<0 || d.tokens[op].type!='"' || d.tokens[op].end<=d.tokens[op].start+d.tokens[op].header)return -1;
    unsigned i = 0;
    for (; i < sizeof ops/sizeof *ops; i++)
        if (wn_doc_equal(&d, op, ops[i]))
            break;
    if (i == sizeof ops/sizeof *ops)return 1;
    if(number(&d,g,"v",&version) || number(&d,g,"type",&type))return -1;
    if(version!=1 || (operator ? type!=3:(type!=1 && type!=2)))return 1;
    /* Unknown additive transport fields are ignored. Signed object fields are
     * still validated independently by their exact existing parsers. */
    struct wg_message m = {.id.type = (uint8_t)type, .data = bytes};
    m.op = (enum wg_op)i;
    const char *names[] = {"request", "offset", "total"};
    uint64_t *values[] = {&request, &offset, &total};
    for (i = 0; i < 3; i++)
    {
        int t = wn_doc_member(&d, g, names[i]);
        if (t >= 0 && wn_doc_u64(&d, t, values[i]))
            return -1;
    }
    if (offset > UINT32_MAX || total > UINT32_MAX ||
        binary(&d, wn_doc_member(&d, g, "digest"), m.id.hash, 32, &n) ||
        n != 32)
        return -1;
    int payload=wn_doc_member(&d,g,"data");
    if(bytes){if(binary(&d,payload,bytes,WG_CHUNK,&m.size))return -1;}
    else if(payload>=0 && wn_doc_bytes(&d,payload,&m.data,&m.size))return -1;
    m.request = request;
    m.offset = (uint32_t)offset;
    m.total = (uint32_t)total;
    if (wg_validate(&m))
        return -1;
    *out = m;
    return 0;
}
int wn_gossip_read(const void *data,size_t size,struct wg_message *out,uint8_t bytes[WG_CHUNK])
{return bytes ? gossip_read(data,size,out,bytes):-1;}
int wn_gossip_read_view(const void *data,size_t size,struct wg_message *out)
{return gossip_read(data,size,out,NULL);}
int wn_gossip_identify(void *context, uint8_t type, const void *data,
                       size_t size, uint8_t hash[32])
{
    (void)context;
    static const uint8_t domain[] = "wendy-mesh-artifact/1";
    if (!data || !size || size > WG_OBJECT_MAX || !hash ||
        (type != 1 && type != 2 && type != 3) || wendy_pki_crypto_init())
        return -1;
    uint8_t length[4];
    wn_put32(length, (uint32_t)size);
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    size_t written = 0;
    int result =
        psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS &&
                psa_hash_update(&op, domain, sizeof domain) == PSA_SUCCESS &&
                psa_hash_update(&op, &type, 1) == PSA_SUCCESS &&
                psa_hash_update(&op, length, sizeof length) == PSA_SUCCESS &&
                psa_hash_update(&op, data, size) == PSA_SUCCESS &&
                psa_hash_finish(&op, hash, 32, &written) == PSA_SUCCESS &&
                written == 32
            ? 0
            : -1;
    psa_hash_abort(&op);
    return result;
}
