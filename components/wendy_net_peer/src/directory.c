/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_directory.h"
#include "wendy_net_service_protocol.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_crypto.h"
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#endif
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int number(const struct wn_doc *d, unsigned object, const char *name,
                  uint64_t *value)
{
    return wn_doc_u64(d, wn_doc_member(d, object, name), value);
}
void wne_clear(struct wne_cache *c)
{
    while(c->entries){struct wne_entry *e=c->entries;c->entries=e->next;wendy_net_free(e);}
    c->count=0;
}
void wne_reap(struct wne_cache *c,int64_t now)
{
    for(struct wne_entry **at=&c->entries;*at;){
        struct wne_entry *e=*at;
        if(e->deadline_us<=now){*at=e->next;wendy_net_free(e);c->count--;}
        else at=&e->next;
    }
}
int wne_update(struct wne_cache *c,const struct wnd_manifest *m,const uint8_t hash[32],int64_t deadline,int64_t now)
{
    wne_reap(c,now);
    if(deadline<=now)return 1;
    struct wne_entry *e=c->entries;
    while(e && memcmp(e->device,m->device,16))e=e->next;
    if(e){
        if(m->revision<e->revision)return 1;
        if(m->revision==e->revision){
            if(memcmp(e->body_hash,hash,32))return 2;
            if(deadline<e->deadline_us)e->deadline_us=deadline;
            return 0;
        }
    }else{
        if(c->count==WNE_ENDPOINTS_MAX){
            /* FIFO replacement reuses the oldest allocation, even when valid. */
            struct wne_entry **old=&c->entries;
            while((*old)->next)old=&(*old)->next;
            e=*old;*old=NULL;c->count--;
        }else e=wendy_net_calloc(1,sizeof *e);
        if(!e)return 3;
        memset(e,0,sizeof *e);e->next=c->entries;c->entries=e;c->count++;
    }
    memcpy(e->device,m->device,16);memcpy(e->body_hash,hash,32);
    e->revision=m->revision;e->deadline_us=deadline;e->app_port=m->tls_app_port;
    e->agent_port=m->agent_port;e->agent_mtls=m->agent_mtls;e->withdraw=m->withdraw;
    return 0;
}
bool wne_endpoint(const struct wne_cache *c,const uint8_t device[16],bool agent,int64_t now,uint16_t *port)
{
    *port=0;
    for(const struct wne_entry *e=c->entries;e;e=e->next)
        if(!memcmp(e->device,device,16) && !e->withdraw && e->deadline_us>now){
            *port=agent ? (e->agent_mtls ? e->agent_port:0):e->app_port;
            return *port!=0;
        }
    return false;
}
void wnd_forget_keyless(struct wnd_directory *d)
{
    for(struct wnd_entry **at=&d->entries;*at;){
        struct wnd_entry *e=*at;
        if(!e->peer.spki_size && !e->key_pinned){*at=e->next;wendy_net_free(e);d->count--;}
        else at=&e->next;
    }
}
static struct wnd_entry *find(const struct wnd_directory *d,
                              const uint8_t device[16])
{
    for (struct wnd_entry *e = d->entries; e; e = e->next)
        if (!memcmp(e->device, device, 16))
            return e;
    return NULL;
}
static struct wnd_entry *insert(struct wnd_directory *d,
                                const uint8_t device[16])
{
    if (d->count >= WND_ORIGINS_MAX)
        return NULL;
    struct wnd_entry *e = wendy_net_calloc(1, sizeof *e);
    if (e)
    {
        memcpy(e->device, device, 16);
        wn_address(device, e->address);
        e->next = d->entries;
        d->entries = e;
        d->count++;
    }
    return e;
}
int wnd_init(struct wnd_directory *d, const char *tenant, const char *self)
{
    uint8_t uuid[16];
    if (!d || wn_uuid_parse(tenant, uuid) || wn_uuid_parse(self, uuid))
        return -1;
    *d = (struct wnd_directory){0};
    d->key_limit=WND_ORIGINS_MAX;
    memcpy(d->tenant, tenant, 37);
    memcpy(d->self, uuid, 16);
    wn_address(uuid, d->self_address);
    return 0;
}
void wnd_deinit(struct wnd_directory *d)
{
    while (d->entries)
    {
        struct wnd_entry *e = d->entries;
        d->entries = e->next;
        wendy_net_free((void *)e->peer.spki);
        wendy_net_free(e);
    }
    memset(d, 0, sizeof *d);
}
int wnd_key_limit(struct wnd_directory *d,unsigned limit)
{
    if(!d || !limit || limit>WND_ORIGINS_MAX)return -1;
    while(d->key_count>limit){
        struct wnd_entry *evict=NULL;
        for(struct wnd_entry *e=d->entries;e;e=e->next)
            if(e->peer.spki_size && !e->key_pinned && (!evict || e->key_serial<evict->key_serial))evict=e;
        if(!evict)return 3;
        wendy_net_free((void *)evict->peer.spki);evict->peer.spki=NULL;evict->peer.spki_size=0;evict->peer.expires=0;
        evict->key_serial=0;evict->certificate_chain_until=0;
        memset(evict->certificate_chain_hash,0,32);memset(evict->certificate_leaf_hash,0,32);d->key_count--;
    }
    d->key_limit=limit;return 0;
}
int wnd_key_pin(struct wnd_directory *d,const uint8_t device[16],bool pinned)
{
    struct wnd_entry *e=d && device ? find(d,device):NULL;
    if(!e || !e->peer.spki_size)return 1;
    e->key_pinned=pinned;return 0;
}
static struct wnd_entry *oldest_key(struct wnd_directory *d)
{
    struct wnd_entry *oldest=NULL;
    for(struct wnd_entry *e=d->entries;e;e=e->next)
        if(e->peer.spki_size && !e->key_pinned &&
           (!oldest || e->key_serial<oldest->key_serial))oldest=e;
    return oldest;
}
static void drop_key(struct wnd_directory *d,struct wnd_entry *e)
{
    wendy_net_free((void *)e->peer.spki);
    e->peer.spki=NULL;e->peer.spki_size=0;e->peer.expires=0;
    e->key_serial=0;e->certificate_chain_until=0;
    memset(e->certificate_chain_hash,0,sizeof e->certificate_chain_hash);
    memset(e->certificate_leaf_hash,0,sizeof e->certificate_leaf_hash);
    d->key_count--;
}
int wnd_identity(struct wnd_directory *d,
                 const struct wendy_pki_mesh_peer *peer)
{
    uint8_t uuid[16], address[16];
    if (!d || !peer || wn_uuid_parse(peer->device, uuid) || !peer->spki_size ||
        peer->spki_size > sizeof peer->spki || peer->expires <= 0 ||
        peer->expires > INT64_MAX / 1000)
        return -1;
    wn_address(uuid, address);
    if (!memcmp(d->self_address, address, 16))
        return -1;
    struct wnd_entry *e = find(d, uuid);
    bool changed = !e || e->peer.spki_size != peer->spki_size ||
        memcmp(e->peer.spki, peer->spki, peer->spki_size);
    if (changed) {
        bool adding=!e || !e->peer.spki_size;
        struct wnd_entry *evict=NULL;
        if(adding && d->key_count>=d->key_limit){
            evict=oldest_key(d);if(!evict)return 3;
        }
        uint8_t *key = wendy_net_malloc(peer->spki_size);
        if (!key) return 3;
        memcpy(key, peer->spki, peer->spki_size);
        if (!e && !(e = insert(d, uuid))) { wendy_net_free(key); return 3; }
        if(evict)drop_key(d,evict);
        wendy_net_free((void *)e->peer.spki);
        e->peer.spki = key;
        e->peer.spki_size = peer->spki_size;
        if(adding)d->key_count++;
        e->key_serial=++d->key_serial;
        e->deadline_us = 0;
        e->certificate_chain_until=0;
    }
    memcpy(e->peer.device, peer->device, sizeof e->peer.device);
    e->peer.expires = peer->expires;
    /* A shortened certified path can revoke sooner, never extend a proof. */
    if (e->manifest.expires > (int64_t)peer->expires * 1000)
        e->deadline_us = 0;
    return 0;
}
static int app_endpoints(const struct wn_doc *d, unsigned body,
                         struct wnd_manifest *m)
{
    int endpoints = wn_doc_member(d, body, "appEndpoints");
    if (endpoints < 0 || d->tokens[endpoints].type == 'n')
        return 0;
    if (d->tokens[endpoints].type != '[')
        return -1;
    unsigned count = 0;
    for (unsigned i = endpoints + 1; i < d->tokens[endpoints].next;
         i = d->tokens[i].next)
    {
        uint64_t port;
        uint16_t *slot;
        if (++count > 2 || d->tokens[i].type!='{' ||
            number(d, i, "port", &port) || !port || port > 65535)
            return -1;
        int transport = wn_doc_member(d, i, "transport");
        if (wn_doc_equal(d, transport, "tls-v1"))
            slot = &m->tls_app_port;
        else if (wn_doc_equal(d, transport, "quic-v1"))
            slot = &m->quic_app_port;
        else
            return WND_UNSUPPORTED;
        if (*slot)
            return -1;
        *slot = (uint16_t)port;
    }
    return 0;
}
static bool extension_name(const char *name)
{
    for(size_t i=0;name[i];i++){
        unsigned char c=(unsigned char)name[i];
        if((c>='a' && c<='z') || (c>='0' && c<='9'))continue;
        if(i && (c=='.' || c=='_' || c=='/' || c=='-'))continue;
        return false;
    }
    return *name!=0;
}
int wnd_manifest_read(const struct wn_doc *d, unsigned body,
                    struct wnd_manifest *m)
{
    uint64_t version, issued, expires, port = 0, seq;
    char uuid[37], prefix[48];
    uint8_t actual[16], expected[16];
    memset(m, 0, sizeof *m);
    if(d->tokens[body].type!='{' || number(d,body,"version",&version))return -1;
    if(version!=4)return WND_UNSUPPORTED;
    int route = wn_doc_member(d, body, "route"),
        withdraw = wn_doc_member(d, body, "withdraw"),
        name = wn_doc_member(d, body, "name"),
        agent = wn_doc_member(d, body, "agentTransport"),
        port_token = wn_doc_member(d, body, "agentPort");
    if (route < 0 || d->tokens[route].type!='{' ||
        number(d, body, "revision", &m->revision) || !m->revision ||
        number(d, body, "Issued", &issued) || !issued || issued > INT64_MAX ||
        number(d, body, "Expires", &expires) || expires > INT64_MAX ||
        expires <= issued || expires - issued > 900000 ||
        (port_token >= 0 && wn_doc_u64(d, port_token, &port)) ||
        port > 65535 ||
        wn_doc_string(d, wn_doc_member(d, body, "device"), uuid,
                       sizeof uuid) < 0 ||
        wn_uuid_parse(uuid, m->device) ||
        number(d, route, "routerId", &m->origin.router_id) ||
        !m->origin.router_id || m->origin.router_id == UINT64_MAX ||
        number(d, route, "seqno", &seq) || seq > 65535 ||
        wn_doc_string(d, wn_doc_member(d, route, "prefix"), prefix,
                       sizeof prefix) < 0)
        return -1;
    size_t n = strlen(prefix);
    if (n < 5 || strcmp(prefix + n - 4, "/128"))
        return -1;
    prefix[n - 4] = 0;
    wn_address(m->device, expected);
    if (inet_pton(AF_INET6, prefix, actual) != 1 ||
        memcmp(actual, expected, 16))
        return -1;
    if (name >= 0 && (d->tokens[name].type != '"' ||
                      d->tokens[name].end - d->tokens[name].start > 1532))
        return -1;
    if (withdraw >= 0)
    {
        char type = d->tokens[withdraw].type;
        if (type != 't' && type != 'f')
            return -1;
        m->withdraw = type == 't';
    }
    if (!m->withdraw && !port)
        return -1;
    if (agent >= 0)
    {
        if (wn_doc_equal(d, agent, "mtls-v1") && port)
            m->agent_mtls = true;
        else if (!wn_doc_equal(d, agent, ""))
            return WND_UNSUPPORTED;
    }
    m->agent_port = (uint16_t)port;
    int platform=wn_doc_member(d,body,"platform");
    if(platform>=0){
        char value[33];
        if(wn_doc_string(d,platform,value,sizeof value)<0)return -1;
        m->platform_lite=!strcmp(value,"Lite");
    }
    int caps=wn_doc_member(d,body,"caps");
    if(caps>=0){
        if(d->tokens[caps].type!='[')return -1;
        unsigned count=0;
        for(unsigned i=(unsigned)caps+1;i<d->tokens[caps].next;i=d->tokens[i].next){
            char value[65];
            if(++count>16 || wn_doc_string(d,(int)i,value,sizeof value)<=0 || !extension_name(value))return -1;
            for(unsigned j=(unsigned)caps+1;j<i;j=d->tokens[j].next)
                if(wn_doc_equal(d,(int)j,value))return -1;
            if(!strcmp(value,"sensors"))m->sensors=true;
        }
    }
    int requires=wn_doc_member(d,body,"requires");
    if(requires>=0){
        if(d->tokens[requires].type!='[')return -1;
        unsigned count=0;
        for(unsigned i=(unsigned)requires+1;i<d->tokens[requires].next;i=d->tokens[i].next){
            char value[65];
            if(++count>16 || wn_doc_string(d,(int)i,value,sizeof value)<=0 || !extension_name(value))return -1;
            for(unsigned j=(unsigned)requires+1;j<i;j=d->tokens[j].next)
                if(wn_doc_equal(d,(int)j,value))return -1;
        }
        /* Baseline v4 defines the mechanism and no named required extensions. */
        if(count)return WND_UNSUPPORTED;
    }
    m->issued = (int64_t)issued;
    m->expires = (int64_t)expires;
    m->origin.seqno = (uint16_t)seq;
    int services=wns_manifest_services_validate(d,body);
    return services ? services:app_endpoints(d, body, m);
}
static int accept_manifest(struct wnd_directory *d, const void *data, size_t size,
               int64_t now, int64_t monotonic,bool verified)
{
    static const char *const fields[] = {"principal", "body", "signature",
                                         NULL};
    struct wn_doc doc;
    struct wnd_manifest m;
    char principal[106];
    uint8_t uuid[16],hash[32];
    const uint8_t *signature;
    size_t signature_size = 0;
    if (!d || now <= 0 || now > INT64_MAX - 905000 || monotonic < 0 ||
        monotonic > INT64_MAX - INT64_C(905000000) ||
        wn_doc_parse_array_view(&doc, data, size, 40 * 1024,"s") ||
        !wn_doc_fields(&doc, 0, fields))
        return -1;
    int body = wn_doc_member(&doc, 0, "body");
    if(body<0)return -1;
    int decoded=wnd_manifest_read(&doc,(unsigned)body,&m);if(decoded)return decoded;
    if (
        wn_doc_string(&doc, wn_doc_member(&doc, 0, "principal"), principal,
                       sizeof principal) < 0 ||
        wn_principal_device(principal, d->tenant, uuid) ||
        memcmp(uuid, m.device, 16) ||
        wn_doc_bytes(&doc,wn_doc_member(&doc,0,"signature"),&signature,&signature_size) ||
        signature_size<8 || signature_size>WN_ORIGIN_SIGNATURE_MAX ||
        m.issued > now + 5000)
        return -1;
    if (m.expires <= now)
        return 1;
    struct wnd_entry *e = find(d, uuid);
    if (!e || !e->peer.spki_size)
        return 2;
    if (e->peer.expires <= now / 1000 ||
        m.expires > (int64_t)e->peer.expires * 1000)
        return -1;
    if (m.revision < e->revision)
        return 1;
    const struct wn_token *t = &doc.tokens[body];
    const char *raw = doc.text + t->start;
    size_t n = t->end - t->start;
    if (n > 32768 ||
        (!verified && wendy_pki_mesh_verify_key(&e->peer, principal, raw, n, signature,
                              signature_size)) ||
        wendy_pki_sha256((const uint8_t *)raw, n, hash))
        return -1;
    if (m.revision == e->revision && memcmp(hash, e->body_hash, 32))
        return -1;
    int64_t deadline = m.withdraw ? 0 : monotonic + (m.expires - now) * 1000;
    if (m.revision == e->revision && e->deadline_us > 0 &&
        deadline > e->deadline_us)
        deadline = e->deadline_us;
    e->revision = m.revision;
    memcpy(e->body_hash, hash, 32);
    e->manifest = m;
    e->deadline_us = deadline;
    return 0;
}
static const struct wnd_entry *owner(const struct wnd_directory *d,
                                     const uint8_t address[16], int64_t now)
{
    const struct wnd_entry *found = NULL;
    if (!d || !address || now < 0)
        return NULL;
    for (const struct wnd_entry *e = d->entries; e; e = e->next)
        if (e->deadline_us > now && !memcmp(e->address, address, 16))
        {
            if (found)
                return NULL;
            found = e;
        }
    return found;
}
bool wnd_address(const struct wnd_directory *d, const uint8_t address[16],
                 int64_t now)
{
    return owner(d, address, now) != NULL;
}
bool wnd_authorizes(const struct wnd_directory *d, const uint8_t address[16],
                    uint64_t router, uint16_t seqno, int64_t now)
{
    const struct wnd_entry *e = owner(d, address, now);
    return e && e->manifest.origin.router_id == router &&
           e->manifest.origin.seqno == seqno;
}
static void put64(uint8_t *out, uint64_t n)
{
    for (unsigned i = 0; i < 8; i++)
        out[7 - i] = (uint8_t)(n >> (i * 8));
}
static uint64_t get64(const uint8_t *in)
{
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; i++)
        n = (n << 8) | in[i];
    return n;
}
int wnd_save(const struct wnd_directory *d, void *data, size_t capacity)
{
    if (!d || (data && capacity < 6))
        return -1;
    uint8_t *out = data;
    unsigned count = 0;
    size_t n = 6;
    if(out)memcpy(out, "WDR1", 4);
    const struct wnd_entry *previous = NULL;
    for (;;)
    {
        const struct wnd_entry *next = NULL;
        for (const struct wnd_entry *e = d->entries; e; e = e->next)
            if (e->revision &&
                (!previous || memcmp(e->device, previous->device, 16) > 0) &&
                (!next || memcmp(e->device, next->device, 16) < 0))
                next = e;
        if (!next)
            break;
        if (out && capacity - n < 56)
            return -1;
        if(out) {
            memcpy(out + n, next->device, 16);
            put64(out + n + 16, next->revision);
            memcpy(out + n + 24, next->body_hash, 32);
        }
        n += 56;
        count++;
        previous = next;
    }
    if(out)wn_put16(out + 4, (uint16_t)count);
    return (int)n;
}
int wnd_restore(struct wnd_directory *d, const void *data, size_t size)
{
    const uint8_t *in = data;
    if (!d || !in || size < 6 || d->entries || d->count ||
        memcmp(in, "WDR1", 4))
        return -1;
    unsigned count = wn_get16(in + 4);
    if (count > WND_ORIGINS_MAX || size != 6 + count * 56)
        return -1;
    struct wnd_directory next = *d;
    uint8_t zero[16] = {0};
    for (unsigned i = 0; i < count; i++)
    {
        const uint8_t *p = in + 6 + i * 56;
        uint8_t address[16];
        wn_address(p, address);
        if (!memcmp(p, zero, 16) || !memcmp(address, d->self_address, 16) ||
            find(&next, p) || !get64(p + 16))
            goto fail;
        struct wnd_entry *e = insert(&next, p);
        if (!e)
            goto fail;
        e->revision = get64(p + 16);
        memcpy(e->body_hash, p + 24, 32);
    }
    *d = next;
    return 0;
fail:
    wnd_deinit(&next);
    return -1;
}
size_t wnd_memory(const struct wnd_directory *d)
{
    size_t bytes = sizeof *d;
    for (const struct wnd_entry *e=d->entries; e; e=e->next)
        bytes += sizeof *e + e->peer.spki_size;
    return bytes;
}

int wnd_accept(struct wnd_directory *d,const void *data,size_t size,int64_t now,int64_t monotonic)
{return accept_manifest(d,data,size,now,monotonic,false);}
int wnd_accept_verified(struct wnd_directory *d,const void *data,size_t size,int64_t now,int64_t monotonic)
{return accept_manifest(d,data,size,now,monotonic,true);}
