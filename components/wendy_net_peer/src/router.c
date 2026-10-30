/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_router.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_crypto.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static void put64(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++)
        p[7 - i] = (uint8_t)(v >> (8 * i));
}
static bool receipt_pending(const struct wnr_core *c,const uint8_t address[16])
{
    for(const struct wnd_entry *e=c->directory.entries;e;e=e->next)
        if(!memcmp(e->address,address,16))return e->pending_receipt;
    return false;
}
static bool allowed(void *context, uint64_t router, const struct wb_prefix *p,
                    uint16_t seqno)
{
    struct wnr_core *c = context;
    return p->family == 6 && p->bits == 128 && !receipt_pending(c,p->bytes) &&
           (wnd_authorizes(&c->directory, p->bytes, router, seqno, c->now_us) ||
            wno_authorizes(c->operators,p->bytes,router,seqno,c->now_us));
}
static int stop(struct wnr_core *c, const char *stage, int error)
{
    if (!c->stopped) { c->stop_stage = stage; c->stop_error = error; }
    c->stopped = true;
    c->ready = false;
    c->babel.stopped = true;
    return WB_STOPPED;
}
static int clock_at(struct wnr_core *c, int64_t unix_ms, int64_t monotonic_us)
{
    if (!c || c->stopped || !c->started)
        return WB_STOPPED;
    if (monotonic_us < c->now_us || unix_ms <= 0 ||
        unix_ms > INT64_MAX - 125000 ||
        monotonic_us > INT64_MAX - INT64_C(125000000))
        return WB_INVALID;
    c->now_us = monotonic_us;
    c->unix_ms = unix_ms;
    c->ready = false;
    return 0;
}
static uint64_t babel_now(const struct wnr_core *c)
{
    return (uint64_t)(c->now_us - c->epoch_us) / 1000;
}
static bool links(const struct wnr_core *c)
{
    for (size_t i = 0; i < c->babel.links_capacity; i++)
        if (c->babel.links[i].config.id)
            return true;
    return false;
}
static bool route_live(const struct wnr_core *c, const struct wb_route *route,
                       int64_t monotonic)
{
    if (route->local)
        return true;
    uint64_t now = (uint64_t)(monotonic - c->epoch_us) / 1000;
    bool link = false;
    for (size_t i = 0; i < c->babel.links_capacity; i++)
    {
        const struct wb_link_state *l = &c->babel.links[i];
        if (l->config.id == route->link && l->tx != WB_INFINITY &&
            l->ihu_expires > now &&
            (l->hello_expires[0] > now || l->hello_expires[1] > now))
            link = true;
    }
    if (!link)
        return false;
    for (size_t i = 0; i < c->babel.candidates_capacity; i++)
    {
        const struct wb_candidate *candidate = &c->babel.candidates[i];
        const struct wb_route *r = &candidate->route;
        if (candidate->used && candidate->expires > now &&
            candidate->advertised != WB_INFINITY && r->link == route->link &&
            r->router == route->router && r->seqno == route->seqno &&
            wb_prefix_equal(&r->prefix, &route->prefix))
            return true;
    }
    return false;
}
static bool service_endpoint(const struct wnr_core *c, const uint8_t device[16],
                              int64_t monotonic, bool agent, uint16_t *port)
{
    if (!c || !device || !port)
        return false;
    *port = 0;
    uint8_t address[16];
    struct wb_route route;
    wn_address(device, address);
    if (!wnr_lookup(c, address, monotonic, &route) || route.local)
        return false;
    if(c->config.endpoint_gateway)
        return wne_endpoint(&c->endpoints,device,agent,monotonic,port);
    for (const struct wnd_entry *e = c->directory.entries; e; e = e->next)
        if (!memcmp(e->device, device, 16) &&
            (agent ? e->manifest.agent_mtls && e->manifest.agent_port :
                     e->manifest.tls_app_port != 0) &&
            !e->manifest.withdraw && e->deadline_us > monotonic)
        {
            *port = agent ? e->manifest.agent_port : e->manifest.tls_app_port;
            return true;
        }
    return false;
}
bool wnr_app_endpoint(const struct wnr_core *c, const uint8_t device[16],
                      int64_t monotonic, uint16_t *port)
{
    return service_endpoint(c, device, monotonic, false, port);
}
bool wnr_agent_endpoint(const struct wnr_core *c, const uint8_t device[16],
                        int64_t monotonic, uint16_t *port)
{
    return service_endpoint(c, device, monotonic, true, port);
}
static int persist(struct wnr_core *c)
{
    /* Firmware commits to its already-owned bounded RAM state. Do not build
     * a second serialized copy or write flash for each routing event. */
    if(!c->config.persist){
        c->durable=true;
        for(struct wnd_entry *e=c->directory.entries;e;e=e->next)e->pending_receipt=false;
        return 0;
    }
    c->durable=false;
    int expected_b = wb_save(&c->babel, NULL, 0),
        expected_d = wnd_save(&c->directory, NULL, 0);
    if (expected_b < 0 || expected_d < 0 || expected_b > WB_HISTORY_MAX ||
        expected_d > WND_RECEIPTS_MAX)
        return -1;
    size_t exact_size =
        WNR_JOURNAL_HEADER + (size_t)expected_b + (size_t)expected_d + 32;
    c->checkpoint_bytes = exact_size;
    /* Reuse the actual journal-sized workspace. Repeatedly allocating it on
     * every tick fragments the TLS peak and can stop an unchanged router for
     * lack of a small contiguous block. Grow only when durable state grows;
     * never reserve WNR_JOURNAL_MAX for a small mesh. */
    if (exact_size > c->checkpoint_capacity) {
        uint8_t *grown = wendy_net_realloc(c->checkpoint, exact_size);
        if (!grown)
            return 1;
        c->checkpoint = grown;
        c->checkpoint_capacity = exact_size;
    }
    uint8_t *out = c->checkpoint;
    memcpy(out, c->scope, sizeof c->scope);
    int b = wb_save(&c->babel, out + WNR_JOURNAL_HEADER, (size_t)expected_b);
    int d = b == expected_b
                ? wnd_save(&c->directory, out + WNR_JOURNAL_HEADER + b,
                           (size_t)expected_d)
                : -1;
    uint8_t hash[32];
    int result=-1;
    if(b==expected_b && d==expected_d && b>0 && d>0){
        size_t size=WNR_JOURNAL_HEADER+(size_t)b+(size_t)d;
        wn_put32(out+76,(uint32_t)b);wn_put32(out+80,(uint32_t)d);
        if(!wendy_pki_sha256(out,size,hash)){
            if(c->saved && !memcmp(hash,c->saved_hash,32))result=0;
            else{memcpy(out+size,hash,32);result=c->config.persist(c->config.context,out,size+32);}
            if(!result){memcpy(c->saved_hash,hash,32);c->saved=true;}
        }
    }
    c->durable=result==0;
    if(c->durable)for(struct wnd_entry *e=c->directory.entries;e;e=e->next)e->pending_receipt=false;
    return result;
}
static int finish(struct wnr_core *c, int result)
{
    if (result < 0)
        return stop(c, "babel-event", result);
    int checkpoint = persist(c);
    if(checkpoint>0){
        if(c->babel.pending && wb_commit(&c->babel,c->babel.pending,true))return stop(c,"babel-commit",0);
        c->ready=true;return 0;
    }
    if(checkpoint<0)return stop(c,"checkpoint-write",checkpoint);
    if (links(c))
    {
        if ((!c->published || c->publication_pending || c->publication_dirty || c->published_seqno != c->babel.seqno ||
            c->now_us - c->published_us >= INT64_C(300000000)) &&
            (!c->published || c->publication_pending || c->now_us-c->published_us>=INT64_C(1000000)))
        {
            struct wn_origin origin = {.router_id = c->babel.config.router,
                                       .seqno = c->babel.seqno};
            int publication = c->config.publish(c->config.context, &origin,
                                                c->unix_ms, c->now_us);
            if(publication>0){
                c->publication_pending=true;
                /* The exact signed origin is a pending effect. Commit local
                 * routing state but hold datagrams until authorization exists. */
                if(c->babel.pending && wb_commit(&c->babel,c->babel.pending,true))return stop(c,"babel-commit",0);
                c->ready=true;return 0;
            }
            if(publication<0)return stop(c,"origin-publication",publication);
            c->publication_pending=false;
            c->published = true;
            c->published_us = c->now_us;
            c->published_seqno = c->babel.seqno;
        }
        /* A sequence can change inside the one-second publication gate.
         * Keep its queued Babel updates until the matching signed origin is
         * available; established IP forwarding still uses committed routes. */
        if(c->published_seqno!=c->babel.seqno){
            if(c->babel.pending && wb_commit(&c->babel,c->babel.pending,true))
                return stop(c,"babel-commit",0);
            c->ready=true;return 0;
        }
    }
    else
        c->published = false;
    if (c->babel.pending && wb_commit(&c->babel, c->babel.pending, true))
        return stop(c, "babel-commit", 0);
    uint8_t packet[WB_PACKET_MAX];
    for (;;)
    {
        uint64_t link;
        int n = wb_next_packet(&c->babel, &link, packet, sizeof packet);
        if (n < 0)
            return stop(c, "babel-encode", n);
        int sent = n ? c->config.send(c->config.context, link, packet, n) : 0;
        if (sent)
            return stop(c, "babel-send", sent);
        if (!n)
            break;
    }
    c->ready = true;
    return 0;
}
bool wnr_busy(const struct wnr_core *c)
{return c->babel.pending || c->babel.message_cursor<c->babel.message_count;}
static int pending_finish(struct wnr_core *c)
{
    if(!wnr_busy(c))return 0;
    return finish(c,0);
}
int wnr_init(struct wnr_core *c, const struct wnr_config *cfg,
             int64_t monotonic, const void *journal, size_t size)
{
    if (!c || !cfg || !cfg->publish || !cfg->send ||
        (cfg->endpoint_gateway && !cfg->non_transit) ||
        monotonic < 0 || monotonic > INT64_MAX - INT64_C(125000000) ||
        (!!journal != !!size) ||
        wnd_init(&c->directory, cfg->tenant, cfg->device))
        return WB_INVALID;
    c->config = *cfg;
    /* Do not retain configuration strings whose storage may be temporary. */
    c->config.tenant = c->config.device = NULL;
    c->now_us = c->epoch_us = monotonic;
    memcpy(c->scope, "WNR1", 4);
    if (wn_uuid_parse(cfg->tenant, c->scope + 4))
        return stop(c, "state", 0);
    memcpy(c->scope + 20, c->directory.self, 16);
    memcpy(c->scope + 36, cfg->trust_hash, 32);
    put64(c->scope + 68, cfg->router);
    struct wb_config b = {.router = cfg->router,
                          .seed = cfg->seed,
                          .hello_ms = 4000,
                          .update_ms = 16000,
                          .local_only = cfg->endpoint_gateway,
                          .allow = allowed,
                          .context = c};
    if (journal)
    {
        const uint8_t *in = journal;
        uint8_t hash[32];
        if (size < WNR_JOURNAL_HEADER + 32 || size > WNR_JOURNAL_MAX ||
            wendy_pki_sha256(in, size - 32, hash) ||
            memcmp(hash, in + size - 32, 32) ||
            memcmp(in, c->scope, sizeof c->scope))
            return stop(c, "state", 0);
        uint32_t bs = wn_get32(in + 76), ds = wn_get32(in + 80);
        if (bs > WB_HISTORY_MAX || ds > WND_RECEIPTS_MAX ||
            size != WNR_JOURNAL_HEADER + (size_t)bs + ds + 32 ||
            wb_restore(&c->babel, &b, in + WNR_JOURNAL_HEADER, bs) ||
            wnd_restore(&c->directory, in + WNR_JOURNAL_HEADER + bs, ds))
            return stop(c, "state", 0);
    }
    else if (wb_init(&c->babel, &b))
        return stop(c, "state", 0);
    /* No export is possible until the first independently timed event. */
    return 0;
}
void wnr_deinit(struct wnr_core *c)
{
    if (!c)
        return;
    wb_deinit(&c->babel);
    wnd_deinit(&c->directory);
    wne_clear(&c->endpoints);
    if(c->operators){wno_deinit(c->operators);wendy_net_free(c->operators);}
    wendy_net_free(c->checkpoint);
    memset(c, 0, sizeof *c);
}
int wnr_start(struct wnr_core *c, int64_t unix_ms, int64_t now)
{
    if (!c || c->started || c->stopped)
        return WB_INVALID;
    c->started = true;
    int r = clock_at(c, unix_ms, now);
    if (r)
        return stop(c, "state", 0);
    struct wb_prefix self = {.bits = 128, .family = 6};
    memcpy(self.bytes, c->directory.self_address, 16);
    return finish(c, wb_originate(&c->babel, babel_now(c), &self, 0));
}
int wnr_identity(struct wnr_core *c, const struct wendy_pki_mesh_peer *peer,
                 int64_t unix_ms, int64_t now)
{
    int r = clock_at(c, unix_ms, now);
    if (r)
        return r;
    r = wnd_identity(&c->directory, peer);
    if(c->config.endpoint_gateway)wnd_forget_keyless(&c->directory);
    /* A replaced or shortened identity revokes old forwarding immediately. */
    if (finish(c, wnr_busy(c) ? 0:wb_tick(&c->babel, babel_now(c))))
        return WB_STOPPED;
    return r;
}
int wnr_manifest(struct wnr_core *c, const void *data, size_t size,
                 int64_t unix_ms, int64_t now)
{
    int r = clock_at(c, unix_ms, now);
    if (r)
        return r;
    r = wnd_accept(&c->directory, data, size, unix_ms, now);
    if (finish(c, wnr_busy(c) ? 0:wb_tick(&c->babel, babel_now(c))))
        return WB_STOPPED;
    return r;
}
int wnr_manifest_verified(struct wnr_core *c, const void *data, size_t size,
                 int64_t unix_ms, int64_t now)
{
    int r = clock_at(c, unix_ms, now);
    if (r)
        return r;
    r = wnd_accept_verified(&c->directory, data, size, unix_ms, now);
    if (finish(c, wnr_busy(c) ? 0:wb_tick(&c->babel, babel_now(c))))
        return WB_STOPPED;
    return !r && !c->durable ? 4:r;
}
int wnr_operator_manifest_verified(struct wnr_core *c,const struct wno_manifest *proof,
    const struct wendy_pki_operator_peer *identity,int64_t unix_ms,int64_t now)
{
    if(c && c->config.endpoint_gateway)return 1;
    int r=clock_at(c,unix_ms,now);if(r)return r;
    if(!c->operators){
        c->operators=wendy_net_calloc(1,sizeof *c->operators);
        if(c->operators && wno_init(c->operators,c->directory.tenant,WNO_DIRECTORY_MAX))return -1;
    }
    r=c->operators ? wno_accept_manifest_verified(c->operators,proof,identity,unix_ms,now):3;
    if(finish(c,wnr_busy(c) ? 0:wb_tick(&c->babel,babel_now(c))))return WB_STOPPED;
    return r;
}
static int attach(struct wnr_core *c,bool first,uint16_t cost,
    int64_t unix_ms,int64_t now,uint64_t *id)
{
    if(!c || !id || !cost || cost==WB_INFINITY)return WB_INVALID;
    int r = clock_at(c, unix_ms, now);
    if (r)
        return r;
    if(pending_finish(c))return WB_STOPPED;
    if(wnr_busy(c))return 1;
    if(c->config.endpoint_gateway && links(c))return WB_LIMIT;
    if (c->babel.last_link == UINT64_MAX)
        return stop(c, "state", 0);
    struct wb_link link = {.id = c->babel.last_link + 1,
                           .local = {0xfe, 0x80},
                           .peer = {0xfe, 0x80},
                           .cost = cost,
                           .max_packet = WB_PACKET_MAX};
    link.local[15] = first ? 1 : 2;
    link.peer[15] = first ? 2 : 1;
    r = finish(c, wb_add_link(&c->babel, babel_now(c), &link));
    if (!r)
        *id = link.id;
    return r;
}
int wnr_attach(struct wnr_core *c,const char *peer,uint16_t cost,
    int64_t unix_ms,int64_t now,uint64_t *id)
{
    uint8_t uuid[16];
    if(!c || wn_uuid_parse(peer,uuid) || !memcmp(uuid,c->directory.self,16))return WB_INVALID;
    return attach(c,memcmp(c->directory.self,uuid,16)<0,cost,unix_ms,now,id);
}
int wnr_attach_operator(struct wnr_core *c,uint16_t cost,
    int64_t unix_ms,int64_t now,uint64_t *id)
{
    if(!c || c->config.non_transit || c->config.endpoint_gateway)return WB_INVALID;
    /* meshid.Compare orders the same-tenant device principal before operator. */
    return attach(c,true,cost,unix_ms,now,id);
}
int wnr_detach(struct wnr_core *c,uint64_t link,int64_t unix_ms,int64_t now)
{
    int r=clock_at(c,unix_ms,now);if(r)return r;
    if(pending_finish(c))return WB_STOPPED;
    if(wnr_busy(c)){
        for(unsigned i=0;i<WB_LINKS;i++)if(!c->detaching[i] || c->detaching[i]==link){c->detaching[i]=link;return 0;}
        return stop(c,"detach-bound",WB_LIMIT);
    }
    return finish(c,wb_remove_link(&c->babel,babel_now(c),link));
}
int wnr_receive(struct wnr_core *c,uint64_t link,const void *data,size_t size,int64_t unix_ms,int64_t now)
{
    int r=clock_at(c,unix_ms,now);if(r)return r;
    if(pending_finish(c))return WB_STOPPED;
    if(wnr_busy(c))return 1; /* Caller retains this frame and pauses reads. */
    return finish(c,wb_receive(&c->babel,babel_now(c),link,data,size));
}
int wnr_tick(struct wnr_core *c,int64_t unix_ms,int64_t now)
{
    int r=clock_at(c,unix_ms,now);if(r)return r;
    wne_reap(&c->endpoints,now);
    wno_expire(c->operators,now);
    if(pending_finish(c))return WB_STOPPED;
    if(wnr_busy(c))return 0;
    for(unsigned i=0;i<WB_LINKS;i++)if(c->detaching[i]){
        uint64_t link=c->detaching[i];c->detaching[i]=0;
        r=finish(c,wb_remove_link(&c->babel,babel_now(c),link));
        if(r || wnr_busy(c))return r;
    }
    return finish(c,wb_tick(&c->babel,babel_now(c)));
}
bool wnr_lookup(const struct wnr_core *c, const uint8_t address[16],
                int64_t now, struct wb_route *out)
{
    if (!c || !address || !out || !c->ready || c->stopped || now < c->now_us)
        return false;
    struct wb_prefix host = {.bits = 128, .family = 6};
    memcpy(host.bytes, address, 16);
    if(c->config.endpoint_gateway && memcmp(address,c->directory.self_address,16)){
        static const uint8_t prefix[5]={0xfd,0x45,0xb8,0x91,0x56};
        if(memcmp(address,prefix,sizeof prefix) || (address[5]!=0x7f && address[5]!=0x80))return false;
        const struct wb_link_state *gateway=NULL;
        for(size_t i=0;i<c->babel.links_capacity;i++)if(c->babel.links[i].config.id){
            if(gateway)return false;
            gateway=c->babel.links+i;
        }
        if(!gateway)return false;
        *out=(struct wb_route){.prefix=host,.link=gateway->config.id,
            .metric=gateway->config.cost,.next_family=6};
        memcpy(out->next_hop,gateway->config.peer,16);return true;
    }
    const struct wb_route *route = wb_lookup(&c->babel, &host);
    if (!route || route->unreachable || route->metric == WB_INFINITY ||
        !route_live(c, route, now) ||
        (!route->local && (receipt_pending(c,address) ||
            !(wnd_authorizes(&c->directory,address,route->router,route->seqno,now) ||
              wno_authorizes(c->operators,address,route->router,route->seqno,now)))))
        return false;
    *out = *route;
    return true;
}
int wnr_packet(const struct wnr_core *c, uint64_t incoming, void *data,
               size_t size, int64_t now, uint64_t *outgoing)
{
    uint8_t *p = data;
    struct wb_route source, destination;
    if (!p || !outgoing || size < 40 || size > WN_MTU || (p[0] >> 4) != 6 ||
        wn_get16(p + 4) != size - 40 || !p[7] ||
        !wnr_lookup(c, p + 8, now, &source) ||
        !wnr_lookup(c, p + 24, now, &destination) ||
        (incoming ? source.local : !source.local))
        return -1;
    if (incoming)
    {
        bool known = false;
        for (size_t i = 0; i < c->babel.links_capacity; i++)
            known |= c->babel.links[i].config.id == incoming;
        if (!known)
            return -1;
    }
    if (destination.local)
    {
        *outgoing = 0;
        return 0;
    }
    if ((incoming && c->config.non_transit) || !destination.link || destination.link == incoming)
        return -1;
    if (incoming && p[7] <= 1)
        return -2;
    if (incoming)
        p[7]--;
    *outgoing = destination.link;
    return 1;
}
size_t wnr_memory(const struct wnr_core *c)
{
    return sizeof *c + wb_memory(&c->babel).current - sizeof c->babel +
           wnd_memory(&c->directory) - sizeof c->directory + c->checkpoint_capacity +
           c->endpoints.count*sizeof(struct wne_entry) +
           (c->operators ? sizeof *c->operators+wno_memory(c->operators):0);
}
