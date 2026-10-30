#include "wendy_net_alloc.h"
#include "wendy_net_profile.h"
/* SPDX-License-Identifier: Apache-2.0
 * Single-owner node state shared by authenticated carrier sessions. The
 * firmware actor still serializes admission, routing and gossip. Carrier
 * scheduling and indirect certificate fetching are integrated separately.
 */
#include "router_session.h"
#include "wendy_com_msg.pb.h"
#include "topology_record.h"
#include "catalog_node.h"
#include "certificate_fetch.h"
#include "certificate_store.h"
#include "certificate_wire.h"
#include "certificate_worker.h"
#include "operator_worker.h"
#include "certificate_read.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wendy_net_control.h"
#include "wendy_net_carrier.h"
extern bool wendy_net_app_ready(void);
#include "wendy_pki_crypto.h"
#include "wendy_pki_work.h"
#if ESP_PLATFORM || defined(WENDY_NET_ROUTE_CRYPTO_HOST_TEST)
#define WN_ROUTE_ASYNC 1
#include "crypto_job.h"
#else
#define WN_ROUTE_ASYNC 0
#endif
#if ESP_PLATFORM
#include "wendy_com_cmd.h"
#include "wendy_conf.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CONFIG_WENDY_NET_ENDPOINT_GATEWAY
#define CONFIG_WENDY_NET_ENDPOINT_GATEWAY 0
#endif
#ifndef CONFIG_WENDY_SERVER_PORT
#define CONFIG_WENDY_SERVER_PORT 5054
#endif
#ifndef CONFIG_WENDY_NET_CATALOG_BYTES
#define CONFIG_WENDY_NET_CATALOG_BYTES 32768
#endif

struct pending_manifest {
    struct pending_manifest *next;
    struct wg_id id;
    char principal[106];
    uint64_t supplier;
    int64_t deadline,asked;
    size_t size;
    uint8_t bytes[];
};
struct certificate_upload {
    struct certificate_upload *next;
    uint64_t owner;
    int64_t deadline;
    void *part;
    size_t total;
    uint8_t hash[32];
};
struct wnrs_node
{
    struct wnr_core core;
    struct wg_pool pool;
    struct wnsc_node *catalog;
    struct wendy_pki_mesh_identity clock;
    struct wnrs *sessions;
    struct wnrs_node **owner;
    bool own_cached;
    int64_t tick_us;
    struct wg_id own_artifact;
    struct wncs_store certificates;
    struct certificate_upload *uploads;
    struct wncd_reader certificate_read;
    struct wncv_job *verification;
    struct wnrs *fetch_owner;
    struct pending_manifest *pending;
    size_t pending_bytes;
    unsigned pending_count;
    int64_t verification_retry;

    int64_t endpoint_request_retry;
    uint64_t endpoint_request_supplier;
    uint8_t endpoint_request_device[16];
#if ESP_PLATFORM
    struct route_signature {struct wncrypto_job *job;struct wncrypto_signature completed;struct wn_origin origin;int64_t issued,expires;size_t size;char *body;uint64_t revision;} *signing;
#endif
};
struct wnrs
{
    struct wnrs_node *node;
    struct wnrs *next;
    struct wg_session gossip;

    struct wendy_pki_mesh_identity identity;
    wendy_pki_connection *connection;
    wnrs_send send;
    void *context;
    int (*time_receive)(void *,const struct wn_doc *,unsigned);
    uint8_t peer_address[16],operator_instance[16];
    const struct wendy_pki_operator_peer *operator_peer;
    uint64_t link;
    uint64_t selected_link;
    uint16_t selected_metric;
    bool attached, ready_logged,need_inventory,key_pinned;
    bool inventory_own,inventory_again,inventory_has_after;
    uint8_t inventory_after[16];
    unsigned routing_drops;
    struct wncf_fetch fetch;
    struct wncf_request certificate_reply;
    bool certificate_reply_pending,own_descriptor_pending;
    char descriptor_reply[106];
    uint8_t described_artifact[32];
    bool described;
#if WN_ROUTE_ASYNC
    struct wnop_job *operator_verification;
    uint8_t operator_record[32];
    struct wncrypto_job *record_verification;
    bool verification_blocked;
    int64_t signature_retry;
    signed char record_verdict; /*0none/pending,1verified,-1failed; existing64Bbinding below. */
    uint8_t verified_record[32],verified_record_key[32];
#endif
};
static const char *TAG = "wendy_net_router";
static void route_diagnostic(struct wnrs *s,const uint8_t hash[32],const char *stage,int result)
{
    (void)s;(void)hash;(void)stage;(void)result;
}
#if WN_ROUTE_ASYNC
static void reap_route_verification(struct wnrs *s)
{
    struct wncrypto_verdict result;
    if(wncrypto_take_verification(&s->record_verification,&result)){
        if(result.result)route_diagnostic(s,s->verified_record,"signature-result",result.result);
        s->record_verdict=result.result>0 ? 0:result.result<0 ? -1:1;
        if(result.result>0)s->signature_retry=esp_timer_get_time()+INT64_C(250000);
        s->verification_blocked=false;
    }
}
#endif
static void reap_node_crypto(struct wnrs_node *node)
{
    if(!node)return;
#if WN_ROUTE_ASYNC
    for(struct wnrs *peer=node->sessions;peer;peer=peer->next)reap_route_verification(peer);
#endif
#if ESP_PLATFORM
    if(node->signing)(void)wncrypto_take_signature(&node->signing->job,&node->signing->completed);
#endif

}
size_t wnrs_reclaim_payloads(struct wnrs_node *node,size_t wanted)
{
    return node ? wg_reclaim(&node->pool,wanted):0;
}
static int describe_artifact(struct wnrs *,const struct wg_id *);
static int certificate_tick(struct wnrs *);
static int64_t node_unix(const struct wnrs_node *node)
{
    return (int64_t)node->clock.verified_seconds*1000 +
           (esp_timer_get_time()-node->clock.verified_monotonic_us)/1000;
}
static int64_t unix_now(const struct wnrs *s){return node_unix(s->node);}
/* Descriptor preparation can emit its own message. Keep the CBOR buffer out
 * of that nested path rather than reserving another2KiB in every emit frame. */
static __attribute__((noinline)) int emit_message(struct wnrs *s,const struct wg_message *m)
{
    char text[WN_CONTROL_MAX + 1];
    int n = wn_gossip_write(m, text, sizeof text);
    if(n<0)return -1;
    int r=s->send(s->context,text,n,true);
    return r==WNC_LIMIT || r==WNC_NOMEM ? 1:r;
}
static int emit(void *ctx, const struct wg_message *m)
{
    struct wnrs *s=ctx;
    if(m->op==WG_DATA && !m->offset){
        int r=describe_artifact(s,&m->id);if(r)return r;
    }
    return emit_message(s,m);
}
static void queue_inventory(struct wnrs *s)
{
    if(s->need_inventory){s->inventory_again=true;return;}
    s->need_inventory=true;s->inventory_own=false;s->inventory_has_after=false;
    memset(s->inventory_after,0,sizeof s->inventory_after);
}
static int announce(struct wnrs *s,const struct wg_message *have)
{
    int r=emit(s,have);
    if(r>0){queue_inventory(s);return 0;}
    return r;
}
/* Resume by UUID rather than a pointer into mutable directory storage. A
 * bounded output queue can admit one HAVE per pass without starving the tail.
 * New blocked announcements request one additional sweep after this one. */
static int inventory(struct wnrs *s)
{
    if(!s->need_inventory)return 0;
    struct wnrs_node *node=s->node;
    if(!s->inventory_own){
        if(node->own_cached){
            struct wg_message have={.id=node->own_artifact,.op=WG_HAVE};
            int r=emit(s,&have);if(r)return r;
        }
        s->inventory_own=true;
    }
    for(;;){
        const struct wnd_entry *next=NULL;
        for(const struct wnd_entry *e=node->core.directory.entries;e;e=e->next)
            if(e->gossip_cached && (!s->inventory_has_after || memcmp(e->device,s->inventory_after,16)>0) &&
               (!next || memcmp(e->device,next->device,16)<0))next=e;
        const struct wno_entry *operator=NULL;
        if(node->core.operators)for(const struct wno_entry *e=node->core.operators->entries;e;e=e->next)
            if(e->gossip_cached && (!s->inventory_has_after || memcmp(e->address,s->inventory_after,16)>0) &&
               (!operator || memcmp(e->address,operator->address,16)<0))operator=e;
        if(operator && (!next || memcmp(operator->address,next->device,16)<0)){
            struct wg_message have={.id={.type=1},.op=WG_HAVE};memcpy(have.id.hash,operator->gossip_hash,32);
            int r=emit(s,&have);if(r)return r;
            memcpy(s->inventory_after,operator->address,16);s->inventory_has_after=true;continue;
        }
        if(!next)break;
        struct wg_message have={.id={.type=1},.op=WG_HAVE};
        memcpy(have.id.hash,next->gossip_hash,32);
        int r=emit(s,&have);if(r)return r;
        memcpy(s->inventory_after,next->device,16);s->inventory_has_after=true;
    }
    s->need_inventory=false;
    if(s->inventory_again){s->inventory_again=false;queue_inventory(s);}
    return 0;
}
static int publish(void *ctx, const struct wn_origin *origin, int64_t now,
                   int64_t monotonic)
{
    struct wnrs_node *node=ctx;
    struct wnrs *s=node->sessions;
    if(!s)return -1;
#if ESP_PLATFORM
    if(node->signing)(void)wncrypto_take_signature(&node->signing->job,&node->signing->completed);
    if(wncrypto_borrowed(s->connection))return 1;
    if(!node->signing){
        node->signing=wendy_net_calloc(1,sizeof *node->signing);if(!node->signing)return 1;
        node->signing->origin=*origin;node->signing->issued=now;
        node->signing->expires=now+900000;
        if(node->signing->expires>(int64_t)s->identity.certificate_expires*1000)node->signing->expires=(int64_t)s->identity.certificate_expires*1000;
        uint64_t revision;
        esp_err_t allocated=wendy_pki_mesh_revision_next(&revision);
        if(allocated!=ESP_OK){
            wncrypto_signature_clear(&node->signing->completed);wendy_net_free(node->signing->body);wendy_net_free(node->signing);node->signing=NULL;
            return allocated==ESP_ERR_TIMEOUT ? 1:-1;
        }
        const char *name=wendy_conf_get_resolved_device_display_name();
        int array_size=wnsc_services_write(node->catalog,NULL,0);
        char *array=array_size>0 ? wendy_net_malloc((size_t)array_size+1):NULL;
        if(!array){wendy_net_free(node->signing);node->signing=NULL;return 1;}
        int size=-1;
        if(wnsc_services_write(node->catalog,array,(size_t)array_size+1)==array_size)
            size=wn_manifest_services_write(node->core.directory.self,origin,revision,now,node->signing->expires,CONFIG_WENDY_SERVER_PORT,
                wendy_net_app_ready() ? 43022:0,name,wcom_cmd_sensor_link_available(),array,(size_t)array_size,NULL,0);
        node->signing->body=size>0 ? wendy_net_malloc((size_t)size+1):NULL;
        int written=node->signing->body ? wn_manifest_services_write(node->core.directory.self,origin,revision,now,node->signing->expires,CONFIG_WENDY_SERVER_PORT,
            wendy_net_app_ready() ? 43022:0,name,wcom_cmd_sensor_link_available(),array,(size_t)array_size,node->signing->body,(size_t)size+1):-1;
        wendy_net_free(array);
        if(written!=size || size<=0){wendy_net_free(node->signing->body);wendy_net_free(node->signing);node->signing=NULL;return 1;}
        node->signing->revision=revision;node->signing->size=(size_t)size;
        /* Only this immutable draft leaves the actor. Later service changes
         * set dirty again and survive completion of its crypto loan. */
        node->core.publication_dirty=false;
    }
    char *body=node->signing->body,principal[106];
    int n=(int)node->signing->size;
    int64_t expires=node->signing->expires;
    const uint8_t *signature=NULL;size_t sig_size=0;
    if(wn_principal(s->identity.tenant,s->identity.device,principal)<0)return -1;
    int signed_result=wncrypto_sign_cached(&node->signing->job,&node->signing->completed,0,s->connection,principal,body,(size_t)n,&signature,&sig_size);
    if(signed_result)return signed_result;
    if(node->signing->origin.router_id!=origin->router_id || node->signing->origin.seqno!=origin->seqno || expires<=now){wncrypto_signature_clear(&node->signing->completed);wendy_net_free(node->signing->body);wendy_net_free(node->signing);node->signing=NULL;return 1;}
#else
    char body[768], text[WN_CONTROL_MAX + 1], principal[106];
    uint8_t signature[80];
    size_t sig_size;
    int64_t expires = now + 900000;
    if (expires > (int64_t)s->identity.certificate_expires * 1000)
        expires = (int64_t)s->identity.certificate_expires * 1000;
    uint64_t revision;
    if (expires - now < 5000)return -1;
    esp_err_t allocated=wendy_pki_mesh_revision_next(&revision);
    if(allocated!=ESP_OK)return allocated==ESP_ERR_TIMEOUT ? 1:-1;
    int n = wn_manifest_app_write(
        s->node->core.directory.self, origin, revision, now, expires, CONFIG_WENDY_SERVER_PORT,
        wendy_net_app_ready() ? 43022 : 0, body, sizeof body);
    if (n < 0 || wn_principal(s->identity.tenant, s->identity.device, principal) < 0)return -1;
    int signed_result=wendy_pki_mesh_sign(s->connection,principal,body,n,signature,&sig_size);
    if(signed_result){
        ESP_LOGW(TAG,"route proof signing failed: result=%d heap=%u largest=%u",
            signed_result,(unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
        return -1;
    }
#endif
    int wire_size=wn_manifest_wire_write(principal,body,(size_t)n,signature,sig_size,NULL,0);
    if(wire_size<=0)return -1;
#if ESP_PLATFORM
    char *text=wendy_net_malloc((size_t)wire_size+1);if(!text)return 1;
#else
    if((size_t)wire_size>=sizeof text)return -1;
#endif
    n=wn_manifest_wire_write(principal,body,(size_t)n,signature,sig_size,text,(size_t)wire_size+1);
    struct wg_id id={.type=1};
    uint64_t ms = (uint64_t)monotonic / 1000;
    int identified=n==wire_size ? wn_gossip_identify(NULL,1,text,(size_t)n,id.hash):-1;
    if(n!=wire_size || identified){
#if ESP_PLATFORM
        wendy_net_free(text);
#endif
        return n!=wire_size ? -1:1; /* Preserve the signed draft through hash workspace pressure. */
    }
    if (node->own_cached && memcmp(node->own_artifact.hash,id.hash,32))
        wg_forget(&s->node->pool, &node->own_artifact);
    node->own_cached=false;
    node->own_artifact=id; /* Identify the critical proof before admission. */
    int offered=wg_offer(&s->node->pool, 1, text, n, ms + (uint64_t)(expires - now), ms, &id);
#if ESP_PLATFORM
    wendy_net_free(text);
#endif
    if(offered){
        ESP_LOGW(TAG,"route proof cache admission failed: result=%d bytes=%u payload=%u objects=%u",
            offered,(unsigned)n,(unsigned)node->pool.payload_bytes,(unsigned)node->pool.object_count);
        return offered<0 ? -1:1;
    }
    node->own_artifact = id;
    node->own_cached = true;
#if ESP_PLATFORM
    wnsc_manifest_committed(node->catalog,node->signing->revision,node->signing->issued,node->signing->expires);
    wncrypto_signature_clear(&node->signing->completed);wendy_net_free(node->signing->body);wendy_net_free(node->signing);node->signing=NULL;
#endif
    struct wg_message have = {.id = id, .op = WG_HAVE};
    for(struct wnrs *peer=node->sessions;peer;peer=peer->next){
        int announced=announce(peer,&have);
        if(announced){ESP_LOGW(TAG,"route proof announcement failed: result=%d",announced);return -1;}
    }
    return 0;
}
static bool own_route_artifact(void *context,const struct wg_id *id)
{
    struct wnrs_node *node=context;
    return id->type==1 && !memcmp(node->own_artifact.hash,id->hash,32);
}
static bool protected_artifact(void *context,const struct wg_id *id)
{
    return own_route_artifact(context,id);
}
static bool known_artifact(void *context,const struct wg_id *id)
{
    struct wnrs_node *node=context;
    if(id->type!=1)return false;
    if(id->type==1 && node->core.config.endpoint_gateway)
        for(const struct wne_entry *e=node->core.endpoints.entries;e;e=e->next)
            if(e->deadline_us>esp_timer_get_time() && !memcmp(e->artifact_hash,id->hash,32))return true;
    for(const struct wnd_entry *e=node->core.directory.entries;e;e=e->next)
        if(e->gossip_retired && !memcmp(e->gossip_hash,id->hash,32))return true;
    if(node->core.operators)for(const struct wno_entry *e=node->core.operators->entries;e;e=e->next)
        if(e->gossip_retired && !memcmp(e->gossip_hash,id->hash,32))return true;
    return false;
}
static void evicted_artifact(void *context,const struct wg_id *id,const void *bytes,size_t size)
{
    struct wnrs_node *node=context;(void)size;(void)bytes;
    if(id->type!=1)return;
    for(struct wnd_entry *e=node->core.directory.entries;e;e=e->next)
        if(e->gossip_cached && !memcmp(e->gossip_hash,id->hash,32)){e->gossip_cached=false;e->gossip_retired=true;}
    if(node->core.operators)for(struct wno_entry *e=node->core.operators->entries;e;e=e->next)
        if(e->gossip_cached && !memcmp(e->gossip_hash,id->hash,32)){e->gossip_cached=false;e->gossip_retired=true;}
}
static bool want_artifact(void *context,const struct wg_id *id,uint64_t now)
{
    (void)context;(void)now;return id->type==1;
}
static int babel_send(void *ctx, uint64_t link, const void *packet, size_t size)
{
    struct wnrs_node *node=ctx;
    uint8_t data[WN_DATAGRAM_MAX];
    if(size>sizeof data-1)return -1;
    data[0]=2;memcpy(data+1,packet,size);
    for(struct wnrs *s=node->sessions;s;s=s->next)
        if(s->link==link){
            int r=s->send(s->context,data,size+1,false);
            if(r==WNC_LIMIT || r==WNC_NOMEM){
                if(++s->routing_drops==1 || !(s->routing_drops%16))
                    ESP_LOGW(TAG,"Babel datagram dropped under queue pressure: link=%llu drops=%u",
                        (unsigned long long)link,s->routing_drops);
                return 0; /* Babel retransmits Hellos/updates as on lossy UDP. */
            }
            return r;
        }
    return 0; /* A retired link may still have queued Babel output. */
}
static int describe(struct wnrs *s)
{
#if WN_ROUTE_ASYNC
    if(wncrypto_borrowed(s->connection))return 1;
#endif
    char text[1024];
    struct wn_writer w={.data=(uint8_t*)text,.capacity=sizeof text,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,"certificate");wn_key(&w,"certificate");
    wn_map(&w,1);wn_key(&w,"chain");if(w.failed)return -1;
    int n=wendy_pki_mesh_describe(s->connection,text+w.size,sizeof text-w.size);
    if(n<0)return -1;
    int sent=s->send(s->context,text,w.size+(size_t)n,true);
    return sent==WNC_LIMIT || sent==WNC_NOMEM ? 1:sent;
}
static int certificate_request(struct wnrs *s, const struct wn_doc *d,
                               unsigned request)
{
    struct wncf_request parsed;
    if(wncf_request_read(d,request,&parsed))return -1;
    if(s->certificate_reply_pending)return 0;
    s->certificate_reply=parsed;s->certificate_reply_pending=true;return 0;
}
static int send_control(struct wnrs *s,const char *text,size_t size)
{
    int r=s->send(s->context,text,size,true);
    return r==WNC_LIMIT || r==WNC_NOMEM ? 1:r;
}
/* One whole certificate part per active carrier, never per idle origin. */
static void drop_uploads(struct wnrs_node *node,uint64_t owner)
{
    for(struct certificate_upload **at=&node->uploads;*at;){
        struct certificate_upload *u=*at;
        if(!owner || u->owner==owner){*at=u->next;wncs_release(u->part);wendy_net_free(u);}
        else at=&u->next;
    }
}
static void prune_uploads(struct wnrs_node *node,int64_t now)
{
    for(struct certificate_upload **at=&node->uploads;*at;){
        struct certificate_upload *u=*at;
        if(now>=u->deadline){*at=u->next;wncs_release(u->part);wendy_net_free(u);}
        else at=&u->next;
    }
}
static int hold_upload(struct wnrs_node *node,uint64_t owner,
    const uint8_t hash[32],size_t total)
{
    bool admitted=false;
    for(const struct wnrs *peer=node->sessions;peer;peer=peer->next)if(peer->link==owner)admitted=true;
    if(!admitted)return -1;
    struct certificate_upload **at=&node->uploads;
    while(*at && (*at)->owner!=owner)at=&(*at)->next;
    if(*at && !memcmp((*at)->hash,hash,32)){
        (*at)->deadline=esp_timer_get_time()+INT64_C(60000000);return 0;
    }
    struct certificate_upload *u=wendy_net_calloc(1,sizeof *u);if(!u)return -2;
    u->part=wncs_retain(&node->certificates,hash);
    if(!u->part){wendy_net_free(u);return -2;}
    u->owner=owner;u->total=total;
    u->deadline=esp_timer_get_time()+INT64_C(60000000);memcpy(u->hash,hash,32);
    if(*at){struct certificate_upload *old=*at;u->next=old->next;wncs_release(old->part);wendy_net_free(old);}
    *at=u;return 0;
}
static void release_public_part(struct wnrs_node *node,uint64_t owner,
    const uint8_t hash[32],size_t offset)
{
    wncd_release(&node->certificate_read,owner,hash,offset);
    for(struct certificate_upload **at=&node->uploads;*at;at=&(*at)->next){
        struct certificate_upload *u=*at;
        if(u->owner==owner && !memcmp(u->hash,hash,32)){
            /* Only queue admission of the final chunk ends the whole-part
             * loan. Output pressure keeps it pinned for the retry. */
            if(offset>=u->total || u->total-offset<=WNCF_CHUNK){
                *at=u->next;wncs_release(u->part);wendy_net_free(u);
            }
            return;
        }
    }
}
static int read_public_part(struct wnrs_node *node,uint64_t owner,
    const uint8_t hash[32],size_t offset,uint8_t out[WNCF_CHUNK],size_t *total)
{
    if(!node->certificates.opened)return -1;
    int r=wncs_read_resident(&node->certificates,hash,offset,out,total);
    if(r==1){
        if(offset>=*total)return -1;
        int held=hold_upload(node,owner,hash,*total);if(held)return held;
        size_t count=*total-offset;return (int)(count<WNCF_CHUNK ? count:WNCF_CHUNK);
    }
    if(r<0 || wncs_read(&node->certificates,hash,0,NULL,total)!=1)return -1;
    const struct wendy_pki_mesh_public_index *index=&node->certificates.baseline_index;
    return wncd_read(&node->certificate_read,owner,index->config_generation,
        index->certificate_epoch,hash,offset,*total,out,total);
}
static int serve_part(struct wnrs *s)
{
    if(!s->certificate_reply_pending)return 0;
    struct wncf_request *q=&s->certificate_reply;
    uint8_t part[WNCF_CHUNK];size_t total=0;
    int count=read_public_part(s->node,s->link,q->hash,q->offset,part,&total);
    if(count==-2)return 1;
    if(count<0){
        char wire[192];int n=wncf_missing_write(q,wire,sizeof wire);if(n<0)return -1;
        int sent=send_control(s,wire,(size_t)n);
        if(!sent){s->certificate_reply_pending=false;
            release_public_part(s->node,s->link,q->hash,q->offset);}
        return sent;
    }
    struct wncf_chunk chunk={.offset=q->offset,.total=total,.size=(size_t)count};
    memcpy(chunk.hash,q->hash,32);char text[WN_CONTROL_MAX+1];
    int n=wncf_chunk_write(&chunk,part,text,sizeof text);if(n<0)return -1;
    int r=send_control(s,text,(size_t)n);if(!r){s->certificate_reply_pending=false;
        release_public_part(s->node,s->link,q->hash,q->offset);}
    return r;
}
/* 2 means not cached; descriptions remain public hints, never authority. */
static int send_descriptor(struct wnrs *s,const char *principal)
{
    char own[106];if(wn_principal(s->identity.tenant,s->identity.device,own)<0)return -1;
    if(!strcmp(principal,own)){
        int r=describe(s);return r==WNC_LIMIT || r==WNC_NOMEM ? 1:r;
    }
    struct wncf_chain chain;
    if(wncs_chain_get(&s->node->certificates,principal,unix_now(s)/1000,&chain)!=1)return 2;
    char text[1400];int n=wncf_chain_write(&chain,text,sizeof text);
    return n<0 ? -1:send_control(s,text,(size_t)n);
}
static int describe_artifact(struct wnrs *s,const struct wg_id *id)
{
    if(s->described && !memcmp(s->described_artifact,id->hash,32))return 0;
    char principal[106];const uint8_t *device=NULL;
    if(s->node->own_cached && !memcmp(s->node->own_artifact.hash,id->hash,32))
        device=s->node->core.directory.self;
    else for(struct wnd_entry *e=s->node->core.directory.entries;e;e=e->next)
        if(e->gossip_cached && !memcmp(e->gossip_hash,id->hash,32)){device=e->device;break;}
    if(!device)return 0;
    char uuid[37];wn_uuid_format(device,uuid);
    if(wn_principal(s->identity.tenant,uuid,principal)<0)return -1;
    int r=send_descriptor(s,principal);
    if(r==2)return 0;
    if(!r){memcpy(s->described_artifact,id->hash,32);s->described=true;}
    return r;
}
static int retain_manifest(struct wnrs *s,const struct wg_id *id,const void *bytes,size_t size,int64_t now)
{
    struct wnrs_node *node=s->node;
    for(struct pending_manifest *p=node->pending;p;p=p->next)
        if(!memcmp(p->id.hash,id->hash,32))return 0;
    size_t retained=size;
#if WN_ROUTE_ASYNC
    retained=0; /* The completed gossip download already owns immutable bytes. */
#endif
    if(node->pending_count>=4 || retained>8192-node->pending_bytes)return 0;
    struct wn_doc doc;char principal[106];uint8_t uuid[16];
    if(wn_doc_parse_array_view(&doc,bytes,size,WG_OBJECT_MAX,"s") ||
       wn_doc_string(&doc,wn_doc_member(&doc,0,"principal"),principal,sizeof principal)!=105 ||
       wn_principal_device(principal,s->identity.tenant,uuid))return -1;
    struct pending_manifest *p=wendy_net_calloc(1,sizeof *p+retained);if(!p)return WG_DEFER;
    p->id=*id;memcpy(p->principal,principal,106);p->supplier=s->link;
    p->size=retained;p->deadline=now+INT64_C(60000000);memcpy(p->bytes,bytes,retained);
    p->next=node->pending;node->pending=p;node->pending_count++;node->pending_bytes+=retained;
    return 0;
}
static int admit_complete(void *ctx, const struct wg_id *id, const void *bytes,
                    size_t size)
{
    struct wnrs *s = ctx;
    int64_t now = esp_timer_get_time();
    int r =
#if WN_ROUTE_ASYNC
        wnr_manifest_verified(&s->node->core,bytes,size,unix_now(s),now);
#else
        wnr_manifest(&s->node->core, bytes, size, unix_now(s), now);
#endif
    if(r==4)return WG_DEFER;
    if(r==2)return retain_manifest(s,id,bytes,size,now);
    if(r==1 || r==3 || r==WND_UNSUPPORTED)return 0; /* No claim; keep healthy carrier. */
    if (r){route_diagnostic(s,id->hash,"manifest-admission",r);return -1;}
    struct wn_doc d;
    char principal[106];
    uint8_t uuid[16];
    if (wn_doc_parse_array_view(&d, bytes, size, WG_OBJECT_MAX,"s") ||
        wn_doc_string(&d, wn_doc_member(&d, 0, "principal"), principal,
                       sizeof principal) < 0 ||
        wn_principal_device(principal, s->identity.tenant, uuid)){
        route_diagnostic(s,id->hash,"manifest-projection",-1);return -1;
    }
    for (struct wnd_entry *e = s->node->core.directory.entries; e; e = e->next)
        if (!memcmp(e->device, uuid, 16))
        {
            int64_t until = e->deadline_us;
            if (e->manifest.withdraw)
                until = now + (e->manifest.expires - unix_now(s)) * 1000;
            if (until <= now)
                return 0;
            if(s->node->core.config.endpoint_gateway){
                int cached=wne_update(&s->node->core.endpoints,&e->manifest,e->body_hash,until,now);
                if(cached==3)return WG_DEFER;
                if(cached==2)return -1;
                if(!cached)for(struct wne_entry *endpoint=s->node->core.endpoints.entries;endpoint;endpoint=endpoint->next)
                    if(!memcmp(endpoint->device,uuid,16)){memcpy(endpoint->artifact_hash,id->hash,32);break;}
            }
            int projected=wnsc_manifest_services(s->node->catalog,&d,
                (unsigned)wn_doc_member(&d,0,"body"),uuid,e->manifest.revision,
                e->manifest.issued,e->manifest.expires,e->manifest.withdraw);
            if(projected)return projected>0 ? WG_DEFER:-1;
            struct wg_id accepted;
            if (e->gossip_cached && memcmp(e->gossip_hash, id->hash, 32))
            {
                struct wg_id old = {.type = 1};
                memcpy(old.hash, e->gossip_hash, 32);
                wg_forget(&s->node->pool, &old);
                e->gossip_cached = false;
            }
            if(s->node->core.config.non_transit){
                /* A terminating peer needs the verified route projection, not
                 * a relay copy of every full signature and capability body. */
                memcpy(e->gossip_hash,id->hash,32);
                e->gossip_cached=false;e->gossip_retired=true;
                struct wg_message gone={.id=*id,.op=WG_GONE};
                for(struct wnrs *peer=s->node->sessions;peer;peer=peer->next){
                    int sent=emit(peer,&gone);
                    if(sent)return sent>0 ? WG_DEFER:-1;
                }
                return 0;
            }
            int offered = wg_offer(&s->node->pool, id->type, bytes, size,
                                   (uint64_t)until / 1000, (uint64_t)now / 1000,
                                   &accepted);
            memcpy(e->gossip_hash,id->hash,32);
            e->gossip_retired=offered>0;
            if (!offered)
            {
                memcpy(e->gossip_hash, id->hash, 32);
                e->gossip_cached = true;
            }
            if(!offered){
                struct wg_message have={.id=*id,.op=WG_HAVE};
                for(struct wnrs *peer=s->node->sessions;peer;peer=peer->next)
                    if(peer!=s && announce(peer,&have))return -1;
            }
            return offered<0 ? -1:0;
        }
    return -1;
}
#if WN_ROUTE_ASYNC
/* A typed operator owns an ordinary signed manifest and fetches its exact DER
 * hashes. It does not need a second descriptor format or a special gossip type. */
static int complete_operator(struct wnrs *s,const struct wg_id *id,const void *bytes,size_t size)
{
    struct wnrs_node *node=s->node;
    if(node->core.config.endpoint_gateway)return 0; /* Trusted sole next hop; no remote origin cache. */
    struct wno_manifest proof;
    int parsed=wno_manifest_read(bytes,size,node->clock.tenant,&proof);
    if(parsed==WNO_UNSUPPORTED)return 0;
    if(parsed)return -1;
    if(s->operator_verification){
        struct wnop_job *job=s->operator_verification;
        if(memcmp(s->operator_record,id->hash,32))return WG_DEFER;
        if(!atomic_load(&job->done)){s->verification_blocked=true;return WG_DEFER;}
        s->operator_verification=NULL;s->verification_blocked=false;
        bool current=job->clock.config_generation==node->clock.config_generation &&
            !memcmp(job->clock.trust_hash,node->clock.trust_hash,32);
        int verified=job->result;
        int result=verified;
        if(!verified && current)result=wnr_operator_manifest_verified(&node->core,&proof,job->peer,unix_now(s),esp_timer_get_time());
        wnop_job_release(job);
        if(!current || verified>0){
            s->signature_retry=esp_timer_get_time()+INT64_C(250000);
            return WG_DEFER;
        }
        /* Stale/expired records and a full bounded directory are ordinary
         * terminal outcomes, as for device origins. Do not verify them in a
         * loop while retaining the carrier's completed download slot. */
        if(result==1 || result==3)return 0;
        if(result)return -1;
        struct wno_entry *entry=NULL;
        for(struct wno_entry *e=node->core.operators->entries;e;e=e->next)
            if(e->principal_size==proof.principal_size && !memcmp(e->principal,proof.principal,proof.principal_size) && !memcmp(e->instance,proof.instance,16)){entry=e;break;}
        if(!entry)return -1;
        if(entry->gossip_cached && memcmp(entry->gossip_hash,id->hash,32)){
            struct wg_id old={.type=1};memcpy(old.hash,entry->gossip_hash,32);wg_forget(&node->pool,&old);entry->gossip_cached=false;
        }
        int64_t now=esp_timer_get_time(),until=entry->deadline_us;
        /* Withdrawal revokes the route immediately, but its signed notice
         * remains useful to other peers for the rest of its verified lease. */
        if(proof.withdraw)until=now+(proof.expires-unix_now(s))*1000;
        if(until<=now)return 0;
        struct wg_id accepted;int offered=wg_offer(&node->pool,1,bytes,size,
            (uint64_t)until/1000,(uint64_t)now/1000,&accepted);
        memcpy(entry->gossip_hash,id->hash,32);entry->gossip_cached=!offered;entry->gossip_retired=offered>0;
        if(!offered){struct wg_message have={.id=*id,.op=WG_HAVE};for(struct wnrs *p=node->sessions;p;p=p->next)if(p!=s && announce(p,&have))return -1;}
        return offered<0 ? -1:0;
    }
    int started=wnop_job_start(&s->operator_verification,&node->certificates,bytes,size,&node->clock,NULL);
    if(started==2){
        if(!s->fetch.chain){
            uint8_t hashes[16][32];for(unsigned i=0;i<proof.hash_count;i++)memcpy(hashes[i],proof.hashes[i],32);
            int r=wncf_start_hashes(&s->fetch,hashes,proof.hash_count,esp_timer_get_time()/1000);
            if(r<0)return -1;
        }
        return WG_DEFER;
    }
    if(started<0)return -1;
    if(!started){memcpy(s->operator_record,id->hash,32);s->verification_blocked=true;}
    return WG_DEFER;
}
#endif
#if WN_ROUTE_ASYNC
struct manifest_workspace {struct wn_doc doc;struct wnd_manifest manifest;char principal[106];uint8_t uuid[16];};
#endif
static int complete(void *ctx,const struct wg_id *id,const void *bytes,size_t size)
{
#if WN_ROUTE_ASYNC
    struct wnrs *s=ctx;struct wnrs_node *node=s->node;
    reap_route_verification(s);
    if(esp_timer_get_time()<s->signature_retry)return WG_DEFER;
    s->signature_retry=0;
    if(s->record_verification){s->verification_blocked=true;return WG_DEFER;}
    if(s->record_verdict && memcmp(s->verified_record,id->hash,32))return WG_DEFER;
    if(s->record_verdict<0){s->record_verdict=0;return -1;}
    struct manifest_workspace *w=wendy_net_malloc(sizeof *w);if(!w)return WG_DEFER;
    int result=-1;const char *stage="artifact-envelope";size_t sig_size=0;const uint8_t *signature;struct wnd_entry *identity=NULL;
    if(wn_doc_parse_array_view(&w->doc,bytes,size,WG_OBJECT_MAX,"s"))goto done;
    int owner_body=wn_doc_member(&w->doc,0,"body");
    if(owner_body>=0 && wn_doc_member(&w->doc,(unsigned)owner_body,"o")>=0){
        wendy_net_free(w);return complete_operator(s,id,bytes,size);
    }
    if(wn_doc_string(&w->doc,wn_doc_member(&w->doc,0,"principal"),w->principal,sizeof w->principal)!=105 ||
       wn_principal_device(w->principal,node->clock.tenant,w->uuid))goto done;
    stage="manifest-body";int body=wn_doc_member(&w->doc,0,"body");
    if(body<0)goto done;
    int sig=wn_doc_member(&w->doc,0,"signature");
    if(wn_doc_bytes(&w->doc,sig,&signature,&sig_size) || sig_size<8)goto done;
    if(sig_size>WN_ORIGIN_SIGNATURE_MAX){result=0;goto done;}
    stage="manifest-metadata";int metadata=wnd_manifest_read(&w->doc,(unsigned)body,&w->manifest);
    if(metadata==WND_UNSUPPORTED){
        result=0;goto done;
    }
    /* Service validation owns a temporary parser. Ordinary budget pressure
     * retains this completed download for retry, not a malformed-peer error. */
    if(metadata==4){result=WG_DEFER;goto done;}
    if(metadata)goto done;
    /* Normal gossip can echo a previous boot's own proof. Our publisher owns
     * this origin; no foreign key/identity repair is needed or possible here. */
    if(!memcmp(w->uuid,node->core.directory.self,16)){result=0;goto done;}
    for(struct wnd_entry *e=node->core.directory.entries;e;e=e->next)
        if(!memcmp(e->device,w->uuid,16)){identity=e;break;}
    if(!identity || !identity->peer.spki_size){
        result=retain_manifest(s,id,bytes,size,esp_timer_get_time());
        if(!result)result=WG_DEFER;
        s->verification_blocked=false;goto done;
    }
    stage="signature-field";
    const struct wn_token *t=wn_doc_token(&w->doc,body);
    if(!t)goto done;
    uint8_t key_hash[32];
    if(wendy_pki_sha256(identity->peer.spki,identity->peer.spki_size,key_hash)){
        result=WG_DEFER;goto done; /* Ordinary temporary digest workspace pressure. */
    }
    if(s->record_verdict>0 && !memcmp(s->verified_record_key,key_hash,32))result=0;
    else{
        s->record_verdict=0;memcpy(s->verified_record,id->hash,32);memcpy(s->verified_record_key,key_hash,32);
        stage="signature-dispatch";
        result=wncrypto_verify(&s->record_verification,0,&identity->peer,w->principal,
            w->doc.text+t->start,t->end-t->start,signature,sig_size);
    }
    s->verification_blocked=result>0 && s->record_verification!=NULL;
    if(result>0)result=WG_DEFER;
    else if(!result){
        s->record_verdict=1;
        /* Admission reparses the immutable artifact itself. Do not retain this
         * temporary parser while it hashes the body or queues responses. */
        wendy_net_free(w);w=NULL;
        stage=NULL; /* Admission reports its exact native result itself. */
        result=admit_complete(s,id,bytes,size);
        if(result!=WG_DEFER)s->record_verdict=0;
    }
 done:
    if(result<0 && stage)route_diagnostic(s,id->hash,stage,result);
    wendy_net_free(w);return result;
#else
    return admit_complete(ctx,id,bytes,size);
#endif
}
static void prune_pending(struct wnrs_node *node,int64_t now)
{
    for(struct pending_manifest **at=&node->pending;*at;){
        struct pending_manifest *p=*at;
        if(now>=p->deadline){
            /* Identity repair is an adapter-owned bounded wait. Dropping only
             * its metadata would let the retained completed download recreate
             * a fresh deadline forever and monopolize a global download slot. */
            for(struct wnrs *peer=node->sessions;peer;peer=peer->next)
                if(peer->link==p->supplier){wg_discard(&peer->gossip,&p->id);break;}
            *at=p->next;node->pending_count--;node->pending_bytes-=p->size;
            wendy_net_free(p);
        }else at=&p->next;
    }
}
static struct wnd_entry *chain_identity(struct wnrs_node *node,const struct wncf_chain *chain)
{
    uint8_t uuid[16];if(wn_principal_device(chain->principal,node->clock.tenant,uuid))return NULL;
    for(struct wnd_entry *e=node->core.directory.entries;e;e=e->next)
        if(!memcmp(e->device,uuid,16))return e;
    return NULL;
}
static bool chain_verified(struct wnrs_node *node,const struct wncf_chain *chain)
{
    struct wnd_entry *e=chain_identity(node,chain);uint8_t hash[32];
    int64_t now=node_unix(node)/1000;
    return e && e->peer.spki_size && e->peer.expires>now && e->certificate_chain_until>now &&
        !wendy_pki_sha256((const uint8_t*)chain->hashes,chain->count*32,hash) &&
        !memcmp(hash,e->certificate_chain_hash,32);
}
static void trim_certificates(struct wnrs_node *node)
{
    prune_uploads(node,esp_timer_get_time());
    if(node->core.config.non_transit){
        size_t retired=wncs_trim(&node->certificates);
        if(retired)ESP_LOGI(TAG,"terminating peer DER retired: bytes=%u cached=%u parts=%u descriptors=%u",
            (unsigned)retired,(unsigned)node->certificates.bytes,node->certificates.count,node->certificates.chains);
    }
}
static void finish_verification(struct wnrs *s,int64_t now)
{
    struct wnrs_node *node=s->node;struct wncv_job *job=node->verification;
    if(!job || !atomic_load(&job->done))return;
    node->verification=NULL;
    if(!job->result && job->clock.config_generation==node->clock.config_generation &&
       !memcmp(job->clock.trust_hash,node->clock.trust_hash,32) &&
       !wnr_identity(&node->core,&job->peer,unix_now(s),now)){
        struct wnd_entry *identity=chain_identity(node,&job->chain);
        if(identity)memcpy(identity->certificate_leaf_hash,job->chain.hashes[0],32);
        if(identity && !wendy_pki_sha256((const uint8_t*)job->chain.hashes,
            job->chain.count*32,identity->certificate_chain_hash))
            identity->certificate_chain_until=(int64_t)job->peer.expires;
        if(!node->core.config.non_transit)
            (void)wncs_chain_put(&node->certificates,&job->chain,(int64_t)job->peer.expires);
        ESP_LOGI(TAG,"public peer chain verified: peer=%s parts=%u cached_bytes=%u",
            job->peer.device,job->chain.count,(unsigned)node->certificates.bytes);
        for(struct wnrs *peer=node->sessions;peer;peer=peer->next)
            if(peer->fetch.chain && peer->fetch.chain->count==job->chain.count &&
               !strcmp(peer->fetch.chain->principal,job->chain.principal) &&
               !memcmp(peer->fetch.chain->hashes,job->chain.hashes,job->chain.count*32)){
                if(node->fetch_owner==peer)node->fetch_owner=NULL;
                wncf_stop(&peer->fetch);
            }
#if !WN_ROUTE_ASYNC
        struct pending_manifest *ready=NULL;
        for(struct pending_manifest **at=&node->pending;*at;){
            struct pending_manifest *p=*at;
            if(!strcmp(p->principal,job->chain.principal)){
                *at=p->next;node->pending_count--;node->pending_bytes-=p->size;
                p->next=ready;ready=p;
            }else at=&p->next;
        }
        while(ready){
            struct pending_manifest *p=ready;ready=p->next;
            int result=complete(s,&p->id,p->bytes,p->size);
            if(result<0)ESP_LOGW(TAG,"pending origin could not be applied: peer=%s",job->peer.device);
            wendy_net_free(p);
        }
#endif
#if WN_ROUTE_ASYNC
        for(struct pending_manifest **at=&node->pending;*at;){
            struct pending_manifest *p=*at;
            if(!strcmp(p->principal,job->chain.principal)){
                *at=p->next;node->pending_count--;wendy_net_free(p);
            }else at=&p->next;
        }
#endif
        node->verification_retry=0;
    }else{
        ESP_LOGW(TAG,"public peer verification deferred: peer=%s",job->chain.principal+69);
        node->verification_retry=now+INT64_C(5000000);
        for(struct wnrs *peer=node->sessions;peer;peer=peer->next)
            if(peer->fetch.chain && !strcmp(peer->fetch.chain->principal,job->chain.principal)){
#if CONFIG_WENDY_NET_CONSTRAINED_PROFILE
                if(node->fetch_owner==peer)node->fetch_owner=NULL;
                wncf_stop(&peer->fetch);
#else
                peer->fetch.index=0;peer->fetch.waiting=false;
#endif
            }
    }
    wncv_release(job);
    trim_certificates(node);
}
static int ask_pending_identity(struct wnrs *s,int64_t now)
{
    for(struct pending_manifest *p=s->node->pending;p;p=p->next){
        if(p->asked && now-p->asked<INT64_C(5000000))continue;
        bool supplier_present=false;
        for(struct wnrs *peer=s->node->sessions;peer;peer=peer->next)
            if(peer->link==p->supplier)supplier_present=true;
        if(supplier_present && p->supplier!=s->link)continue;
        char text[192];int n=wn_identity_request_write(p->principal,text,sizeof text);
        if(n<0 || (size_t)n>=sizeof text)return -1;
        int r=send_control(s,text,(size_t)n);if(!r)p->asked=now;
        return r;
    }
    return 0;
}
static void forget_pending_identity(struct wnrs *s,const char *principal)
{
    struct wnrs_node *node=s->node;
    if(s->fetch.chain && !strcmp(s->fetch.chain->principal,principal)){
        if(node->fetch_owner==s)node->fetch_owner=NULL;
        wncf_stop(&s->fetch);
    }
    for(struct pending_manifest **at=&node->pending;*at;){
        struct pending_manifest *p=*at;
        if(p->supplier==s->link && !strcmp(p->principal,principal)){
            *at=p->next;node->pending_count--;node->pending_bytes-=p->size;
            wg_discard(&s->gossip,&p->id);
            wendy_net_free(p);
        }else at=&p->next;
    }
}
static int missing_certificate(struct wnrs *s,const struct wn_doc *d,unsigned token)
{
    struct wncf_request q;if(wncf_request_read(d,token,&q))return -1;
    char principal[106]={0};
    if(s->fetch.chain)memcpy(principal,s->fetch.chain->principal,sizeof principal);
    if(!wncf_missing(&s->fetch,&q))return 0;
    struct wnrs_node *node=s->node;if(node->fetch_owner==s)node->fetch_owner=NULL;
    forget_pending_identity(s,principal);
    trim_certificates(node);return 0;
}
static int certificate_tick(struct wnrs *s)
{
    struct wnrs_node *node=s->node;int64_t now=esp_timer_get_time();
    prune_pending(node,now);finish_verification(s,now);
    trim_certificates(node);
    int r=serve_part(s);if(r<0)return -1;
    if(s->descriptor_reply[0]){
        r=send_descriptor(s,s->descriptor_reply);
        if(r==2){
            char wire[192];int n=wn_directory_missing_write(s->descriptor_reply,false,wire,sizeof wire);
            r=n<0 ? -1:send_control(s,wire,(size_t)n);
        }
        if(r<0)return -1;
        if(r!=1)s->descriptor_reply[0]=0;
    }
    if(!node->certificates.opened || node->verification)return 0;
    if(!s->fetch.chain){r=ask_pending_identity(s,now);return r<0 ? -1:0;}
    if(node->fetch_owner && node->fetch_owner!=s)return 0;
    struct wncf_store store={.context=&node->certificates,.read=wncs_read,.put=wncs_put,
        .retain=wncs_retain,.release=wncs_release};
    struct wncf_request request;
    r=wncf_next(&s->fetch,&store,now/1000,&request);
    if(r<0){
        if(node->fetch_owner==s)node->fetch_owner=NULL;
        wncf_stop(&s->fetch);trim_certificates(node);return 0;
    }
    if(r==2){
        /* Exact hashes came from an operator's signed manifest; its own worker
         * pins and verifies them when the retained download next completes. */
        if(!s->fetch.chain->principal[0]){
            if(node->fetch_owner==s)node->fetch_owner=NULL;
            wncf_stop(&s->fetch);return 0;
        }
        if(chain_verified(node,s->fetch.chain)){
            if(node->fetch_owner==s)node->fetch_owner=NULL;
            wncf_stop(&s->fetch);trim_certificates(node);return 0;
        }
        if(now<node->verification_retry)return 0;
        int queued=wncv_start(&node->verification,&node->certificates,s->fetch.chain,&node->clock);
        if(!queued)node->fetch_owner=NULL;
        return 0;
    }
    if(r==1){
        char text[192];int n=wncf_request_write(&request,text,sizeof text);if(n<0)return -1;
        r=send_control(s,text,(size_t)n);
        if(!r){node->fetch_owner=s;wncf_sent(&s->fetch,now/1000);}
        if(r<0)return -1;
    }
    return 0;
}
static int64_t catalog_expires(void *context)
{struct wnrs_node *node=context;return node->sessions ? (int64_t)node->sessions->identity.certificate_expires*1000:0;}
static uint64_t catalog_next_hop(void *context,const uint8_t device[16],uint64_t exclude)
{
 struct wnrs_node *node=context;uint8_t address[16];wn_address(device,address);struct wb_route route;
 if(!wnr_lookup(&node->core,address,esp_timer_get_time(),&route) || route.link==exclude)return 0;
 return route.link;
}
static void catalog_changed(void *context){((struct wnrs_node *)context)->core.publication_dirty=true;}
static int catalog_open(struct wnrs_node *node)
{
 bool psram=heap_caps_get_total_size(MALLOC_CAP_SPIRAM)>0;
 struct wnsc_config config={.context=node,.tenant=node->clock.tenant,.device=node->clock.device,
  .catalog_bytes=psram ? 512*1024:CONFIG_WENDY_NET_CATALOG_BYTES,.catalog_records=psram ? 512:64,
  .services_changed=catalog_changed,.expires=catalog_expires,.next_hop=catalog_next_hop};
 return wnsc_open(&node->catalog,&config);
}
static int catalog_tick(struct wnrs *s,int64_t now)
{
    (void)now;wnsc_prune(s->node->catalog,unix_now(s));return 0;
}
static void node_free(struct wnrs_node *node)
{
    if(!node)return;
    drop_uploads(node,0);
    wncd_close(&node->certificate_read);
#if ESP_PLATFORM
    if(node->signing){wncrypto_cancel(&node->signing->job);wncrypto_signature_clear(&node->signing->completed);wendy_net_free(node->signing->body);wendy_net_free(node->signing);}
#endif
    wncv_release(node->verification);
    wncs_close(&node->certificates);
    while(node->pending){struct pending_manifest *p=node->pending;node->pending=p->next;wendy_net_free(p);}
    wnsc_close(node->catalog);
    wg_deinit(&node->pool);wnr_deinit(&node->core);
    wendy_net_free(node);
}
static bool certificate_index_current(void *context,const struct wendy_pki_mesh_public_index *index)
{
    struct wnrs_node *node=context;
    return wendy_pki_mesh_public_index_current(index,&node->clock);
}
/* A newly admitted TLS context is actor-owned after its worker loan returned.
 * Snapshot availability only; actual DER output keeps the existing I/O path. */
static void refresh_certificate_index(struct wnrs_node *node,wendy_pki_connection *connection,
    const struct wendy_pki_mesh_identity *identity)
{
    if(!node->certificates.opened)return;
#if ESP_PLATFORM
    if(wncrypto_borrowed(connection))return;
#endif
    struct wendy_pki_mesh_public_index *index=wendy_net_calloc(1,sizeof *index);
    if(!index)return;
    if(!wendy_pki_mesh_public_index_snapshot(connection,identity,index) &&
       wendy_pki_mesh_public_index_current(index,&node->clock))
        wncs_set_baseline_index(&node->certificates,index,certificate_index_current);
    wendy_net_free(index);
}
static int node_open(struct wnrs_node **owner,wendy_pki_connection *connection,
                     const struct wendy_pki_mesh_identity *identity)
{
    if(*owner)return 0;
    struct wnrs_node *node=wendy_net_calloc(1,sizeof *node);
    if(!node)return -1;
    node->owner=owner;node->clock=*identity;
    /* A RAM-only Babel runtime must not reuse a previous origin with a reset
     * sequence number. Existing neighbors learn this replacement origin from
     * its higher, boot-reserved signed publication revision. */
    uint64_t router;
    do {esp_fill_random(&router,sizeof router);} while(!router || router==UINT64_MAX);
    struct wnr_config config={.tenant=identity->tenant,.device=identity->device,
        .router=router,.context=node,.publish=publish,.send=babel_send,
#if WENDY_NET_NON_TRANSIT
        .non_transit=true,
        .endpoint_gateway=CONFIG_WENDY_NET_ENDPOINT_GATEWAY,
#endif
    };
    memcpy(config.trust_hash,identity->journal_trust_hash,32);
    bool external_ram=heap_caps_get_total_size(MALLOC_CAP_SPIRAM)>0;
    struct wg_config gossip={.identify=wn_gossip_identify,.context=node,
        .want_object=want_artifact,.known_object=known_artifact,
        .objects=32,.pending=external_ram ? 256:64,.bytes=64*1024,
        .downloads=external_ram ? 2:1,.uploads=external_ram ? 2:1,
        .route_download_reserve=external_ram ? 1:0};
    gossip.context=node;gossip.fifo=true;
    gossip.objects=external_ram ? 1024:128;
    gossip.type_bytes[0]=external_ram ? 512*1024:8192;
    gossip.bytes=gossip.type_bytes[0];
    gossip.reserve_objects=gossip.uploads+1;
    gossip.critical_object=own_route_artifact;
    gossip.known_object=known_artifact;
    gossip.protected_object=protected_artifact;gossip.evicted=evicted_artifact;
#if CONFIG_WENDY_NET_CONSTRAINED_PROFILE
    /* A hint is96 bytes on RV32, allocated only when observed. Retain a
     * normal startup burst without dropping the service a local app needs
     * until the five-minute reconciliation. Full downloads remain one. */
    gossip.pending=64;gossip.route_pending_reserve=8;
#endif
    if(wg_init(&node->pool,&gossip))goto fail;
    if(wncs_open_limits(&node->certificates,external_ram ? 512*1024:32*1024,
        external_ram ? 256:8,external_ram ? 128:4))
        ESP_LOGW(TAG,"public certificate cache unavailable; direct TLS neighbors remain usable");
    else{
        /* Actual local DER output is an explicit outer-driver read effect. */
        wncs_set_baseline(&node->certificates,node,NULL);
        /* Even a missing/stale snapshot is an explicit RAM miss, never a
         * fallback to actor-side NVS reads for a NULL-output size query. */
        wncs_set_baseline_index(&node->certificates,NULL,certificate_index_current);
        refresh_certificate_index(node,connection,identity);
    }
    if(wnr_init(&node->core,&config,esp_timer_get_time(),NULL,0))goto fail;
#if CONFIG_WENDY_NET_CONSTRAINED_PROFILE
    if(wnd_key_limit(&node->core.directory,8))goto fail;
#endif
    if(catalog_open(node) || wnr_start(&node->core,node_unix(node),esp_timer_get_time()))goto fail;
    *owner=node;return 0;
fail:
    node_free(node);return -1;
}
static int open_session(struct wnrs **out,struct wnrs_node **owner,
              wendy_pki_connection *connection,
              const struct wendy_pki_mesh_identity *identity,const char *peer,const uint8_t *instance,uint16_t cost,
              wnrs_send send,void *ctx)
{
    if(!out || !owner || !connection || !identity || !send)return -1;
    *out=NULL;
    uint8_t uuid[16];bool existing=*owner!=NULL;
    const struct wendy_pki_operator_peer *operator=instance ? wendy_pki_mesh_authenticated_operator(connection):NULL;
    uint8_t address[16];
    if(instance){
        if(!operator || wno_address(operator->principal,strlen(operator->principal),instance,address))return -1;
    }else if(wn_uuid_parse(peer,uuid))return -1;
    if(node_open(owner,connection,identity))return -1;
    struct wnrs_node *node=*owner;
    if(strcmp(node->clock.tenant,identity->tenant) || strcmp(node->clock.device,identity->device) ||
       node->clock.config_generation!=identity->config_generation ||
       memcmp(node->clock.trust_hash,identity->trust_hash,32))return -1;
    struct wnrs *s=wendy_net_calloc(1,sizeof *s);
    if(!s){if(!node->sessions){*owner=NULL;node_free(node);}return -1;}
    s->node=node;s->identity=*identity;s->connection=connection;s->send=send;s->context=ctx;
    if(instance){
        s->operator_peer=operator;memcpy(s->operator_instance,instance,16);
        memcpy(s->peer_address,address,16);
    }else wn_address(uuid,s->peer_address);
    s->next=node->sessions;node->sessions=s;
    if(identity->verified_monotonic_us>node->clock.verified_monotonic_us)node->clock=*identity;
    if(existing)refresh_certificate_index(node,connection,identity);
    int64_t now=esp_timer_get_time(),wall=unix_now(s);
    /* ML-DSA peer keys are about 2 KiB. The actor also runs the routing and
     * TLS call chain; retain its stack margin by owning this temporary here. */
    if(wg_open(&node->pool,&s->gossip,1))goto fail;
    if(!instance){
        struct wendy_pki_mesh_peer *authenticated=wendy_net_calloc(1,sizeof *authenticated);
        bool ok=authenticated && !wendy_pki_mesh_authenticated_peer(connection,authenticated) &&
            !strcmp(authenticated->device,peer) && !wnr_identity(&node->core,authenticated,wall,now);
        wendy_net_free(authenticated);if(!ok)goto fail;
    }
    int described=describe(s);if(described<0)goto fail;
    s->own_descriptor_pending=described>0;
    if(!instance && (WENDY_NET_SMALL_RESOURCES || node->core.config.non_transit)){
        if(wnd_key_pin(&node->core.directory,uuid,true))goto fail;
        s->key_pinned=true;
    }
    /* Attach emits initial packets synchronously; make their predicted unique
     * link visible to the node send callback before entering the core. */
    s->link=node->core.babel.last_link+1;
    uint64_t attached=0;
    int attachment=instance ? wnr_attach_operator(&node->core,cost,wall,esp_timer_get_time(),&attached):
        wnr_attach(&node->core,peer,cost,wall,esp_timer_get_time(),&attached);
    if(attachment || attached!=s->link)
        goto fail;
    s->attached=true;
    /* Inventory owns its cursor through bounded output backpressure. */
    queue_inventory(s);

    ESP_LOGI(TAG,"native Babel stream started: router=%llu link=%llu state=%u gossip=%u",
        (unsigned long long)node->core.babel.config.router,(unsigned long long)s->link,
        (unsigned)wnr_memory(&node->core),(unsigned)wg_memory(&node->pool));
    *out=s;return 0;
fail:
    wnrs_close(s);return -1;
}
int wnrs_open(struct wnrs **out,struct wnrs_node **owner,wendy_pki_connection *connection,
    const struct wendy_pki_mesh_identity *identity,const char *peer,uint16_t cost,wnrs_send send,void *ctx)
{return open_session(out,owner,connection,identity,peer,NULL,cost,send,ctx);}
int wnrs_open_operator(struct wnrs **out,struct wnrs_node **owner,wendy_pki_connection *connection,
    const struct wendy_pki_mesh_identity *identity,const uint8_t instance[16],uint16_t cost,wnrs_send send,void *ctx)
{
    if(!instance || WENDY_NET_SMALL_RESOURCES || CONFIG_WENDY_NET_ENDPOINT_GATEWAY)return -1;
    uint8_t nonzero=0;for(unsigned i=0;i<16;i++)nonzero|=instance[i];
    if(!nonzero)return -1;
    return open_session(out,owner,connection,identity,NULL,instance,cost,send,ctx);
}
void wnrs_close(struct wnrs *s)
{
    if(!s)return;
#if WN_ROUTE_ASYNC
    wnop_job_release(s->operator_verification);s->operator_verification=NULL;
    wncrypto_cancel(&s->record_verification);
#endif
    struct wnrs_node *node=s->node;
    struct wnrs **slot=&node->sessions;
    while(*slot && *slot!=s)slot=&(*slot)->next;
    if(*slot)*slot=s->next;
    if(s->key_pinned){
        bool other=false;
        for(const struct wnrs *peer=node->sessions;peer;peer=peer->next)
            if(peer->key_pinned && !memcmp(peer->peer_address,s->peer_address,16))other=true;
        if(!other)for(struct wnd_entry *e=node->core.directory.entries;e;e=e->next)
            if(!memcmp(e->address,s->peer_address,16)){
                (void)wnd_key_pin(&node->core.directory,e->device,false);break;
            }
    }
    if(node->fetch_owner==s)node->fetch_owner=NULL;
    wncd_cancel(&node->certificate_read,s->link);
    drop_uploads(node,s->link);
    wncf_stop(&s->fetch);trim_certificates(node);

    wg_close(&s->gossip);
    if(s->attached)(void)wnr_detach(&node->core,s->link,node_unix(node),esp_timer_get_time());
    wendy_net_free(s);
    if(!node->sessions){*node->owner=NULL;node_free(node);}
}
void wnrs_refresh(struct wnrs *s,
                  const struct wendy_pki_mesh_identity *identity)
{
    s->identity = *identity;
    if(identity->verified_monotonic_us>s->node->clock.verified_monotonic_us)
        s->node->clock=*identity;
}
int wnrs_tick(struct wnrs *s)
{
    reap_node_crypto(s->node);
    int64_t now = esp_timer_get_time();
    int r=0;
    if(now>=wnrs_next_deadline(s)){
        r=wnr_tick(&s->node->core,unix_now(s),now);s->node->tick_us=now+1000000;
    }
    if (r)
    {
        ESP_LOGW(TAG, "router tick failed: result=%d stage=%s error=%d checkpoint=%u heap=%u largest=%u",
            r,s->node->core.stop_stage ? s->node->core.stop_stage : "unknown",
            s->node->core.stop_error,(unsigned)s->node->core.checkpoint_bytes,
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
        return -1;
    }
    bool owned=false;
#if WN_ROUTE_ASYNC
    owned=s->record_verification!=NULL || s->record_verdict!=0 || s->operator_verification!=NULL;
    if(owned){
        struct wg_id id={.type=1};memcpy(id.hash,s->operator_verification ? s->operator_record:s->verified_record,32);
        r=wg_resume_id(&s->gossip,&id,complete,s);
        if(r==WG_RESUME_MISSING){wncrypto_cancel(&s->record_verification);wnop_job_release(s->operator_verification);s->operator_verification=NULL;s->record_verdict=0;s->verification_blocked=false;r=0;}
    }
#endif
    if(!owned)r=wg_resume(&s->gossip,complete,s);
    if(r<0){ESP_LOGW(TAG,"router continuation failed: stage=route-gossip result=%d",r);return -1;}
    if(s->own_descriptor_pending){
        int described=describe(s);if(described<0)return -1;
        s->own_descriptor_pending=described>0;
    }
    r=certificate_tick(s);
    if(r<0){ESP_LOGW(TAG,"router continuation failed: stage=certificate result=%d",r);return -1;}
    r=catalog_tick(s,now);
    if(r<0){ESP_LOGW(TAG,"router continuation failed: stage=service-catalog result=%d",r);return -1;}
    r=inventory(s);
    if(r<0)return -1;
    if(!r)r = wg_poll(&s->gossip, (uint64_t)now / 1000, emit, s);
    if (r<0)
    {
        ESP_LOGW(TAG, "gossip poll failed: %d", r);
        return -1;
    }
    struct wb_route route;
    if (wnr_lookup(&s->node->core, s->peer_address, now, &route) &&
        (!s->ready_logged || s->selected_link!=route.link || s->selected_metric!=route.metric))
    {
        s->ready_logged = true;
        s->selected_link=route.link;s->selected_metric=route.metric;
        ESP_LOGI(TAG,
                 "native Babel peer route ready: cost=%u selected_link=%llu carrier_link=%llu state=%u gossip=%u "
                 "heap=%u internal=%u largest_internal=%u stack_free=%u",
                 (unsigned)route.metric,(unsigned long long)route.link,(unsigned long long)s->link,
                 (unsigned)wnr_memory(&s->node->core),
                 (unsigned)wg_memory(&s->node->pool),
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL |
                                                   MALLOC_CAP_8BIT),
                 (unsigned)heap_caps_get_largest_free_block(
                     MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
                 (unsigned)uxTaskGetStackHighWaterMark(NULL));
    }
#undef TICK_PROBE
    return 0;
}
static int control_parsed(struct wnrs *s,const void *data,size_t size,const struct wn_doc *d)
{
    int kind = wn_doc_member(d, 0, "kind");
    const struct wn_token *kind_token=wn_doc_token(d,kind);
    if(!kind_token || kind_token->type!='"' || kind_token->end<=kind_token->start+kind_token->header)return -1;
    if (wn_doc_equal(d, kind, "gossip"))
    {
        struct wg_message m;
        uint8_t bytes[WG_CHUNK];
        int decoded=wn_gossip_read(data,size,&m,bytes);
        if(decoded>0)return 0;
        if (decoded<0 || m.id.type!=1)
        {
            ESP_LOGW(TAG, "invalid router gossip frame: bytes=%u",
                     (unsigned)size);
            return -1;
        }
        /* Endpoint gateways also verify router capabilities for outgoing VIPs.
         * Only their compact bounded projections survive admission; Babel
         * continues to ignore remote routing updates and use its sole gateway. */
        int r = wg_receive(&s->gossip, &m, esp_timer_get_time() / 1000, emit,
                           complete, s);
        if (r < 0)
            ESP_LOGW(
                TAG,
                "gossip receive failed: result=%d op=%u request=%llu bytes=%u",
                r, (unsigned)m.op, (unsigned long long)m.request,
                (unsigned)m.size);
        return r < 0 ? -1 : 0;
    }
    if(wn_doc_equal(d,kind,"identity-missing") || wn_doc_equal(d,kind,"manifest-missing")){
        char principal[106];uint8_t device[16];
        if(wn_doc_string(d,wn_doc_member(d,0,"principal"),principal,sizeof principal)!=105 ||
           wn_principal_device(principal,s->identity.tenant,device))return -1;
        if(wn_doc_equal(d,kind,"identity-missing"))forget_pending_identity(s,principal);
        else if(s->node->endpoint_request_supplier==s->link &&
                !memcmp(s->node->endpoint_request_device,device,16)){
            /* An alternate direct peer can be asked on the next lookup. With
             * one carrier, avoid repeatedly querying a known-empty supplier. */
            bool alternate=false;
            for(struct wnrs *peer=s->node->sessions;peer;peer=peer->next)
                if(peer!=s)alternate=true;
            s->node->endpoint_request_retry=alternate ? 0:esp_timer_get_time()+INT64_C(5000000);
        }
        return 0;
    }
    if (wn_doc_equal(d, kind, "identity-request") || wn_doc_equal(d,kind,"manifest-request"))
    {
        char principal[106];uint8_t device[16];
        if (wn_doc_string(d, wn_doc_member(d, 0, "principal"), principal,
                           sizeof principal) != 105 ||
            wn_principal_device(principal,s->identity.tenant,device))
            return -1;
        if(wn_doc_equal(d,kind,"manifest-request")){
            if(!memcmp(device,s->node->core.directory.self,16) && s->node->own_cached){
                struct wg_message have={.id=s->node->own_artifact,.op=WG_HAVE};return emit(s,&have);
            }
            for(struct wnd_entry *e=s->node->core.directory.entries;e;e=e->next)
                if(!memcmp(e->device,device,16) && e->gossip_cached){
                    struct wg_message have={.id.type=1,.op=WG_HAVE};memcpy(have.id.hash,e->gossip_hash,32);return emit(s,&have);
                }
            char wire[192];int n=wn_directory_missing_write(principal,true,wire,sizeof wire);
            return n<0 ? -1:send_control(s,wire,(size_t)n);
        }
        memcpy(s->descriptor_reply,principal,sizeof principal);return 0;
    }
    if (wn_doc_equal(d, kind, "certificate"))
    {
        int cert = wn_doc_member(d, 0, "certificate");
        if (cert < 0)
            return -1;
        int request = wn_doc_member(d, cert, "request");
        if(request>=0)return certificate_request(s,d,(unsigned)request);
        int missing=wn_doc_member(d,cert,"missing");
        if(missing>=0)return missing_certificate(s,d,(unsigned)missing);
        int chain=wn_doc_member(d,cert,"chain");
        if(chain>=0){
            struct wncf_chain description;
            int principal=wn_doc_member(d,(unsigned)chain,"principal");
            const char *name=NULL;size_t name_size=0;
            if(wn_doc_text(d,principal,&name,&name_size))return -1;
            if(!wendy_pki_operator_principal(name,name_size,s->identity.tenant))return 0;
            if(wncf_chain_read(d,(unsigned)chain,s->identity.tenant,&description))return -1;
            if(!s->node->certificates.opened || s->fetch.chain)return 0;
            char self[106];if(wn_principal(s->identity.tenant,s->identity.device,self)<0)return -1;
            if(!strcmp(self,description.principal))return 0;
            /* A retained verification receipt prevents hints from refilling
             * an exact path forgotten by the FIFO, including on PSRAM nodes. */
            if(chain_verified(s->node,&description))return 0;
            if(s->node->core.config.non_transit){
                /* A terminating peer needs only keys demanded by a pending
                 * claim. Its verified keys do not need duplicate relay DER. */
                struct wnd_entry *identity=chain_identity(s->node,&description);
                if(identity && identity->peer.spki_size && identity->peer.expires>unix_now(s)/1000)return 0;
                bool needed=false;
                for(struct pending_manifest *p=s->node->pending;p;p=p->next)
                    if(!strcmp(p->principal,description.principal)){needed=true;break;}

                if(!needed)return 0;
            }else if(WENDY_NET_SMALL_RESOURCES){
                /* A direct TLS key alone is insufficient for relaying its
                 * certificate path. Fetch its first descriptor normally, but
                 * do not refill an already verified/forgotten chain on hints. */
                struct wnd_entry *identity=chain_identity(s->node,&description);
                bool needed=false;
                for(struct pending_manifest *p=s->node->pending;p;p=p->next)
                    if(!strcmp(p->principal,description.principal)){needed=true;break;}
                for(struct wnrs *peer=s->node->sessions;identity && peer;peer=peer->next)
                    if(!memcmp(peer->peer_address,identity->address,16)){needed=true;break;}
                if(!needed)return 0;
            }
            int started=wncf_start(&s->fetch,&description,esp_timer_get_time()/1000);
            return started<0 ? -1:0;
        }
        int chunk=wn_doc_member(d,cert,"chunk");
        if(chunk>=0){
            struct wncf_chunk received;uint8_t bytes[WNCF_CHUNK];
            if(wncf_chunk_read(d,(unsigned)chunk,&received,bytes))return -1;
            if(!s->fetch.chain || !s->fetch.waiting || s->fetch.index>=s->fetch.chain->count ||
               memcmp(received.hash,s->fetch.chain->hashes[s->fetch.index],32) ||
               received.offset<s->fetch.offset)return 0;
            struct wncf_store store={.context=&s->node->certificates,.read=wncs_read,.put=wncs_put,
                .retain=wncs_retain,.release=wncs_release};
            int result=wncf_receive(&s->fetch,&store,received.hash,received.offset,
                received.total,bytes,received.size,esp_timer_get_time()/1000);
            return result<0 ? -1:0;
        }
        return 0; /* A future certificate control variant is optional. */
    }
    if (wn_doc_equal(d, kind, "catalog"))
        return 0; /* Unknown obsolete control kind; no catalogue transport. */
    if (wn_doc_equal(d, kind, "time")) {
        int at=wn_doc_member(d,0,"time");
        return at>=0 && s->time_receive ? s->time_receive(s->context,d,(unsigned)at):0;
    }
    char name[40];
    if (wn_doc_string(d, kind, name, sizeof name) < 0)
        strcpy(name, "invalid");
    ESP_LOGD(TAG, "skipping unsupported router control: kind=%s bytes=%u", name,
             (unsigned)size);
    return 0;
}
int wnrs_control(struct wnrs *s,const void *data,size_t size)
{
    reap_node_crypto(s->node);
    if(s->certificate_reply_pending || s->descriptor_reply[0])return 1;
    /* Larger catalogue exchanges must not add another parser frame to the
     * constrained packet actor's stack. This is operation-owned workspace. */
    struct wn_doc *d=wendy_net_malloc(sizeof *d);if(!d)return 1;
    /* The carrier retains its exact current frame while this callback returns
     * positive; consume no HAVE/WANT/certificate bytes without a parser. */
    int r=wn_doc_parse_bounded(d,data,size,65536);
    if(!r){
        r=control_parsed(s,data,size,d);
        if(r<0){
            char kind[40];
            if(wn_doc_string(d,wn_doc_member(d,0,"kind"),kind,sizeof kind)<0)strcpy(kind,"invalid");
            ESP_LOGW(TAG,"router control failed: kind=%s bytes=%u result=%d",kind,(unsigned)size,r);
        }
    }
    else ESP_LOGW(TAG,"invalid router control CBOR: bytes=%u",(unsigned)size);
    wendy_net_free(d);return r;
}

int wnrs_routing(struct wnrs *s, const void *data, size_t size)
{
    int r = wnr_receive(&s->node->core, s->link, data, size, unix_now(s),
                        esp_timer_get_time());
    if (r<0)
        ESP_LOGW(TAG, "Babel receive failed: result=%d bytes=%u", r,
                 (unsigned)size);
    return r;
}
void wnrs_time_handler(struct wnrs *s,int (*receive)(void *,const struct wn_doc *,unsigned))
{s->time_receive=receive;}
bool wnrs_app_endpoint(struct wnrs *s, const uint8_t device[16], uint16_t *port)
{
    int64_t now=esp_timer_get_time();wne_reap(&s->node->core.endpoints,now);
    bool found=wnr_app_endpoint(&s->node->core,device,now,port);
    if(!found && s->node->core.config.endpoint_gateway && now>=s->node->endpoint_request_retry){
        char uuid[37],principal[106],wire[192];wn_uuid_format(device,uuid);
        int n=wn_principal(s->identity.tenant,uuid,principal);
        if(n>0)n=wn_manifest_request_write(principal,wire,sizeof wire);
        struct wnrs *supplier=s;
        if(!memcmp(s->node->endpoint_request_device,device,16)){
            for(struct wnrs *peer=s->node->sessions;peer;peer=peer->next)
                if(peer->link==s->node->endpoint_request_supplier){supplier=peer->next ? peer->next:s->node->sessions;break;}
        }
        if(n>0 && !send_control(supplier,wire,(size_t)n)){
            memcpy(s->node->endpoint_request_device,device,16);
            s->node->endpoint_request_supplier=supplier->link;
            s->node->endpoint_request_retry=now+INT64_C(1000000);
        }
    }
    return found;
}
bool wnrs_agent_endpoint(struct wnrs *s, const uint8_t device[16], uint16_t *port)
{
    return wnr_agent_endpoint(&s->node->core, device, esp_timer_get_time(), port);
}
uint64_t wnrs_link_id(const struct wnrs *s){return s->link;}
int wnrs_packet_route(struct wnrs *s,void *data,size_t size,bool incoming,uint64_t *outgoing)
{
    int64_t now=esp_timer_get_time();
    int result=wnr_packet(&s->node->core,incoming ? s->link:0,data,size,now,outgoing);
    return result;
}
int wnrs_packet(struct wnrs *s,void *data,size_t size,bool incoming)
{
    uint64_t outgoing=0;int r=wnrs_packet_route(s,data,size,incoming,&outgoing);
    return incoming ? r==0 ? 0:-1 : r==1 && outgoing==s->link ? 0:-1;
}

int wnrs_service_action(struct wnrs *s,struct wnsc_registry **registry,unsigned operation,
    const void *input,size_t size,char *out,size_t cap,wnsc_listener_owner owner,void *context)
{
    if(s)reap_node_crypto(s->node);
    struct wnsc_node *node=s ? s->node->catalog:NULL;
    int64_t wall=s ? unix_now(s):0;uint64_t now=(uint64_t)esp_timer_get_time()/1000;
    if(!input || !size || memchr(input,0,size))return -1;
    char selector[64];
    if(operation==0 || operation==2 || operation==3){
        if(size>=sizeof selector)return -1;
        memcpy(selector,input,size);selector[size]=0;input=selector;
    }
    if((operation==0 || operation==3) && node)wnsc_browse_demand(node,now);
    if(operation==0)return node ? wnsc_browse(node,input,wall,out,cap):-2;
    if(operation==3)return node ? wnsc_browse_endpoints(node,input,wall,out,cap):-2;
    if(operation==2 && !node)return -2;
    int r=operation==1 ? wnsc_guest_register(registry,input,size,owner,context):
        operation==2 ? wnsc_guest_unregister(registry,node,input,wall,now):-1;
    return r>0 || r==-2 ? -2:r;
}
void wnrs_service_maintain(struct wnrs *s,struct wnsc_registry **registry,wnsc_listener_owner owner,void *context)
{
    if(s)reap_node_crypto(s->node);
    (void)wnsc_guest_tick(registry,s ? s->node->catalog:NULL,owner,context,
        s ? unix_now(s):0,(uint64_t)esp_timer_get_time()/1000);
}

int64_t wnrs_next_deadline(const struct wnrs *s)
{
    const struct wnr_core *c=&s->node->core;
    uint64_t next=wb_next_deadline(&c->babel);
    int64_t deadline=s->node->tick_us;
    for(const struct certificate_upload *u=s->node->uploads;u;u=u->next)
        if(u->deadline<deadline)deadline=u->deadline;
    int64_t read_deadline=wncd_deadline(&s->node->certificate_read);
    if(read_deadline<deadline)deadline=read_deadline;
#if ESP_PLATFORM
    if(s->node->signing && wncrypto_ready(s->node->signing->job))return esp_timer_get_time();
#endif
    /* A later edit stays dirty while the worker owns an immutable draft.
     * Its elapsed rate-limit deadline must not spin the higher-priority actor
     * and starve that worker: completion is the next relevant I/O event. */
    bool publishing=c->publication_pending;
    if(!publishing && (c->publication_dirty || c->published_seqno!=c->babel.seqno) && c->published &&
       c->published_us+INT64_C(1000000)<deadline)deadline=c->published_us+INT64_C(1000000);
#if WN_ROUTE_ASYNC
    if(s->operator_verification && atomic_load(&s->operator_verification->done))return esp_timer_get_time();
    if(s->signature_retry && s->signature_retry<deadline)deadline=s->signature_retry;
#endif
    if(wnr_busy(c))return deadline;
    if(next!=UINT64_MAX && next<(uint64_t)(INT64_MAX-c->epoch_us)/1000){
        int64_t babel=c->epoch_us+(int64_t)next*1000;
        if(babel<deadline)deadline=babel;
    }
    return deadline;
}

bool wnrs_receive_paused(const struct wnrs *s)
{
    if(s && s->certificate_reply_pending)return true;
#if WN_ROUTE_ASYNC
    return s && (s->verification_blocked);
#else
    (void)s;return false;
#endif
}

bool wnrs_node_busy(const struct wnrs_node *node){return node && wnr_busy(&node->core);}

int wnrs_poll_effects(struct wnrs_node *node)
{
    if(!node)return 0;
    reap_node_crypto(node);
    const struct wendy_pki_mesh_public_index *index=&node->certificates.baseline_index;
    const struct wncd_reader *read=&node->certificate_read;
    bool current=wendy_pki_mesh_public_index_current(index,&node->clock) &&
        read->generation==index->config_generation &&
        read->certificate_epoch==index->certificate_epoch;
    return wncd_poll(&node->certificate_read,&node->clock,current,esp_timer_get_time());
}

void wnrs_service_clear(struct wnsc_registry **registry){wnsc_guest_clear(registry);}

/* A structural fingerprint, independent of periodic Babel ticks/clock refresh.
 * Repeating a page after ordinary maintenance must not invalidate pagination. */
static uint64_t topology_hash(uint64_t h,const void *bytes,size_t size)
{
    const uint8_t *p=bytes;while(size--)h=(h^*p++)*UINT64_C(1099511628211);return h;
}
static int64_t topology_expiry(const struct wnrs_node *n,int64_t deadline,int64_t signed_expiry)
{
    int64_t bound=(int64_t)n->clock.verified_seconds*1000+
        (deadline-n->clock.verified_monotonic_us)/1000;
    return signed_expiry>0 && signed_expiry<bound ? signed_expiry:bound;
}
/* Borrow only an already verified live receipt. No scan allocations, signer
 * work or additional registry is needed; constrained gateways return empty. */
int wnrs_topology_operator_row(struct wnrs_node *node,unsigned category,unsigned index,
    int64_t now,struct wnt_record_view *view)
{
    if(!node || !view || !node->core.operators || node->core.config.endpoint_gateway)return 0;
    if(category!=2 && category!=3)return 0;
    const struct wno_entry *selected=NULL;
    for(const struct wno_entry *e=node->core.operators->entries;e;e=e->next){
        if(e->deadline_us<=now)continue;
        if(category==2){
            if(view->record.address.size!=16 || memcmp(e->address,view->record.address.bytes,16))continue;
            /* A collision has no unique authenticated owner. */
            if(selected)return 0;
            selected=e;
        }else if(!index--){selected=e;break;}
    }
    if(!selected || selected->principal_size>WNT_TOPOLOGY_PRINCIPAL_MAX)return 0;
    WendyComNetTopologyRecord *out=&view->record;
    out->owner_role=WNT_TOPOLOGY_OPERATOR;out->device.size=0;
    out->owner_instance.size=16;memcpy(out->owner_instance.bytes,selected->instance,16);
    view->principal=selected->principal;view->principal_size=selected->principal_size;
    out->expires_at_unix_ms=topology_expiry(node,selected->deadline_us,0);
    if(category==2){
        out->authorized=wno_authorizes(node->core.operators,selected->address,out->router_id,(uint16_t)out->sequence,now);
    }else{
        out->kind=3;out->address.size=16;memcpy(out->address.bytes,selected->address,16);
        out->router_id=selected->origin.router_id;out->sequence=selected->origin.seqno;
        out->revision=selected->revision;out->authorized=true;
    }
    return 1;
}
static int topology_record(struct wnrs_node *n,unsigned wanted,int64_t now,
    struct wnt_record_view *view)
{
    WendyComNetTopologyRecord *out=&view->record;
    unsigned at=0;
    for(struct wnrs *s=n->sessions;s;s=s->next)if(s->attached){
        if(at++!=wanted)continue;
        out->kind=1;
        if(s->operator_peer){
            out->owner_role=WNT_TOPOLOGY_OPERATOR;out->owner_instance.size=16;
            memcpy(out->owner_instance.bytes,s->operator_instance,16);
            view->principal=s->operator_peer->principal;view->principal_size=strlen(view->principal);
            out->expires_at_unix_ms=(int64_t)s->operator_peer->expires*1000;
        }else{out->owner_role=WNT_TOPOLOGY_DEVICE;out->device.size=16;wn_uuid_parse(s->identity.peer,out->device.bytes);}
        out->address.size=16;memcpy(out->address.bytes,s->peer_address,16);
        out->link_id=s->link;
        for(size_t i=0;i<n->core.babel.links_capacity;i++)if(n->core.babel.links[i].config.id==s->link){
            out->metric=n->core.babel.links[i].config.cost;break;
        }
        return true;
    }
    for(size_t i=0;i<n->core.babel.route_count;i++){
        const struct wb_route *r=&n->core.babel.routes[i];
        if(r->prefix.family!=6 || r->prefix.bits!=128)continue;
        if(at++!=wanted)continue;
        out->kind=2;out->address.size=16;memcpy(out->address.bytes,r->prefix.bytes,16);
        out->link_id=r->link;out->router_id=r->router;out->sequence=r->seqno;out->metric=r->metric;
        out->local=r->local;out->unreachable=r->unreachable;
        if(r->local){out->owner_role=WNT_TOPOLOGY_DEVICE;out->device.size=16;memcpy(out->device.bytes,n->core.directory.self,16);out->authorized=true;}
        for(struct wnrs *s=n->sessions;s;s=s->next)if(s->attached && s->link==r->link){
            if(!s->operator_peer){out->next_hop_device.size=16;wn_uuid_parse(s->identity.peer,out->next_hop_device.bytes);}break;
        }
        for(const struct wnd_entry *e=n->core.directory.entries;e;e=e->next)
            if(!memcmp(e->address,r->prefix.bytes,16) && e->deadline_us>now && !e->pending_receipt && !e->manifest.withdraw){
                out->owner_role=WNT_TOPOLOGY_DEVICE;out->device.size=16;memcpy(out->device.bytes,e->device,16);
                out->authorized=wnd_authorizes(&n->core.directory,r->prefix.bytes,r->router,r->seqno,now);
                out->expires_at_unix_ms=topology_expiry(n,e->deadline_us,e->manifest.expires);break;
            }
        if(!out->device.size && wnrs_topology_operator_row(n,2,0,now,view)<0)return -1;
        return true;
    }
    for(const struct wnd_entry *e=n->core.directory.entries;e;e=e->next){
        if(e->deadline_us<=now || e->pending_receipt || !e->revision || e->manifest.withdraw)continue;
        if(at++!=wanted)continue;
        out->kind=3;out->owner_role=WNT_TOPOLOGY_DEVICE;out->device.size=16;memcpy(out->device.bytes,e->device,16);
        out->address.size=16;memcpy(out->address.bytes,e->address,16);
        out->router_id=e->manifest.origin.router_id;out->sequence=e->manifest.origin.seqno;
        out->revision=e->revision;out->issued_at_unix_ms=e->manifest.issued;
        out->expires_at_unix_ms=topology_expiry(n,e->deadline_us,e->manifest.expires);out->authorized=true;return true;
    }
    /* Constrained endpoint projections have verified identity/revision/deadline,
     * but intentionally omit full signed origin tuples and remote route tables. */
    for(const struct wne_entry *e=n->core.endpoints.entries;e;e=e->next){
        if(e->deadline_us<=now || e->withdraw)continue;
        if(at++!=wanted)continue;
        out->kind=3;out->owner_role=WNT_TOPOLOGY_DEVICE;out->device.size=16;memcpy(out->device.bytes,e->device,16);
        out->address.size=16;wn_address(e->device,out->address.bytes);
        out->revision=e->revision;out->expires_at_unix_ms=topology_expiry(n,e->deadline_us,0);
        out->authorized=true;return true;
    }
    return wnrs_topology_operator_row(n,3,wanted-at,now,view);
}
int wnrs_topology(struct wnrs_node *n,uint32_t cursor,uint64_t generation,WendyComNetTopologyPage *page)
{
    if(!n || cursor>1024)return -1;
    wnt_page_release(page);
    page->has_record=false;page->record=(WendyComNetTopologyRecord)WendyComNetTopologyRecord_init_zero;
    page->next_cursor=0;page->generation=0;page->truncated=false;
    int64_t now=esp_timer_get_time();
    wn_uuid_parse(n->clock.tenant,page->tenant);wn_uuid_parse(n->clock.device,page->device);
    page->captured_at_unix_ms=(int64_t)n->clock.verified_seconds*1000+(now-n->clock.verified_monotonic_us)/1000;
    page->runtime_available=n->core.ready && !n->core.stopped;
    page->partial=n->core.config.endpoint_gateway;
    if(!page->runtime_available)return cursor || generation ? 1:0;
    uint64_t hash=UINT64_C(1469598103934665603);
    /* Hash only semantic fields, never struct padding, timers or counters. */
    hash=topology_hash(hash,&n->core.config.router,sizeof n->core.config.router);
    hash=topology_hash(hash,&n->core.config.endpoint_gateway,sizeof n->core.config.endpoint_gateway);
    unsigned count=0;
    struct wnt_record_view view={.record=WendyComNetTopologyRecord_init_zero};
    int found=0;
    while(count<1024 && (found=topology_record(n,count,now,&view))>0){
        const WendyComNetTopologyRecord *row=&view.record;
        hash=topology_hash(hash,&row->kind,sizeof row->kind);
        hash=topology_hash(hash,row->device.bytes,row->device.size);
        hash=topology_hash(hash,row->address.bytes,row->address.size);
        hash=topology_hash(hash,&row->link_id,sizeof row->link_id);
        hash=topology_hash(hash,&row->router_id,sizeof row->router_id);
        hash=topology_hash(hash,&row->sequence,sizeof row->sequence);
        hash=topology_hash(hash,&row->metric,sizeof row->metric);
        hash=topology_hash(hash,&row->local,sizeof row->local);
        hash=topology_hash(hash,&row->unreachable,sizeof row->unreachable);
        hash=topology_hash(hash,&row->authorized,sizeof row->authorized);
        hash=topology_hash(hash,&row->revision,sizeof row->revision);
        hash=topology_hash(hash,&row->expires_at_unix_ms,sizeof row->expires_at_unix_ms);
        hash=topology_hash(hash,&row->owner_role,sizeof row->owner_role);
        hash=topology_hash(hash,row->owner_instance.bytes,row->owner_instance.size);
        hash=topology_hash(hash,view.principal,view.principal_size);
        count++;view=(struct wnt_record_view){.record=WendyComNetTopologyRecord_init_zero};
    }
    if(found<0)return -1;
    hash=hash ? hash:1;
    if((generation && generation!=hash) || cursor>count)return 1;
    page->generation=hash;
    page->truncated=count==1024;
    /* A terminal cursor is empty even when more rows exist beyond the bounded
     * scan; never return a row that was not covered by this generation. */
    if(cursor==count)return 0;
    view=(struct wnt_record_view){.record=WendyComNetTopologyRecord_init_zero};
    found=topology_record(n,cursor,now,&view);
    if(found<0 || (found>0 && wnt_record_copy(page,&view)))return -1;
    page->next_cursor=cursor+1<count ? cursor+1:0;
    return 0;
}

void wnrs_issuer_snapshot(struct wnrs_node *node,struct wendy_pki_net_issuers *snapshot)
{
    memset(snapshot,0,sizeof *snapshot);
    if(!node)return;
    int64_t now=(int64_t)node->clock.verified_seconds+
        (esp_timer_get_time()-node->clock.verified_monotonic_us)/1000000;
    struct wncs_loan *loan=wncs_issuer_loan(&node->certificates,now);
    if(!loan)return;
    snapshot->context=loan;snapshot->release=wncs_issuer_loan_free;
    for(unsigned i=0;i<loan->count && i<WENDY_PKI_NET_CACHED_ISSUERS;i++){
        snapshot->der[i]=loan->parts[i];snapshot->sizes[i]=loan->sizes[i];snapshot->count++;
    }
}
