#include "wendy_net_alloc.h"
#include "wendy_net_profile.h"
/* SPDX-License-Identifier: Apache-2.0
 * Single-owner node state shared by authenticated carrier sessions. The
 * firmware actor still serializes admission, routing and gossip. Carrier
 * scheduling and indirect certificate fetching are integrated separately.
 */
#include "router_session.h"
#include "catalog_node.h"
#include "certificate_fetch.h"
#include "certificate_store.h"
#include "certificate_wire.h"
#include "certificate_worker.h"
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

struct pending_manifest {
    struct pending_manifest *next;
    struct wg_id id;
    char principal[106];
    uint64_t supplier;
    int64_t deadline,asked;
    size_t size;
#if ESP_PLATFORM
    struct wncrypto_job *crypto;
#endif
    uint8_t bytes[];
};
enum public_part_domain { PUBLIC_ROUTER, PUBLIC_CATALOG };
struct certificate_upload {
    struct certificate_upload *next;
    uint64_t owner;
    int64_t deadline;
    void *part;
    size_t total;
    uint8_t hash[32];
    enum public_part_domain domain;
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
#if CONFIG_WENDY_NET_TEST_ACTOR_READINESS
    /* Actor-owned wall counters, including time preempted by other tasks.
     * Diagnostic builds only; storage follows the node's heap placement. */
    struct {uint64_t us[9];int64_t next;unsigned calls;} tick_probe;
#endif
    struct wg_id own_artifact;
    struct wncs_store certificates;
    struct certificate_upload *uploads;
    struct wncd_reader certificate_read;
    struct wncv_job *verification;
    struct wnrs *fetch_owner;
    struct pending_manifest *pending;
    size_t pending_bytes;
    unsigned pending_count;
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
    unsigned route_failures;
    struct {unsigned received[5],completed,unsupported,admitted,deferred,unknown_key;int64_t next;} route_probe;
#endif
    int64_t verification_retry;

    int64_t endpoint_request_retry;
    uint64_t endpoint_request_supplier;
    uint8_t endpoint_request_device[16];
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS

#endif
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
    uint8_t peer_address[16];
    uint64_t link;
    uint64_t selected_link;
    uint16_t selected_metric;
    bool attached, ready_logged,need_inventory,key_pinned;
    unsigned routing_drops;
    struct wncf_fetch fetch;
    struct wncf_request certificate_reply;
    bool certificate_reply_pending;
    char descriptor_reply[106];
    uint8_t described_artifact[32];
    bool described;
#if WN_ROUTE_ASYNC
    struct wncrypto_job *record_verification;
    bool verification_blocked;
    signed char record_verdict; /*0none/pending,1verified,-1failed; existing64Bbinding below. */
    uint8_t verified_record[32],verified_record_key[32];
#endif
};
static const char *TAG = "wendy_net_router";
static void route_diagnostic(struct wnrs *s,const uint8_t hash[32],const char *stage,int result)
{
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
    unsigned count=++s->node->route_failures;
    if(count<=8 || !(count%32))
        ESP_LOGW(TAG,"router artifact continuation: stage=%s result=%d count=%u link=%llu hash=%02x%02x%02x%02x",
            stage,result,count,(unsigned long long)s->link,(unsigned)hash[0],(unsigned)hash[1],(unsigned)hash[2],(unsigned)hash[3]);
#else
    (void)s;(void)hash;(void)stage;(void)result;
#endif
}
#if WN_ROUTE_ASYNC
static void reap_route_verification(struct wnrs *s)
{
    struct wncrypto_verdict result;
    if(wncrypto_take_verification(&s->record_verification,&result)){
        if(result.result)route_diagnostic(s,s->verified_record,"signature-result",result.result);
        s->record_verdict=result.result ? -1:1;
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
/* Descriptor preparation can emit its own message. Keep the JSON buffer out
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
static int announce(struct wnrs *s,const struct wg_message *have)
{
    int r=emit(s,have);
    if(r>0){s->need_inventory=true;return 0;}
    return r;
}
static int inventory(struct wnrs *s)
{
    if(!s->need_inventory)return 0;
    struct wnrs_node *node=s->node;
    if(node->own_cached){
        struct wg_message have={.id=node->own_artifact,.op=WG_HAVE};
        int r=emit(s,&have);if(r)return r;
    }
    for(struct wnd_entry *e=node->core.directory.entries;e;e=e->next){
        if(!e->gossip_cached)continue;
        struct wg_message have={.id={.type=1},.op=WG_HAVE};
        memcpy(have.id.hash,e->gossip_hash,32);
        int r=emit(s,&have);if(r)return r;
    }
    s->need_inventory=false;return 0;
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
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
    ESP_LOGI(TAG,"manifest commit: revision=%llu body_bytes=%u issued_ms=%lld expires_ms=%lld",
        (unsigned long long)node->signing->revision,(unsigned)node->signing->size,
        (long long)node->signing->issued,(long long)node->signing->expires);
#endif
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
#if CONFIG_WENDY_NET_TEST_BLOB_FIFO
static bool own_route_artifact(void *context,const struct wg_id *id)
{
    struct wnrs_node *node=context;
    return id->type==1 && !memcmp(node->own_artifact.hash,id->hash,32);
}
static bool protected_artifact(void *context,const struct wg_id *id)
{
    return own_route_artifact(context,id);
}
#endif
static bool known_artifact(void *context,const struct wg_id *id)
{
    struct wnrs_node *node=context;
    if(id->type==2)return false;
    if(id->type==1 && node->core.config.endpoint_gateway)
        for(const struct wne_entry *e=node->core.endpoints.entries;e;e=e->next)
            if(e->deadline_us>esp_timer_get_time() && !memcmp(e->artifact_hash,id->hash,32))return true;
    for(const struct wnd_entry *e=node->core.directory.entries;e;e=e->next)
        if(e->gossip_retired && !memcmp(e->gossip_hash,id->hash,32))return true;
    return false;
}
#if CONFIG_WENDY_NET_TEST_BLOB_FIFO
static void evicted_artifact(void *context,const struct wg_id *id,const void *bytes,size_t size)
{
    struct wnrs_node *node=context;(void)size;(void)bytes;
    if(id->type==2)return;
    for(struct wnd_entry *e=node->core.directory.entries;e;e=e->next)
        if(e->gossip_cached && !memcmp(e->gossip_hash,id->hash,32)){e->gossip_cached=false;e->gossip_retired=true;}
}
#endif
static bool want_artifact(void *context,const struct wg_id *id,uint64_t now)
{
    (void)context;(void)now;return id->type!=2;
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
    return n<0 ? -1:s->send(s->context,text,w.size+(size_t)n,true);
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
/* One part per active control domain/session. There are at most three
 * bounded upload windows per admitted carrier, never one per idle mesh node. */
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
static int hold_upload(struct wnrs_node *node,uint64_t owner,enum public_part_domain domain,
    const uint8_t hash[32],size_t total)
{
    bool admitted=false;
    for(const struct wnrs *peer=node->sessions;peer;peer=peer->next)if(peer->link==owner)admitted=true;
    if(!admitted || domain>PUBLIC_CATALOG)return -1;
    struct certificate_upload **at=&node->uploads;
    while(*at && ((*at)->owner!=owner || (*at)->domain!=domain))at=&(*at)->next;
    if(*at && !memcmp((*at)->hash,hash,32)){
        (*at)->deadline=esp_timer_get_time()+INT64_C(60000000);return 0;
    }
    struct certificate_upload *u=wendy_net_calloc(1,sizeof *u);if(!u)return -2;
    u->part=wncs_retain(&node->certificates,hash);
    if(!u->part){wendy_net_free(u);return -2;}
    u->owner=owner;u->domain=domain;u->total=total;
    u->deadline=esp_timer_get_time()+INT64_C(60000000);memcpy(u->hash,hash,32);
    if(*at){struct certificate_upload *old=*at;u->next=old->next;wncs_release(old->part);wendy_net_free(old);}
    *at=u;return 0;
}
static void release_public_part(struct wnrs_node *node,uint64_t owner,
    enum public_part_domain domain,const uint8_t hash[32],size_t offset)
{
    wncd_release(&node->certificate_read,owner,domain==PUBLIC_CATALOG,hash,offset);
    for(struct certificate_upload **at=&node->uploads;*at;at=&(*at)->next){
        struct certificate_upload *u=*at;
        if(u->owner==owner && u->domain==domain && !memcmp(u->hash,hash,32)){
            /* Only queue admission of the final chunk ends the whole-part
             * loan. Output pressure keeps it pinned for the retry. */
            if(offset>=u->total || u->total-offset<=WNCF_CHUNK){
                *at=u->next;wncs_release(u->part);wendy_net_free(u);
            }
            return;
        }
    }
}
static int read_public_part(struct wnrs_node *node,uint64_t owner,enum public_part_domain domain,
    const uint8_t hash[32],size_t offset,uint8_t out[WNCF_CHUNK],size_t *total)
{
    if(!node->certificates.opened)return -1;
    int r=wncs_read_resident(&node->certificates,hash,offset,out,total);
    if(r==1){
        if(offset>=*total)return -1;
        int held=hold_upload(node,owner,domain,hash,*total);if(held)return held;
        size_t count=*total-offset;return (int)(count<WNCF_CHUNK ? count:WNCF_CHUNK);
    }
    if(r<0 || wncs_read(&node->certificates,hash,0,NULL,total)!=1)return -1;
    const struct wendy_pki_mesh_public_index *index=&node->certificates.baseline_index;
    return wncd_read(&node->certificate_read,owner,domain==PUBLIC_CATALOG,index->config_generation,
        index->certificate_epoch,hash,offset,*total,out,total);
}
static int serve_part(struct wnrs *s)
{
    if(!s->certificate_reply_pending)return 0;
    struct wncf_request *q=&s->certificate_reply;
    uint8_t part[WNCF_CHUNK];size_t total=0;
    int count=read_public_part(s->node,s->link,PUBLIC_ROUTER,q->hash,q->offset,part,&total);
    if(count==-2)return 1;
    if(count<0){
        char wire[192];int n=wncf_missing_write(q,wire,sizeof wire);if(n<0)return -1;
        int sent=send_control(s,wire,(size_t)n);
        if(!sent){s->certificate_reply_pending=false;
            release_public_part(s->node,s->link,PUBLIC_ROUTER,q->hash,q->offset);}
        return sent;
    }
    struct wncf_chunk chunk={.offset=q->offset,.total=total,.size=(size_t)count};
    memcpy(chunk.hash,q->hash,32);char text[WN_CONTROL_MAX+1];
    int n=wncf_chunk_write(&chunk,part,text,sizeof text);if(n<0)return -1;
    int r=send_control(s,text,(size_t)n);if(!r){s->certificate_reply_pending=false;
        release_public_part(s->node,s->link,PUBLIC_ROUTER,q->hash,q->offset);}
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
    if(node->pending_count>=4 || size>8192-node->pending_bytes)return 0;
    struct wn_doc doc;char principal[106];uint8_t uuid[16];
    if(wn_doc_parse_array_view(&doc,bytes,size,WG_OBJECT_MAX,"s") ||
       wn_doc_string(&doc,wn_doc_member(&doc,0,"principal"),principal,sizeof principal)!=105 ||
       wn_principal_device(principal,s->identity.tenant,uuid))return -1;
    size_t retained=size;
#if ESP_PLATFORM
    retained=0;
#endif
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
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
    s->node->route_probe.admitted+=r==0;
    s->node->route_probe.deferred+=r==4;
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
struct manifest_workspace {struct wn_doc doc;struct wnd_manifest manifest;char principal[106];uint8_t uuid[16];};
#endif
static int complete(void *ctx,const struct wg_id *id,const void *bytes,size_t size)
{
#if WN_ROUTE_ASYNC
    struct wnrs *s=ctx;struct wnrs_node *node=s->node;
    reap_route_verification(s);
    if(s->record_verification){s->verification_blocked=true;return WG_DEFER;}
    if(s->record_verdict && memcmp(s->verified_record,id->hash,32))return WG_DEFER;
    if(s->record_verdict<0){s->record_verdict=0;return -1;}
    struct manifest_workspace *w=wendy_net_malloc(sizeof *w);if(!w)return WG_DEFER;
    int result=-1;const char *stage="artifact-envelope";size_t sig_size=0;const uint8_t *signature;struct wnd_entry *identity=NULL;
    if(wn_doc_parse_array_view(&w->doc,bytes,size,WG_OBJECT_MAX,"s") ||
       wn_doc_string(&w->doc,wn_doc_member(&w->doc,0,"principal"),w->principal,sizeof w->principal)!=105 ||
       wn_principal_device(w->principal,node->clock.tenant,w->uuid))goto done;
    stage="manifest-body";int body=wn_doc_member(&w->doc,0,"body");
    if(body<0)goto done;
    int sig=wn_doc_member(&w->doc,0,"signature");
    if(wn_doc_bytes(&w->doc,sig,&signature,&sig_size) || sig_size<8)goto done;
    if(sig_size>WN_ORIGIN_SIGNATURE_MAX){result=0;goto done;}
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
    node->route_probe.completed++;
#endif
    stage="manifest-metadata";int metadata=wnd_manifest_read(&w->doc,(unsigned)body,&w->manifest);
    if(metadata==WND_UNSUPPORTED){
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
        node->route_probe.unsupported++;
#endif
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
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
        if(++node->route_probe.unknown_key<=4)
            ESP_LOGI(TAG,"router origin awaits key: peer=%s supplier=%llu entry=%u",w->principal+69,(unsigned long long)s->link,identity!=NULL);
#endif
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
#if ESP_PLATFORM
            wncrypto_cancel(&p->crypto);
#endif
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
#if !ESP_PLATFORM
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
#if ESP_PLATFORM
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
#if ESP_PLATFORM
            wncrypto_cancel(&p->crypto);
#endif
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
    for(struct pending_manifest *p=node->pending;p;p=p->next)wncrypto_cancel(&p->crypto);
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
#if CONFIG_WENDY_NET_TEST_BLOB_FIFO
    gossip.context=node;gossip.fifo=true;
    gossip.objects=external_ram ? 1024:128;
    gossip.type_bytes[0]=external_ram ? 512*1024:8192;
    gossip.type_bytes[1]=external_ram ? 512*1024:
        (size_t)CONFIG_WENDY_NET_TEST_SRAM_SERVICE_CACHE_KIB*1024;
    gossip.bytes=gossip.type_bytes[0]+gossip.type_bytes[1]+gossip.type_bytes[2];
    gossip.reserve_objects=gossip.uploads+1;
    gossip.critical_object=own_route_artifact;
    gossip.known_object=known_artifact;
    gossip.protected_object=protected_artifact;gossip.evicted=evicted_artifact;
#endif
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
int wnrs_open(struct wnrs **out,struct wnrs_node **owner,
              wendy_pki_connection *connection,
              const struct wendy_pki_mesh_identity *identity,const char *peer,uint16_t cost,
              wnrs_send send,void *ctx)
{
    *out=NULL;
    uint8_t uuid[16];bool existing=owner && *owner;
    if(!owner || wn_uuid_parse(peer,uuid) || node_open(owner,connection,identity))return -1;
    struct wnrs_node *node=*owner;
    if(strcmp(node->clock.tenant,identity->tenant) || strcmp(node->clock.device,identity->device) ||
       node->clock.config_generation!=identity->config_generation ||
       memcmp(node->clock.trust_hash,identity->trust_hash,32))return -1;
    struct wnrs *s=wendy_net_calloc(1,sizeof *s);
    if(!s){if(!node->sessions){*owner=NULL;node_free(node);}return -1;}
    s->node=node;s->identity=*identity;s->connection=connection;s->send=send;s->context=ctx;
    wn_address(uuid,s->peer_address);
    s->next=node->sessions;node->sessions=s;
    if(identity->verified_monotonic_us>node->clock.verified_monotonic_us)node->clock=*identity;
    if(existing)refresh_certificate_index(node,connection,identity);
    int64_t now=esp_timer_get_time(),wall=unix_now(s);
    /* ML-DSA peer keys are about 2 KiB. The actor also runs the routing and
     * TLS call chain; retain its stack margin by owning this temporary here. */
    struct wendy_pki_mesh_peer *authenticated=wendy_net_calloc(1,sizeof *authenticated);
    bool authenticated_ok=authenticated &&
        !wg_open(&node->pool,&s->gossip,1) &&
        !wendy_pki_mesh_authenticated_peer(connection,authenticated) &&
        !strcmp(authenticated->device,peer) &&
        !wnr_identity(&node->core,authenticated,wall,now);
    wendy_net_free(authenticated);
    if(!authenticated_ok || describe(s))goto fail;
    if(WENDY_NET_SMALL_RESOURCES || node->core.config.non_transit){
        if(wnd_key_pin(&node->core.directory,uuid,true))goto fail;
        s->key_pinned=true;
    }
    /* Attach emits initial packets synchronously; make their predicted unique
     * link visible to the node send callback before entering the core. */
    s->link=node->core.babel.last_link+1;
    uint64_t attached=0;
    if(wnr_attach(&node->core,peer,cost,wall,esp_timer_get_time(),&attached) || attached!=s->link)
        goto fail;
    s->attached=true;
    /* Advertise already cached normal origins to a newly joined carrier. */
    if(node->own_cached){struct wg_message have={.id=node->own_artifact,.op=WG_HAVE};if(announce(s,&have))goto fail;}
    for(struct wnd_entry *e=node->core.directory.entries;e;e=e->next){
        if(!e->gossip_cached)continue;
        struct wg_message have={.id={.type=1},.op=WG_HAVE};
        memcpy(have.id.hash,e->gossip_hash,32);if(announce(s,&have))goto fail;
    }

    ESP_LOGI(TAG,"native Babel stream started: router=%llu link=%llu state=%u gossip=%u",
        (unsigned long long)node->core.babel.config.router,(unsigned long long)s->link,
        (unsigned)wnr_memory(&node->core),(unsigned)wg_memory(&node->pool));
    *out=s;return 0;
fail:
    wnrs_close(s);return -1;
}
void wnrs_close(struct wnrs *s)
{
    if(!s)return;
#if WN_ROUTE_ASYNC
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
#if CONFIG_WENDY_NET_TEST_ACTOR_READINESS
    int64_t probe_at=esp_timer_get_time();
    s->node->tick_probe.calls++;
#define TICK_PROBE(phase) do {int64_t at=esp_timer_get_time(); \
    s->node->tick_probe.us[phase]+=(uint64_t)(at-probe_at);probe_at=at;} while(0)
#else
#define TICK_PROBE(phase) ((void)0)
#endif
    reap_node_crypto(s->node);
    TICK_PROBE(0);
    int64_t now = esp_timer_get_time();
    int r=0;
    if(now>=wnrs_next_deadline(s)){
        r=wnr_tick(&s->node->core,unix_now(s),now);s->node->tick_us=now+1000000;
    }
    TICK_PROBE(1);
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
    owned=s->record_verification!=NULL || s->record_verdict!=0;
    if(owned){
        struct wg_id id={.type=1};memcpy(id.hash,s->verified_record,32);
        r=wg_resume_id(&s->gossip,&id,complete,s);
        if(r==WG_RESUME_MISSING){wncrypto_cancel(&s->record_verification);s->record_verdict=0;s->verification_blocked=false;r=0;}
    }
#endif
    if(!owned)r=wg_resume(&s->gossip,complete,s);
    TICK_PROBE(3);
    if(r<0){ESP_LOGW(TAG,"router continuation failed: stage=route-gossip result=%d",r);return -1;}
    r=certificate_tick(s);
    TICK_PROBE(4);
    if(r<0){ESP_LOGW(TAG,"router continuation failed: stage=certificate result=%d",r);return -1;}
    r=catalog_tick(s,now);
    TICK_PROBE(5);
    if(r<0){ESP_LOGW(TAG,"router continuation failed: stage=service-catalog result=%d",r);return -1;}
    r=inventory(s);
    TICK_PROBE(6);
    if(r<0)return -1;
    if(!r)r = wg_poll(&s->gossip, (uint64_t)now / 1000, emit, s);
    TICK_PROBE(7);
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
    TICK_PROBE(8);
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
    if(now>=s->node->route_probe.next){
        const unsigned *rx=s->node->route_probe.received;
        struct wg_progress progress;wg_progress(&s->node->pool,&progress);
        ESP_LOGI(TAG,"gossip pending by type (hints/active/complete/bytes): route=%u/%u/%u/%u service=%u/%u/%u/%u operator=%u/%u/%u/%u",
            (unsigned)progress.hints[0],(unsigned)progress.active[0],(unsigned)progress.complete[0],(unsigned)progress.bytes[0],
            (unsigned)progress.hints[1],(unsigned)progress.active[1],(unsigned)progress.complete[1],(unsigned)progress.bytes[1],
            (unsigned)progress.hints[2],(unsigned)progress.active[2],(unsigned)progress.complete[2],(unsigned)progress.bytes[2]);
        ESP_LOGI(TAG,"route gossip totals: have=%u want=%u unavailable=%u data=%u gone=%u complete=%u unsupported=%u admitted=%u deferred=%u pending=%u objects=%u payload=%u own_cached=%u published=%u signing=%u",
            rx[0],rx[1],rx[2],rx[3],rx[4],s->node->route_probe.completed,
            s->node->route_probe.unsupported,s->node->route_probe.admitted,s->node->route_probe.deferred,
            (unsigned)s->node->pool.pending_count,(unsigned)s->node->pool.object_count,
            (unsigned)s->node->pool.payload_bytes,s->node->own_cached,s->node->core.published,s->node->signing!=NULL);
        const struct wncd_reader *reader=&s->node->certificate_read;
        ESP_LOGI(TAG,"public reader progress: phase=%u owner=%llu catalog=%u offset=%u total=%u result=%d crypto_idle=%u io_idle=%u",
            (unsigned)reader->phase,(unsigned long long)reader->owner,reader->catalog,
            (unsigned)reader->offset,(unsigned)reader->total,reader->result,
            wendy_pki_work_idle(),wendy_pki_io_work_idle());
        for(const struct pending_manifest *pending=s->node->pending;pending;pending=pending->next)
            ESP_LOGI(TAG,"router identity progress: peer=%s supplier=%llu retry_ms=%lld remaining_ms=%lld",pending->principal+69,(unsigned long long)pending->supplier,(long long)((now-pending->asked)/1000),(long long)((pending->deadline-now)/1000));
        for(const struct wnrs *peer=s->node->sessions;peer;peer=peer->next){
            ESP_LOGI(TAG,"certificate fetch progress: link=%llu peer=%s index=%u waiting=%u owner=%u",(unsigned long long)peer->link,peer->fetch.chain ? peer->fetch.chain->principal+69:"none",(unsigned)peer->fetch.index,peer->fetch.waiting,s->node->fetch_owner==peer);
            ESP_LOGI(TAG,"router input progress: link=%llu route_verify=%u verdict=%d route_cert_reply=%u catalog_paused=%u operator_paused=%u",
                (unsigned long long)peer->link,peer->verification_blocked,peer->record_verdict,
                peer->certificate_reply_pending,0,
                0
            );
        }
        s->node->route_probe.next=now+INT64_C(15000000);
    }
#endif
#undef TICK_PROBE
#if CONFIG_WENDY_NET_TEST_ACTOR_READINESS
    if(!s->node->tick_probe.next)s->node->tick_probe.next=now+INT64_C(15000000);
    if(now>=s->node->tick_probe.next){
        const uint64_t *p=s->node->tick_probe.us;
        ESP_LOGI(TAG,"router tick wall_us interval: calls=%u reap=%llu babel=%llu operator=%llu route_gossip=%llu certificate=%llu service=%llu inventory=%llu gossip_poll=%llu lookup=%llu probe_bytes=%u",
            s->node->tick_probe.calls,(unsigned long long)p[0],(unsigned long long)p[1],
            (unsigned long long)p[2],(unsigned long long)p[3],(unsigned long long)p[4],
            (unsigned long long)p[5],(unsigned long long)p[6],(unsigned long long)p[7],
            (unsigned long long)p[8],(unsigned)sizeof s->node->tick_probe);
        memset(&s->node->tick_probe,0,sizeof s->node->tick_probe);
        s->node->tick_probe.next=now+INT64_C(15000000);
    }
#endif
    return 0;
}
static int control_parsed(struct wnrs *s,const void *data,size_t size,const struct wn_doc *d)
{
    int kind = wn_doc_member(d, 0, "kind");
    if(kind<0 || d->tokens[kind].type!='"' || d->tokens[kind].end<=d->tokens[kind].start+d->tokens[kind].header)return -1;
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
    #if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
        if((unsigned)m.op<5)s->node->route_probe.received[m.op]++;
#endif
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
            if(wncf_chain_read(d,(unsigned)chain,s->identity.tenant,&description))return -1;
            if(!s->node->certificates.opened || s->fetch.chain)return 0;
            char self[106];if(wn_principal(s->identity.tenant,s->identity.device,self)<0)return -1;
            if(!strcmp(self,description.principal))return 0;
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
                if(chain_verified(s->node,&description))return 0;
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
        return -1;
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
    else ESP_LOGW(TAG,"invalid router control JSON: bytes=%u",(unsigned)size);
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
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
static void lookup_diagnostic(const struct wnr_core *c,const uint8_t address[16],int64_t now)
{
    struct wb_prefix prefix={.bits=128,.family=6};memcpy(prefix.bytes,address,16);
    const struct wb_route *route=wb_lookup(&c->babel,&prefix);
    const struct wnd_entry *entry=NULL;
    for(const struct wnd_entry *e=c->directory.entries;e;e=e->next)
        if(!memcmp(e->address,address,16)){entry=e;break;}
    const struct wb_link_state *link=NULL;
    if(route)for(size_t i=0;i<c->babel.links_capacity;i++)
        if(c->babel.links[i].config.id==route->link){link=c->babel.links+i;break;}
    uint64_t tick=(uint64_t)(now-c->epoch_us)/1000;
    bool candidate_live=false;
    if(route)for(size_t i=0;i<c->babel.candidates_capacity;i++){
        const struct wb_candidate *candidate=c->babel.candidates+i;
        if(candidate->used && candidate->expires>tick && candidate->advertised!=WB_INFINITY &&
           candidate->route.link==route->link && candidate->route.router==route->router &&
           candidate->route.seqno==route->seqno && wb_prefix_equal(&candidate->route.prefix,&prefix))candidate_live=true;
    }
    ESP_LOGW(TAG,"IP source lookup: ready=%u stopped=%u clock_delta_us=%lld raw=%u router=%llu seq=%u metric=%u unreachable=%u candidate_live=%u link_tx=%u ihu_live=%u hello_live=%u manifest=%u manifest_router=%llu manifest_seq=%u manifest_remaining_ms=%lld receipt_pending=%u authorized=%u",
        (unsigned)c->ready,(unsigned)c->stopped,(long long)(now-c->now_us),route!=NULL,
        (unsigned long long)(route ? route->router:0),(unsigned)(route ? route->seqno:0),
        (unsigned)(route ? route->metric:0),(unsigned)(route ? route->unreachable:0),candidate_live,
        (unsigned)(link ? link->tx:WB_INFINITY),link && link->ihu_expires>tick,
        link && (link->hello_expires[0]>tick || link->hello_expires[1]>tick),entry!=NULL,
        (unsigned long long)(entry ? entry->manifest.origin.router_id:0),
        (unsigned)(entry ? entry->manifest.origin.seqno:0),
        (long long)(entry ? (entry->deadline_us-now)/1000:0),entry && entry->pending_receipt,
        route && wnd_authorizes(&c->directory,address,route->router,route->seqno,now));
}
#endif
int wnrs_packet_route(struct wnrs *s,void *data,size_t size,bool incoming,uint64_t *outgoing)
{
    int64_t now=esp_timer_get_time();
    int result=wnr_packet(&s->node->core,incoming ? s->link:0,data,size,now,outgoing);
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
    static int64_t rejection_logged_at;
    if(result<0 && incoming && data && size>=40 && now-rejection_logged_at>=INT64_C(1000000)){
        rejection_logged_at=now;
        const uint8_t *packet=data;struct wb_route source={0},destination={0};
        bool source_known=wnr_lookup(&s->node->core,packet+8,now,&source);
        bool destination_known=wnr_lookup(&s->node->core,packet+24,now,&destination);
        char from[48],to[48];wn_prefix(packet+8,from);wn_prefix(packet+24,to);
        ESP_LOGW(TAG,"IP route rejected: result=%d in_link=%llu source=%s source_known=%u source_local=%u destination=%s destination_known=%u destination_local=%u bytes=%u",
            result,(unsigned long long)s->link,from,(unsigned)source_known,(unsigned)source.local,
            to,(unsigned)destination_known,(unsigned)destination.local,(unsigned)size);
        if(!source_known)lookup_diagnostic(&s->node->core,packet+8,now);
    }
#endif
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
    if(!publishing && c->publication_dirty && c->published &&
       c->published_us+INT64_C(1000000)<deadline)deadline=c->published_us+INT64_C(1000000);
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
