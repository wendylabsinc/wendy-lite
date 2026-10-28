/* Ordinary native three-node catalogue line: signed publish, routed nonce
 * inventories, partition/rejoin and refresh. Identity callbacks represent an
 * already verified cache; real full-path Go/C checks are separate fixtures. */
#include "catalog_internal.h"
#include "../../../Sources/CWendyLite/include/wendy_services.h"
#include "cJSON.h"
#include "certificate_wire.h"
#include "wendy_net_control.h"
#include "wendy_pki_crypto.h"
#include <mbedtls/pk.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct node {struct wnsc_node *catalog;struct wg_pool pool;struct wnsc_link *links[3];unsigned index;char *journal;size_t journal_size;};
struct delivery {struct delivery *next;struct wnsc_link *to;size_t size;char bytes[];};
static struct node nodes[3];static struct delivery *head,**tail=&head;
static mbedtls_pk_context signer;static struct wendy_pki_mesh_peer key;
static uint8_t fingerprint[32];
static const char tenant[]="2558fd76-afc7-466e-9613-6b715296a526";
static const char *ids[]={"00000000-0000-4000-8000-000000000004","00000000-0000-4000-8000-000000000005","00000000-0000-4000-8000-000000000006"};
static uint64_t clock_ms=1000;static int64_t wall(void){return 1790000000000+(int64_t)clock_ms;}
static unsigned routed_requests,verified_inventories,service_signatures;
static uint32_t guest_epoch=1;
static bool guest_catalog_ready=true;
static uint64_t guest_revision=1000;
static bool track_downloads=true;
static unsigned active_downloads[3],maximum_downloads[3];
static struct wnsc_registry *guest_registry;
static int guest_listener=7;
static int listener_owner(void *context,uint16_t port,bool datagram)
{(void)context;return datagram && port==28081 ? guest_listener:-1;}
static int transport(void *context,uint64_t id,const void *bytes,size_t size)
{
    struct node *from=context;unsigned to=(unsigned)id-1;assert(to<3 && from->links[to]);
    struct wn_catalog_fragment fragment;
    if(track_downloads && !wn_catalog_fragment_read(bytes,size,&fragment) &&
       !fragment.offset && fragment.total==fragment.size){
        struct wn_doc doc;
        if(!wn_doc_parse(&doc,fragment.data,fragment.size) &&
           wn_doc_equal(&doc,wn_doc_member(&doc,0,"kind"),"fresh-request")){
            struct wns_fresh_request query;
            assert(!wns_fresh_request_read(&doc,(unsigned)wn_doc_member(&doc,0,"request"),tenant,&query));
            if(!strcmp(query.requester,from->catalog->principal)){
                unsigned active=++active_downloads[from->index];assert(active<=1);
                if(active>maximum_downloads[from->index])maximum_downloads[from->index]=active;
            }
        }
    }
    assert(nodes[to].links[from->index]);struct delivery *d=malloc(sizeof *d+size);assert(d);
    d->next=NULL;d->to=nodes[to].links[from->index];d->size=size;memcpy(d->bytes,bytes,size);
    *tail=d;tail=&d->next;return 0;
}
static int sign(void *context,bool inventory,const void *body,size_t size,uint8_t signature[80],size_t *written)
{
    (void)context;if(!inventory)service_signatures++;uint8_t digest[32];int r=inventory ? wendy_pki_inventory_digest(body,size,digest):wendy_pki_service_digest(body,size,digest);
    return r || mbedtls_pk_sign(&signer,MBEDTLS_MD_SHA256,digest,sizeof digest,signature,80,written);
}
static int leaf(void *context,uint8_t hash[32]){(void)context;memcpy(hash,fingerprint,32);return 0;}
static int64_t expires(void *context){(void)context;return 1790003600000;}
static int describe(void *context,const char *principal,char *out,size_t cap)
{
    (void)context;struct wncf_chain chain={.count=1};strcpy(chain.principal,principal);
    memcpy(chain.hashes[0],fingerprint,32);return wncf_descriptor_write(&chain,out,cap);
}
static int part(void *context,const uint8_t hash[32],size_t offset,uint8_t out[1024],size_t *total)
{(void)context;(void)hash;(void)offset;(void)out;(void)total;return -1;}
static bool part_ready;
static unsigned part_releases;
static int async_part(void *context,uint64_t link,const uint8_t hash[32],size_t offset,
    uint8_t out[1024],size_t *total)
{
    (void)context;assert(link && hash[0]==17 && offset==0);
    if(!part_ready)return -2;
    *total=2048;if(out)memset(out,3,1024);return 1024;
}
static void async_part_release(void *context,uint64_t link,const uint8_t hash[32],size_t offset)
{(void)context;assert(link && hash[0]==17 && !offset);part_releases++;}
static int chain(void *context,uint64_t link,const struct wncf_chain *description)
{(void)context;(void)link;(void)description;return 0;}
static int verify(void *context,const struct wns_record *r)
{
    struct node *node=context;uint8_t self[16];assert(!wn_uuid_parse(ids[node->index],self));
    if(!memcmp(self,r->device,16))return 1;
    assert(!memcmp(r->fingerprint,fingerprint,32));
    return wendy_pki_service_verify(&key,r->body,r->body_size,r->signature,r->signature_size);
}
static uint64_t next_hop(void *context,const uint8_t uuid[16],uint64_t exclude)
{
    struct node *node=context;unsigned destination=3;
    for(unsigned i=0;i<3;i++){uint8_t expected[16];assert(!wn_uuid_parse(ids[i],expected));if(!memcmp(uuid,expected,16))destination=i;}
    if(destination>=3 || destination==node->index || !nodes[destination].catalog)return 0;
    unsigned next=node->index==1 ? destination:1;
    uint64_t id=next+1;return node->links[next] && id!=exclude ? id:0;
}
static int verify_inventory(void *context,uint64_t supplier,const struct wns_fresh_request *query,const struct wns_inventory *view)
{
    struct node *node=context;(void)supplier;
    assert(!strcmp(query->requester,node->catalog->principal));
    int r=wendy_pki_inventory_verify(&key,view->body,view->body_size,view->signature,view->signature_size);
    if(!r && track_downloads){assert(active_downloads[node->index]);active_downloads[node->index]--;}
    if(!r)verified_inventories++;
    if(!r && ((node->index==0 && !strcmp(query->origin+69,ids[2])) ||
        (node->index==2 && !strcmp(query->origin+69,ids[0]))))routed_requests++;
    return r;
}
static int persist(void *context,const void *bytes,size_t size)
{
    struct node *node=context;char *next=malloc(size);assert(next);memcpy(next,bytes,size);
    free(node->journal);node->journal=next;node->journal_size=size;return 0;
}
static void check_artifact_memos(const struct wnsc_node *node)
{
    for(const struct wns_entry *e=node->records.entries;e;e=e->next)if(e->wire){
        struct wg_id id={.type=2};assert(e->artifact_known);
        assert(!wn_gossip_identify(NULL,2,e->wire,e->wire_size,id.hash));
        assert(!memcmp(e->artifact_hash,id.hash,32));
        /* A memoized live body is not a forgotten-body receipt. */
        assert(!e->body_retired && !wnsc_known_artifact(node,&id));
    }
}
static void open_node(unsigned i)
{
    struct node *node=&nodes[i];node->index=i;
    struct wg_config gossip={.identify=wn_gossip_identify,.objects=128,.pending=8,.bytes=64*1024};
    assert(!wg_init(&node->pool,&gossip));
    struct wnsc_config config={.context=node,.tenant=tenant,.device=ids[i],.send=transport,
        .catalog_bytes=i==1 ? 16384:0,
        .sign=sign,.fingerprint=leaf,.expires=expires,.describe=describe,.part=part,.chain=chain,
        .verify=verify,.persist=persist,.next_hop=next_hop,.verify_inventory=verify_inventory};
    assert(!wnsc_open(&node->catalog,&config,&node->pool,node->journal,node->journal_size));
    assert(node->catalog->records.byte_limit==(i==1 ? 16384:32768));
    for(const struct wns_entry *e=node->catalog->records.entries;e;e=e->next)
        assert(!e->wire && !e->artifact_known); /* Restart restores no wire memo. */
}
static void connect(unsigned a,unsigned b)
{
    assert(!wnsc_link_open(nodes[a].catalog,&nodes[a].links[b],b+1));
    assert(!wnsc_link_open(nodes[b].catalog,&nodes[b].links[a],a+1));
}
static void future_message(struct wnsc_link *link,bool gossip)
{
    char body[256],frame[WN_CONTROL_MAX+1];struct wn_writer w={.data=(uint8_t*)body,.capacity=sizeof body,.maximum=sizeof body};
    wn_map(&w,2);wn_text(&w,"kind");wn_text(&w,gossip ? "gossip":"future-service-summary");
    if(gossip){wn_text(&w,"gossip");wn_map(&w,2);wn_text(&w,"op");wn_text(&w,"future-cache-hint");
        wn_text(&w,"details");wn_map(&w,1);wn_text(&w,"mode");wn_text(&w,"compact");}
    else {wn_text(&w,"details");wn_map(&w,1);wn_text(&w,"pages");wn_uint(&w,3);}
    int size=wn_finish(&w);assert(size>0);
    int n=wn_catalog_fragment_write((uint32_t)size,0,body,(size_t)size,frame,sizeof frame);
    assert(n>0 && !wnsc_receive(link,frame,(size_t)n,wall(),clock_ms));
}
static void pending_certificate_test(struct wnsc_link *link)
{
    struct wnsc_config *config=&link->node->config;
    config->part_async=async_part;config->part_release=async_part_release;
    struct wncf_request request={0};request.hash[0]=17;
    char body[256],frame[WN_CONTROL_MAX+1];
    int size=wncf_request_write(&request,body,sizeof body);assert(size>0);
    int n=wn_catalog_fragment_write((uint32_t)size,0,body,(size_t)size,frame,sizeof frame);assert(n>0);
    assert(!wnsc_receive(link,frame,(size_t)n,wall(),clock_ms));
    assert(wnsc_receive_paused(link) && link->certificate_reply_pending && !part_releases);
    /* A following ordered request stays at the outer carrier boundary, with
     * no replacement/discard of the first bounded request slot. */
    assert(wnsc_receive(link,frame,(size_t)n,wall(),clock_ms)==1);
    assert(link->certificate_reply.hash[0]==17 && !link->assembly.bytes);
    assert(!wnsc_tick(link,wall(),clock_ms) && wnsc_receive_paused(link));
    /* Fill the ordinary bounded send queue with harmless future control
     * messages. A ready result is acknowledged only when its reply fits. */
    struct wn_writer w={.data=(uint8_t*)body,.capacity=sizeof body,.maximum=sizeof body};
    wn_map(&w,1);wn_text(&w,"kind");wn_text(&w,"future-service-summary");
    size=wn_finish(&w);assert(size>0);
    while(!wnsc_queue(link,body,(size_t)size)){}
    part_ready=true;
    assert(!wnsc_tick(link,wall(),clock_ms) && !part_releases && wnsc_receive_paused(link));
    unsigned polls=0;
    while(wnsc_receive_paused(link)){assert(++polls<2000);assert(!wnsc_tick(link,wall(),clock_ms));}
    assert(part_releases==1 && !link->certificate_reply_pending);
    /* The outer caller can now redeliver the untouched following frame. */
    assert(!wnsc_receive(link,frame,(size_t)n,wall(),clock_ms));
    while(wnsc_receive_paused(link)){assert(++polls<2000);assert(!wnsc_tick(link,wall(),clock_ms));}
    assert(part_releases==2);
    config->part_async=NULL;config->part_release=NULL;
}
static bool own_blob(void *context,const struct wg_id *id)
{struct node *n=context;return wnsc_own_artifact(n->catalog,id);}
static void evict_blob(void *context,const struct wg_id *id,const void *bytes,size_t size)
{struct node *n=context;(void)size;wnsc_retire_artifact(n->catalog,id,bytes);}
static bool known_blob(void *context,const struct wg_id *id)
{struct node *n=context;return wnsc_known_artifact(n->catalog,id);}
static int unused_emit(void *ctx,const struct wg_message *m)
{(void)ctx;(void)m;assert(!"retired object must not trigger a request");return 0;}
static int unused_complete(void *ctx,const struct wg_id *id,const void *bytes,size_t size)
{(void)ctx;(void)id;(void)bytes;(void)size;return 0;}
static void publish(unsigned i)
{
    struct wns_record r={.port=28080,.issued=wall(),.expires=wall()+120000};
    strcpy(r.app,"com.example.sensor");strcpy(r.service,"temperature");strcpy(r.type,"_sensorlink._tcp");strcpy(r.instance,"Native sensor");
    assert(!wnsc_publish(nodes[i].catalog,&r,NULL,wall(),clock_ms));
}
static void drive(unsigned steps)
{
    for(unsigned step=0;step<steps;step++){
        clock_ms+=20;
        for(unsigned i=0;i<3;i++)for(unsigned j=0;j<3;j++)if(nodes[i].links[j])
            assert(!wnsc_tick(nodes[i].links[j],wall(),clock_ms));
        assert(!wnsc_guest_tick(&guest_registry,nodes[0].catalog,listener_owner,NULL,wall(),clock_ms));
        unsigned count=0;
        while(head){
            assert(++count<10000);struct delivery *d=head;head=d->next;if(!head)tail=&head;
            assert(!wnsc_receive(d->to,d->bytes,d->size,wall(),clock_ms));free(d);
        }
    }
}
int services_epoch(void){return (int)guest_epoch;}
int services_publish(const void *spec,int size)
{return wnsc_guest_register(&guest_registry,spec,(size_t)size,listener_owner,NULL);}
int services_withdraw(const void *id,int size)
{
    char service[64];assert(size>0 && size<64);memcpy(service,id,(size_t)size);service[size]=0;
    int r=wnsc_guest_unregister(&guest_registry,guest_catalog_ready ? nodes[0].catalog:NULL,service,wall(),clock_ms);
    return r>0 || r==-2 ? -2:r;
}
static int guest_next_revision(void *context,uint64_t *out)
{(void)context;*out=++guest_revision;return 0;}
static void browse(unsigned i,unsigned expected)
{
    int size=wnsc_browse(nodes[i].catalog,"_sensorlink._tcp",wall(),NULL,0);assert(size>0);
    char *bytes=malloc((size_t)size+1);assert(bytes);
    assert(wnsc_browse(nodes[i].catalog,"_sensorlink._tcp",wall(),bytes,(size_t)size+1)==size);
    cJSON *list=cJSON_ParseWithLength(bytes,(size_t)size);assert(cJSON_IsArray(list));
    unsigned count=0;
    for(cJSON *item=list->child;item;item=item->next){
        cJSON *record=cJSON_GetObjectItemCaseSensitive(item,"record");assert(cJSON_IsObject(record));
        assert(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(item,"host")) && cJSON_IsString(cJSON_GetObjectItemCaseSensitive(item,"device")));
        cJSON *type=cJSON_GetObjectItemCaseSensitive(record,"type");assert(cJSON_IsString(type) && !strcmp(type->valuestring,"_sensorlink._tcp"));count++;
    }
    cJSON_Delete(list);
    assert(count==expected);free(bytes);
}
int main(int argc,char **argv)
{
    assert(argc==2 && !wendy_pki_crypto_init());
    FILE *f=fopen(argv[1],"rb");assert(f);uint8_t der[512];size_t size=fread(der,1,sizeof der,f);fclose(f);
    mbedtls_pk_init(&signer);assert(!mbedtls_pk_parse_key(&signer,der,size,NULL,0));
    uint8_t spki[128];int count=mbedtls_pk_write_pubkey_der(&signer,spki,sizeof spki);assert(count>0);
    key.spki_size=(size_t)count;memcpy(key.spki,spki+sizeof spki-count,(size_t)count);
    assert(!wendy_pki_sha256(key.spki,key.spki_size,fingerprint));
    for(unsigned i=0;i<3;i++)open_node(i);
    connect(0,1);connect(1,2);
    future_message(nodes[0].links[1],false);
    for(unsigned i=0;i<3;i++)publish(i);
    const char spec[]="{\"serviceId\":\"echo\",\"type\":\"_wendy-echo._udp\",\"instance\":\"Guest echo\",\"port\":28081,\"txt\":[\"version=1\"]}";
    assert(!wnsc_guest_register(&guest_registry,spec,sizeof spec-1,listener_owner,NULL));
    drive(1000);
    for(unsigned i=0;i<3;i++)check_artifact_memos(nodes[i].catalog);
    track_downloads=false;
    for(unsigned i=0;i<3;i++)assert(maximum_downloads[i]==1 && !active_downloads[i]);
    pending_certificate_test(nodes[0].links[1]);
    future_message(nodes[0].links[1],true);
    for(unsigned i=0;i<3;i++)for(unsigned j=0;j<3;j++){
        uint8_t device[16];assert(!wn_uuid_parse(ids[j],device));assert(wnsc_ready(nodes[i].catalog,device));
        struct wns_entry *e=wns_store_find(&nodes[i].catalog->records,device,"com.example.sensor","temperature");
        assert(e && e->wire && e->generation==1 && !e->unavailable);
    }
    /* Repeated guest replay of the same normalized spec/listener must not
     * dirty or resign the existing service, nor postpone its refresh timer. */
    uint8_t guest_self[16];assert(!wn_uuid_parse(ids[0],guest_self));
    struct wns_entry *stable=wns_store_find(&nodes[0].catalog->records,guest_self,WNS_GUEST_APP_ID,"echo");
    assert(stable && stable->wire);
    uint64_t stable_generation=stable->generation;int64_t stable_expires=stable->expires;
    unsigned stable_signatures=service_signatures;
    for(unsigned replay=0;replay<8;replay++)assert(!wnsc_guest_register(&guest_registry,spec,sizeof spec-1,listener_owner,NULL));
    drive(1);stable=wns_store_find(&nodes[0].catalog->records,guest_self,WNS_GUEST_APP_ID,"echo");
    assert(stable->generation==stable_generation && stable->expires==stable_expires && service_signatures==stable_signatures);
    assert(routed_requests>=2 && verified_inventories>=6);
    for(unsigned i=0;i<3;i++)browse(i,3);
    struct wns_record late;
    const struct wns_entry *sample=nodes[0].catalog->records.entries;
    assert(sample && sample->wire && wns_record_read(sample->wire,sample->wire_size,"default",tenant,sample->expires+1,&late)==1);
    /* Drop one idle remote body from both owners. Verified endpoint browsing
     * still finds it; the full-record API does not invent missing details. */
    assert(!nodes[0].pool.serving && !nodes[0].pool.pending_count);
    nodes[0].pool.config.fifo=true;nodes[0].pool.config.bytes=nodes[0].pool.payload_bytes;
    nodes[0].pool.config.context=&nodes[0];nodes[0].pool.config.protected_object=own_blob;
    nodes[0].pool.config.evicted=evict_blob;
    uint8_t more[128];memset(more,9,sizeof more);struct wg_id extra;
    assert(!wg_offer(&nodes[0].pool,1,more,sizeof more,clock_ms+60000,clock_ms,&extra));
    struct wns_entry *summary=NULL;
    for(struct wns_entry *e=nodes[0].catalog->records.entries;e;e=e->next)
        if(e->body_retired && e->summary_verified && e->port==28080)summary=e;
    assert(summary && !summary->wire);
    int compact=wnsc_browse_endpoints(nodes[0].catalog,"_sensorlink._tcp",wall(),NULL,0);assert(compact>2);
    char *endpoints=malloc((size_t)compact+1);assert(endpoints);
    assert(wnsc_browse_endpoints(nodes[0].catalog,"_sensorlink._tcp",wall(),endpoints,(size_t)compact+1)==compact);
    assert(strstr(endpoints,ids[2]) && strstr(endpoints,"\"detailsAvailable\":false") && strstr(endpoints,"\"port\":28080"));
    free(endpoints);browse(0,2);
    /* An admitted local publication keeps its semantic state even when a
     * full relay metadata table cannot retain its blob. */
    nodes[0].pool.config.objects=nodes[0].pool.object_count;
    nodes[0].pool.config.known_object=known_blob;
    struct wns_record overflow={.port=28080,.issued=wall(),.expires=wall()+120000};
    strcpy(overflow.app,"com.example.sensor");strcpy(overflow.service,"overflow");
    strcpy(overflow.type,"_cache-test._tcp");strcpy(overflow.instance,"Bounded cache");
    assert(!wnsc_publish(nodes[0].catalog,&overflow,NULL,wall(),clock_ms));
    uint8_t own_device[16];assert(!wn_uuid_parse(ids[0],own_device));
    struct wns_entry *local=wns_store_find(&nodes[0].catalog->records,own_device,overflow.app,overflow.service);
    assert(local && local->body_retired && local->artifact_known && local->summary_verified && !local->wire);
    struct wg_message repeated={.op=WG_HAVE,.id.type=2};memcpy(repeated.id.hash,local->artifact_hash,32);
    size_t pending=nodes[0].pool.pending_count;
    assert(!wg_receive(&nodes[0].links[1]->gossip,&repeated,clock_ms,unused_emit,unused_complete,NULL));
    assert(nodes[0].pool.pending_count==pending);
    /* Rejoin with the origin still running but its signed body evicted. The
     * origin inventory must keep peers' already verified service live. */
    local=wns_store_find(&nodes[0].catalog->records,own_device,"com.example.sensor","temperature");
    struct wg_id own_id={.type=2};assert(local && local->wire && !wn_gossip_identify(NULL,2,local->wire,local->wire_size,own_id.hash));
    wnsc_retire_artifact(nodes[0].catalog,&own_id,local->wire);wg_forget(&nodes[0].pool,&own_id);
    struct wns_entry *guest=wns_store_find(&nodes[0].catalog->records,own_device,WNS_GUEST_APP_ID,"echo");
    assert(guest && guest->wire);uint64_t guest_generation=guest->generation;
    struct wg_id guest_id={.type=2};assert(!wn_gossip_identify(NULL,2,guest->wire,guest->wire_size,guest_id.hash));
    wnsc_retire_artifact(nodes[0].catalog,&guest_id,guest->wire);wg_forget(&nodes[0].pool,&guest_id);
    wnsc_link_close(nodes[1].links[0]);nodes[1].links[0]=NULL;
    wnsc_link_close(nodes[0].links[1]);nodes[0].links[1]=NULL;drive(100);
    connect(0,1);drive(1000);browse(2,3);
    guest=wns_store_find(&nodes[0].catalog->records,own_device,WNS_GUEST_APP_ID,"echo");
    assert(guest && guest->generation==guest_generation && !guest->wire && guest->listener==guest_listener);
    /* A restarts with its persisted high-water but without a running service.
     * Current route loss invalidates projection; the new inventory removes the
     * old live body. Publishing again advances the durable generation. */
    wnsc_link_close(nodes[1].links[0]);nodes[1].links[0]=NULL;
    wnsc_close(nodes[0].catalog);nodes[0].catalog=NULL;nodes[0].links[1]=NULL;wg_deinit(&nodes[0].pool);
    drive(100);uint8_t a[16];assert(!wn_uuid_parse(ids[0],a));assert(!wnsc_ready(nodes[2].catalog,a));
    browse(2,2);
    open_node(0);connect(0,1);drive(1000);
    struct wns_entry *old=wns_store_find(&nodes[2].catalog->records,a,"com.example.sensor","temperature");
    assert(old && !old->wire && old->unavailable && wnsc_ready(nodes[2].catalog,a));
    browse(2,2);
    publish(0);drive(1000);old=wns_store_find(&nodes[2].catalog->records,a,"com.example.sensor","temperature");
    assert(old && old->wire && old->generation==2 && !old->unavailable);
    browse(2,3);
    /* Refresh all origins before their old leases expire. Sparse gossip must
     * retain only the current service payloads on every intermediate peer. */
    for(unsigned i=0;i<3;i++)publish(i);
    drive(1000);
    for(unsigned i=0;i<3;i++){
        size_t live=0;
        for(const struct wns_entry *e=nodes[i].catalog->records.entries;e;e=e->next)live+=e->wire_size;
        assert(!nodes[i].pool.pending_count && nodes[i].pool.payload_bytes==live);
        check_artifact_memos(nodes[i].catalog);browse(i,3);
    }
    int bytes=wnsc_browse(nodes[2].catalog,"_wendy-echo._udp",wall(),NULL,0);assert(bytes>2);
    guest_listener=-1;drive(100);assert(!guest_registry);
    assert(wnsc_browse(nodes[2].catalog,"_wendy-echo._udp",wall(),NULL,0)==2);
    guest_listener=8;
    assert(!wnsc_guest_register(&guest_registry,spec,sizeof spec-1,listener_owner,NULL));drive(100);
    assert(wnsc_browse(nodes[2].catalog,"_wendy-echo._udp",wall(),NULL,0)>2);
    /* Automatic five-minute refresh still advances the signed lease. */
    struct wns_entry *renewed=wns_store_find(&nodes[0].catalog->records,a,WNS_GUEST_APP_ID,"echo");
    uint64_t before_refresh=renewed->generation;int64_t before_expiry=renewed->expires;
    clock_ms+=300001;drive(20);renewed=wns_store_find(&nodes[0].catalog->records,a,WNS_GUEST_APP_ID,"echo");
    assert(renewed->generation>before_refresh && renewed->expires>before_expiry);
    /* OFF discards every host registration; the still-running guest retains
     * only its own declaration/replay state and restores it on a new epoch. */
    wendy_service_replay replay={0};
    assert(!wendy_service_replay_step(&replay,spec,sizeof spec-1,0,clock_ms));
    wnsc_guest_clear(&guest_registry);guest_epoch=0;clock_ms+=1000;
    assert(wendy_service_replay_step(&replay,spec,sizeof spec-1,0,clock_ms)==-2 && !guest_registry);
    clock_ms+=900001;drive(20);
    assert(wnsc_browse(nodes[2].catalog,"_wendy-echo._udp",wall(),NULL,0)==2);
    guest_epoch=2;
    assert(!wendy_service_replay_step(&replay,spec,sizeof spec-1,0,clock_ms));drive(100);
    assert(guest_registry && wnsc_browse(nodes[2].catalog,"_wendy-echo._udp",wall(),NULL,0)>2);
    /* An OFF withdrawal must retire a still-valid remote body after a fresh
     * RAM-only local catalogue has forgotten the original service entirely. */
    struct wns_entry *remote_live=wns_store_find(&nodes[2].catalog->records,a,WNS_GUEST_APP_ID,"echo");
    assert(remote_live && remote_live->wire && !remote_live->withdraw && remote_live->expires>wall());
    int64_t remote_live_until=remote_live->expires;uint64_t remote_live_generation=remote_live->generation;
    wnsc_guest_clear(&guest_registry);wns_store_clear(&nodes[0].catalog->records);
    nodes[0].catalog->config.next_revision=guest_next_revision;
    assert(!wns_store_find(&nodes[0].catalog->records,a,WNS_GUEST_APP_ID,"echo"));
    guest_epoch=0;wendy_service_replay_changed(&replay);clock_ms+=1000;
    assert(wendy_service_replay_step(&replay,"echo",4,1,clock_ms)==-2);
    assert(wnsc_browse(nodes[2].catalog,"_wendy-echo._udp",wall(),NULL,0)>2);
    guest_epoch=3;guest_catalog_ready=false;clock_ms+=1000;
    assert(wendy_service_replay_step(&replay,"echo",4,1,clock_ms)==-2);
    assert(!replay.epoch && wnsc_browse(nodes[2].catalog,"_wendy-echo._udp",wall(),NULL,0)>2);
    guest_catalog_ready=true;clock_ms+=1000;
    assert(!wendy_service_replay_step(&replay,"echo",4,1,clock_ms));drive(100);
    const struct wns_entry *tombstone=wns_store_find(&nodes[0].catalog->records,a,WNS_GUEST_APP_ID,"echo");
    assert(tombstone && tombstone->wire && tombstone->withdraw && tombstone->generation>remote_live_generation);
    for(unsigned i=0;i<3;i++)check_artifact_memos(nodes[i].catalog);
    assert(wall()<remote_live_until); /* Actual withdrawal, not lease expiry. */
    assert(!guest_registry && wnsc_browse(nodes[2].catalog,"_wendy-echo._udp",wall(),NULL,0)==2);
    drive(100);assert(wnsc_browse(nodes[2].catalog,"_wendy-echo._udp",wall(),NULL,0)==2);
    printf("normal native three-node catalogue line: inventories=%u routed=%u, state=%zu/%zu/%zu bytes\n",
        verified_inventories,routed_requests,wnsc_memory(nodes[0].catalog),wnsc_memory(nodes[1].catalog),wnsc_memory(nodes[2].catalog));
    wnsc_guest_clear(&guest_registry);
    for(unsigned i=0;i<3;i++){wnsc_close(nodes[i].catalog);wg_deinit(&nodes[i].pool);free(nodes[i].journal);}
    mbedtls_pk_free(&signer);return 0;
}
