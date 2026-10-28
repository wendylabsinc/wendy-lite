/* Normal two-carrier adapter operation. TLS admission is represented by
 * already admitted fixture peers; this exercises shared state and forwarding,
 * not certificate policy or adversarial inputs. */
#include "wendy_pki_mesh.h"
#include "nvs.h"
#include <assert.h>
#include <mbedtls/pk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct wendy_pki_connection {struct wendy_pki_mesh_peer peer;};
/* Fixture implementation of the boot-owned publication counter. */
esp_err_t wendy_pki_mesh_revision_next(uint64_t *);
#include "../src/router_session.c"

/* This fixture isolates ordinary shared routing from the independently
 * exercised public-certificate fetch/storage/verification adapters. */
static unsigned certificate_trims;
#ifndef WENDY_NET_REAL_CERT_RELAY_TEST
int wncs_open_limits(struct wncs_store *s,size_t limit,unsigned parts,unsigned chains)
{(void)limit;(void)parts;(void)chains;memset(s,0,sizeof *s);s->opened=true;return 0;}
void *wncs_retain(void *s,const uint8_t hash[32]){(void)s;(void)hash;return NULL;}
void wncs_release(void *loan){assert(!loan);}
void wncs_close(struct wncs_store *s){(void)s;}
size_t wncs_trim(struct wncs_store *s){(void)s;certificate_trims++;return 0;}
void wncs_set_baseline(struct wncs_store *s,void *context,
    int (*read)(void *,const uint8_t[32],size_t,uint8_t[WNCF_CHUNK],size_t *))
{s->baseline_context=context;s->baseline_read=read;}
void wncs_set_baseline_index(struct wncs_store *s,const struct wendy_pki_mesh_public_index *index,
    bool (*current)(void *,const struct wendy_pki_mesh_public_index *))
{s->baseline_index=index ? *index:(struct wendy_pki_mesh_public_index){0};s->baseline_current=current;s->baseline_index_enabled=true;}
#endif
static unsigned index_snapshots;
static bool index_available=true;
int wendy_pki_mesh_public_index_snapshot(wendy_pki_connection *connection,
    const struct wendy_pki_mesh_identity *identity,struct wendy_pki_mesh_public_index *out)
{
    (void)connection;index_snapshots++;memset(out,0,sizeof *out);
    if(!index_available)return -1;
    out->count=1;out->sizes[0]=900;out->certificate_epoch=1;out->config_generation=identity->config_generation;return 0;
}
bool wendy_pki_mesh_public_index_current(const struct wendy_pki_mesh_public_index *index,
    const struct wendy_pki_mesh_identity *identity)
{return index->count==1 && index->certificate_epoch==1 && index->config_generation==identity->config_generation;}
int wendy_pki_mesh_local_part(const struct wendy_pki_mesh_identity *identity,
    const uint8_t hash[32],size_t offset,uint8_t out[1024],size_t *total)
{(void)identity;(void)hash;(void)offset;(void)out;(void)total;return -1;}
int wendy_pki_mesh_local_part_snapshot(const struct wendy_pki_mesh_identity *identity,
    uint32_t epoch,const uint8_t hash[32],size_t offset,uint8_t out[1024],size_t *total)
{(void)epoch;return wendy_pki_mesh_local_part(identity,hash,offset,out,total);}
#ifndef WENDY_NET_REAL_CERT_RELAY_TEST
int wncs_read(void *s,const uint8_t hash[32],size_t offset,uint8_t out[WNCF_CHUNK],size_t *total)
{(void)s;(void)hash;(void)offset;(void)out;(void)total;return 0;}
int wncs_read_resident(struct wncs_store *s,const uint8_t hash[32],size_t offset,uint8_t out[WNCF_CHUNK],size_t *total)
{return wncs_read(s,hash,offset,out,total);}
int wncs_put(void *s,const uint8_t hash[32],const void *bytes,size_t size)
{(void)s;(void)hash;(void)bytes;(void)size;return 1;}
int wncs_chain_get(struct wncs_store *s,const char *principal,int64_t now,struct wncf_chain *out)
{(void)s;(void)principal;(void)now;(void)out;return 0;}
int wncs_chain_put(struct wncs_store *s,const struct wncf_chain *chain,int64_t expires)
{(void)s;(void)chain;(void)expires;return 1;}
int wncv_start(struct wncv_job **out,struct wncs_store *store,const struct wncf_chain *chain,const struct wendy_pki_mesh_identity *clock)
{(void)out;(void)store;(void)chain;(void)clock;return 1;}
void wncv_release(struct wncv_job *job){assert(!job);}
#endif

#define FIRST_LINK_COST WNR_LAN_COST
static const char tenant[]="2558fd76-afc7-466e-9613-6b715296a526";
static const char *ids[]={"00000000-0000-4000-8000-000000000004",
                         "00000000-0000-4000-8000-000000000005",
                         "00000000-0000-4000-8000-000000000006"};
static int64_t clock_us=1000000;
static mbedtls_pk_context key;
static unsigned opens,closes,commits;
static uint8_t journal[WNR_JOURNAL_MAX];
static size_t journal_size;
static uint8_t service_journal[32768];
static size_t service_journal_size;
int64_t esp_timer_get_time(void){return clock_us;}
static uint64_t fixture_revision,fixture_router=1000;
static bool revision_busy=true;
esp_err_t wendy_pki_mesh_revision_next(uint64_t *out)
{if(revision_busy){revision_busy=false;return ESP_ERR_TIMEOUT;}
 *out=++fixture_revision;return ESP_OK;}
void esp_fill_random(void *out,size_t size)
{assert(size==sizeof fixture_router);++fixture_router;memcpy(out,&fixture_router,size);}
esp_err_t nvs_open_from_partition(const char *part,const char *name,int mode,nvs_handle_t *out)
{(void)part;(void)name;(void)mode;*out=1;opens++;return ESP_OK;}
void nvs_close(nvs_handle_t handle){assert(handle==1);closes++;}
esp_err_t nvs_get_blob(nvs_handle_t handle,const char *name,void *out,size_t *size)
{
    assert(handle==1);bool service=name[0]=='s';
    size_t stored=service ? service_journal_size:journal_size;
    const uint8_t *bytes=service ? service_journal:journal;
    if(!stored)return ESP_ERR_NVS_NOT_FOUND;
    if(out){assert(*size>=stored);memcpy(out,bytes,stored);}
    *size=stored;return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t handle,const char *name,const void *bytes,size_t size)
{
    assert(handle==1);bool service=name[0]=='s';
    assert(size<=(service ? sizeof service_journal:sizeof journal));
    memcpy(service ? service_journal:journal,bytes,size);
    if(service)service_journal_size=size;else journal_size=size;
    return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t handle){assert(handle==1);commits++;return ESP_OK;}
bool wendy_net_app_ready(void){return true;}
int wendy_pki_mesh_authenticated_peer(wendy_pki_connection *c,struct wendy_pki_mesh_peer *out)
{*out=c->peer;return 0;}
int wendy_pki_mesh_describe(wendy_pki_connection *c,char *out,size_t size)
{
    (void)c;struct wncf_chain chain={.count=1};
    assert(wn_principal(tenant,ids[0],chain.principal)>0);
    assert(!wendy_pki_mesh_fingerprint(c,chain.hashes[0]));
    return wncf_descriptor_write(&chain,out,size);
}
int wendy_pki_mesh_part(wendy_pki_connection *c,const uint8_t hash[32],size_t offset,uint8_t out[1024],size_t *total)
{(void)c;(void)hash;(void)offset;(void)out;(void)total;return -1;}
int wendy_pki_mesh_sign(wendy_pki_connection *c,const char *principal,const void *body,size_t size,
                        uint8_t signature[80],size_t *written)
{
    (void)c;uint8_t hash[32];
    return wendy_pki_artifact_digest(0,principal,body,size,hash) ||
        mbedtls_pk_sign(&key,MBEDTLS_MD_SHA256,hash,sizeof hash,signature,80,written);
}
size_t wendy_pki_artifact_signature_capacity(wendy_pki_connection *c)
{(void)c;return 80;}
int wendy_pki_artifact_sign(wendy_pki_connection *c,unsigned kind,const char *principal,
    const void *body,size_t size,uint8_t *signature,size_t capacity,size_t *written)
{(void)c;(void)kind;(void)principal;(void)body;(void)size;(void)signature;(void)capacity;(void)written;assert(false);return -1;}
int wendy_pki_mesh_sign_digest(wendy_pki_connection *c,const char *principal,const uint8_t hash[32],
    uint8_t signature[80],size_t *written)
{
    (void)c;(void)principal;
    return mbedtls_pk_sign(&key,MBEDTLS_MD_SHA256,hash,32,signature,80,written);
}
int wendy_pki_mesh_fingerprint(wendy_pki_connection *c,uint8_t hash[32])
{(void)c;memset(hash,7,32);return 0;}
struct endpoint {struct wnrs *session;struct wb_engine remote;unsigned index,control_backpressure;};
struct frame {struct frame *next;struct endpoint *peer;bool incoming;size_t size;uint8_t bytes[WB_PACKET_MAX];};
static struct frame *head,**tail=&head;
static unsigned gone_messages;
static void enqueue(struct endpoint *peer,const void *bytes,size_t size,bool incoming)
{
    assert(size<=WB_PACKET_MAX);struct frame *frame=calloc(1,sizeof *frame);assert(frame);
    frame->peer=peer;frame->incoming=incoming;frame->size=size;memcpy(frame->bytes,bytes,size);
    *tail=frame;tail=&frame->next;
}
static int send_frame(void *context,const void *bytes,size_t size,bool control)
{
    if(control){
        struct endpoint *peer=context;
        if(peer->control_backpressure){peer->control_backpressure--;return WNC_LIMIT;}
        struct wg_message message;uint8_t chunk[WG_CHUNK];
        if(!wn_gossip_read(bytes,size,&message,chunk) && message.op==WG_GONE){
            assert(message.id.type==1);gone_messages++;
        }
        return 0; /* Gossip transfer itself is separately integrated. */
    }
    assert(size>1 && ((const uint8_t *)bytes)[0]==2);
    enqueue(context,(const uint8_t *)bytes+1,size-1,false);return 0;
}
static uint64_t milliseconds(void){return (uint64_t)(clock_us-1000000)/1000;}
static void remote_finish(struct endpoint *peer,int result)
{
    assert(result>=0);
    if(peer->remote.pending)assert(!wb_commit(&peer->remote,peer->remote.pending,true));
    uint8_t bytes[WB_PACKET_MAX];uint64_t link;
    for(;;){int n=wb_next_packet(&peer->remote,&link,bytes,sizeof bytes);assert(n>=0);if(!n)break;
        assert(link==1);enqueue(peer,bytes,(size_t)n,true);}
}
static bool allow_route(void *context,uint64_t router,const struct wb_prefix *prefix,uint16_t seqno)
{(void)context;(void)router;(void)prefix;(void)seqno;return true;}
static void drain(void)
{
    unsigned count=0;
    while(head){
        assert(++count<10000);struct frame *frame=head;head=frame->next;if(!head)tail=&head;
        if(frame->peer->session){
            if(frame->incoming)assert(!wnrs_routing(frame->peer->session,frame->bytes,frame->size));
            else remote_finish(frame->peer,wb_receive(&frame->peer->remote,milliseconds(),1,frame->bytes,frame->size));
        }
        free(frame);
    }
}
static void origin(struct endpoint *peer,uint64_t revision)
{
    uint8_t uuid[16],signature[80];char body[768],principal[106],proof[1500];
    assert(!wn_uuid_parse(ids[peer->index],uuid));
    struct wn_origin advertised={.router_id=peer->remote.config.router,.seqno=peer->remote.seqno};
    int64_t wall=node_unix(peer->session->node);
    int n=wn_manifest_app_write(uuid,&advertised,revision,wall,wall+60000,5054,43022,body,sizeof body);
    assert(n>0 && wn_principal(tenant,ids[peer->index],principal)>0);
    size_t signature_size;
    assert(!wendy_pki_mesh_sign(NULL,principal,body,n,signature,&signature_size));
    n=wn_manifest_wire_write(principal,body,(size_t)n,signature,signature_size,proof,sizeof proof);
    assert(n>0 && (size_t)n<sizeof proof);
    if(peer->session->node->core.config.non_transit){
        struct wg_id id={.type=1};
        assert(!wn_gossip_identify(NULL,1,proof,(size_t)n,id.hash));
        size_t previous=peer->session->node->pool.payload_bytes;
        assert(!admit_complete(peer->session,&id,proof,(size_t)n));
        assert(peer->session->node->pool.payload_bytes==previous);
        assert(known_artifact(peer->session->node,&id));
    }else assert(!wnr_manifest(&peer->session->node->core,proof,(size_t)n,wall,clock_us));
}
static void remote_open(struct endpoint *peer,uint16_t cost)
{
    struct wb_config config={.router=100+peer->index,.seed=peer->index,
        .hello_ms=1000,.update_ms=4000,.allow=allow_route};
    assert(!wb_init(&peer->remote,&config));
    struct wb_link link={.id=1,.local={0xfe,0x80},.peer={0xfe,0x80},.cost=cost,.max_packet=WB_PACKET_MAX};
    link.local[15]=2;link.peer[15]=1;
    remote_finish(peer,wb_add_link(&peer->remote,milliseconds(),&link));
    uint8_t uuid[16];assert(!wn_uuid_parse(ids[peer->index],uuid));
    struct wb_prefix prefix={.family=6,.bits=128};wn_address(uuid,prefix.bytes);
    remote_finish(peer,wb_originate(&peer->remote,milliseconds(),&prefix,0));origin(peer,1);
}
#if defined(WENDY_NET_ROUTE_CRYPTO_HOST_TEST)
#include "wendy_pki_work.h"
#include "router_gate_positive.inc"
#endif
struct missing_observer {bool busy;unsigned sent;struct wncf_request expected;};
static int send_missing_fixture(void *context,const void *wire,size_t size,bool control)
{
    struct missing_observer *o=context;assert(control);
    if(o->busy)return WNC_LIMIT;
    struct wn_doc d;assert(!wn_doc_parse(&d,wire,size));
    int object=wn_doc_member(&d,0,"certificate");assert(object>=0);
    int missing=wn_doc_member(&d,(unsigned)object,"missing");assert(missing>=0);
    struct wncf_request q;assert(!wncf_request_read(&d,(unsigned)missing,&q));
    assert(q.offset==o->expected.offset && !memcmp(q.hash,o->expected.hash,32));o->sent++;return 0;
}
static void missing_reply_fixture(void)
{
    struct wnrs_node empty={0};empty.certificates.opened=true;
    struct missing_observer observation={.busy=true,.expected.offset=1024};memset(observation.expected.hash,77,32);
    struct wnrs supplier={.node=&empty,.link=42,.send=send_missing_fixture,.context=&observation,
        .certificate_reply_pending=true,.certificate_reply=observation.expected};
    assert(serve_part(&supplier)==1 && supplier.certificate_reply_pending && !observation.sent);
    observation.busy=false;
    assert(!serve_part(&supplier) && !supplier.certificate_reply_pending && observation.sent==1);
    assert(!serve_part(&supplier) && observation.sent==1);
}
static int endpoint_hint_reply(void *context,const void *wire,size_t size,bool control)
{
    struct missing_observer *o=context;assert(control);struct wg_message message;uint8_t data[WG_CHUNK];
    assert(!wn_gossip_read(wire,size,&message,data) && message.id.type==1);o->sent++;return 0;
}
static void endpoint_availability_fixture(void)
{
    struct wnrs_node node={0};node.core.config.non_transit=true;node.core.config.endpoint_gateway=true;
    struct wg_config config={.objects=8,.pending=64,.bytes=8192,.identify=wn_gossip_identify};
    assert(!wg_init(&node.pool,&config));
    struct missing_observer observation={0};
    struct wnrs session={.node=&node,.link=1,.send=endpoint_hint_reply,.context=&observation};
    assert(!wg_open(&node.pool,&session.gossip,1));
    for(unsigned origin=1;origin<=100;origin++){
        struct wg_message have={.op=WG_HAVE,.id.type=1};memset(have.id.hash,(uint8_t)origin,32);
        char wire[192];int n=wn_gossip_write(&have,wire,sizeof wire);assert(n>0);
        struct wn_doc d;assert(!wn_doc_parse(&d,wire,(size_t)n));
        assert(!control_parsed(&session,wire,(size_t)n,&d));
        assert(node.pool.pending_count<=64 && !node.core.directory.count);
        assert(!session.fetch.chain);
    }
    assert(node.pool.pending_count==64);wg_close(&session.gossip);wg_deinit(&node.pool);
}
struct directory_observer {bool busy;unsigned sent;const char *kind;const char *principal;};
static int directory_reply(void *context,const void *wire,size_t size,bool control)
{
    struct directory_observer *o=context;assert(control);
    if(o->busy)return WNC_LIMIT;
    struct wn_doc d;assert(!wn_doc_parse(&d,wire,size));
    assert(wn_doc_equal(&d,wn_doc_member(&d,0,"kind"),o->kind));
    assert(wn_doc_equal(&d,wn_doc_member(&d,0,"principal"),o->principal));
    o->sent++;return 0;
}
static void directory_missing_reply_fixture(void)
{
    struct wnrs_node node={0};char principal[106],wire[192];
    assert(wn_principal(tenant,ids[2],principal)>0);
    struct directory_observer first={.busy=true,.kind="identity-missing",.principal=principal};
    struct wnrs a={.node=&node,.link=1,.send=directory_reply,.context=&first};node.sessions=&a;
    strcpy(a.identity.tenant,tenant);strcpy(a.identity.device,ids[0]);
    strcpy(a.descriptor_reply,principal);
    assert(!certificate_tick(&a) && a.descriptor_reply[0] && !first.sent);
    int n=wn_identity_request_write(principal,wire,sizeof wire);assert(n>0);
    assert(wnrs_control(&a,wire,(size_t)n)==1); /* one retained reply backpressures ingress */
    first.busy=false;assert(!certificate_tick(&a) && !a.descriptor_reply[0] && first.sent==1);
    first.kind="manifest-missing";first.busy=true;
    n=wn_manifest_request_write(principal,wire,sizeof wire);assert(n>0);
    assert(wnrs_control(&a,wire,(size_t)n)==1 && first.sent==1);
    first.busy=false;assert(!wnrs_control(&a,wire,(size_t)n) && first.sent==2);
    /* A normal cache miss changes the next direct supplier immediately. */
    struct directory_observer second={.kind="manifest-request",.principal=principal};
    struct wnrs b={.node=&node,.link=2,.send=directory_reply,.context=&second};a.next=&b;
    strcpy(b.identity.tenant,tenant);first.kind="manifest-request";
    node.core.config.endpoint_gateway=true;
    uint8_t device[16];uint16_t port;assert(!wn_uuid_parse(ids[2],device));
    assert(!wnrs_app_endpoint(&a,device,&port) && first.sent==3 && !second.sent);
    n=wn_directory_missing_write(principal,true,wire,sizeof wire);assert(n>0);
    assert(!wnrs_control(&a,wire,(size_t)n) && node.endpoint_request_retry==0);
    assert(!wnrs_app_endpoint(&a,device,&port) && first.sent==3 && second.sent==1);
}
struct repair_observer {struct wnrs *session;struct wg_message want;bool waiting;unsigned delivered;};
static int repair_emit(void *ctx,const struct wg_message *m)
{struct repair_observer *o=ctx;if(m->op==WG_WANT)o->want=*m;return 0;}
static int repair_complete(void *ctx,const struct wg_id *id,const void *data,size_t size)
{
    struct repair_observer *o=ctx;
    if(!o->waiting){o->delivered++;return 0;}
    assert(!retain_manifest(o->session,id,data,size,clock_us));return WG_DEFER;
}
static void identity_repair_expiry_fixture(void)
{
    struct wnrs_node node={0};struct wnrs session={.node=&node,.link=9};node.sessions=&session;
    strcpy(node.clock.tenant,tenant);strcpy(session.identity.tenant,tenant);
    struct wg_config cfg={.identify=wn_gossip_identify,.objects=4,.pending=4,.bytes=4096,.downloads=1};
    assert(!wg_init(&node.pool,&cfg) && !wg_open(&node.pool,&session.gossip,1));
    uint8_t uuid[16],signature[80];char body[768],principal[106],wire[1500];
    assert(!wn_uuid_parse(ids[2],uuid) && wn_principal(tenant,ids[2],principal)>0);
    struct wn_origin origin={.router_id=100,.seqno=1};
    int size=wn_manifest_app_write(uuid,&origin,99,1800000000000LL,1800000060000LL,5054,43022,body,sizeof body);
    size_t signature_size;assert(size>0 && !wendy_pki_mesh_sign(NULL,principal,body,size,signature,&signature_size));
    size=wn_manifest_wire_write(principal,body,(size_t)size,signature,signature_size,wire,sizeof wire);assert(size>0 && size<=WG_CHUNK);
    struct repair_observer observed={.session=&session,.waiting=true};
    struct wg_message message={.op=WG_HAVE,.id.type=1};
    assert(!wn_gossip_identify(NULL,1,wire,(size_t)size,message.id.hash));
    assert(!wg_receive(&session.gossip,&message,1,repair_emit,repair_complete,&observed));
    message.op=WG_DATA;message.request=observed.want.request;message.total=message.size=(size_t)size;message.data=(const uint8_t*)wire;
    assert(!wg_receive(&session.gossip,&message,2,repair_emit,repair_complete,&observed));
    assert(node.pending_count==1 && node.pool.pending_count==1 && node.pool.payload_bytes==(size_t)size);
    int64_t deadline=node.pending->deadline;
    prune_pending(&node,deadline-1);assert(node.pending_count==1 && node.pool.pending_count==1);
    prune_pending(&node,deadline);assert(!node.pending_count && !node.pool.pending_count && !node.pool.payload_bytes);
    /* A fresh supplier may lose its descriptor after delivering the body.
     * Another announcing peer takes the same bounded slot without timeout. */
    struct wnrs other={.node=&node,.link=10};session.next=&other;
    strcpy(other.identity.tenant,tenant);assert(!wg_open(&node.pool,&other.gossip,1));
    struct repair_observer alternate={.session=&other};
    message=(struct wg_message){.op=WG_HAVE,.id=message.id};
    assert(!wg_receive(&session.gossip,&message,3,repair_emit,repair_complete,&observed));
    assert(!wg_receive(&other.gossip,&message,3,repair_emit,repair_complete,&alternate));
    message.op=WG_DATA;message.request=observed.want.request;
    message.total=message.size=(size_t)size;message.data=(const uint8_t*)wire;
    assert(!wg_receive(&session.gossip,&message,4,repair_emit,repair_complete,&observed));
    assert(node.pending_count==1 && node.pool.payload_bytes==(size_t)size);
    struct wncf_chain staged={.count=1};strcpy(staged.principal,principal);memset(staged.hashes[0],7,32);
    assert(!wncf_start(&session.fetch,&staged,4));
    session.fetch.bytes=wendy_net_malloc(4096);assert(session.fetch.bytes);
    session.fetch.total=4096;session.fetch.offset=1024;session.fetch.waiting=true;node.fetch_owner=&session;
    char missing[192];int missing_size=wn_directory_missing_write(principal,false,missing,sizeof missing);assert(missing_size>0);
    assert(!wnrs_control(&session,missing,(size_t)missing_size));
    assert(!node.pending_count && !node.pool.payload_bytes && !session.fetch.chain && !session.fetch.bytes && !node.fetch_owner);
    assert(!wg_poll(&other.gossip,4,repair_emit,&alternate) && alternate.want.op==WG_WANT);
    message.request=alternate.want.request;
    assert(!wg_receive(&other.gossip,&message,5,repair_emit,repair_complete,&alternate));
    assert(alternate.delivered==1 && !node.pool.pending_count);
    wg_close(&other.gossip);session.next=NULL;
    /* A newly available ordinary proof can immediately use the sole slot. */
    observed.waiting=false;message=(struct wg_message){.op=WG_HAVE,.id=message.id};
    assert(!wg_receive(&session.gossip,&message,6,repair_emit,repair_complete,&observed));
    message.op=WG_DATA;message.request=observed.want.request;
    message.total=message.size=(size_t)size;message.data=(const uint8_t*)wire;
    assert(!wg_receive(&session.gossip,&message,7,repair_emit,repair_complete,&observed));
    assert(observed.delivered==1 && !node.pool.pending_count && !node.pool.payload_bytes);
#if WN_ROUTE_ASYNC
    /* A neighbor may normally relay our valid proof from the previous boot.
     * The publisher does not keep a foreign-directory identity for itself. */
    memcpy(node.core.directory.self,uuid,16);
    assert(!complete(&session,&message.id,wire,(size_t)size));
    assert(!node.pending_count && !session.record_verification && !session.record_verdict);
#endif
    wg_close(&session.gossip);wg_deinit(&node.pool);
}
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST) && WN_ROUTE_ASYNC
static void parser_pressure_recovery_fixture(void)
{
    struct wnrs_node node={0};struct wnrs session={.node=&node,.link=9};node.sessions=&session;
    strcpy(node.clock.tenant,tenant);strcpy(session.identity.tenant,tenant);
    uint8_t uuid[16],signature[80];char body[768],principal[106],wire[1500];
    assert(!wn_uuid_parse(ids[2],uuid) && wn_principal(tenant,ids[2],principal)>0);
    memcpy(node.core.directory.self,uuid,16);
    struct wn_origin origin={.router_id=100,.seqno=1};
    int size=wn_manifest_app_write(uuid,&origin,99,1800000000000LL,1800000060000LL,5054,43022,body,sizeof body);
    size_t signature_size;assert(size>0 && !wendy_pki_mesh_sign(NULL,principal,body,size,signature,&signature_size));
    size=wn_manifest_wire_write(principal,body,(size_t)size,signature,signature_size,wire,sizeof wire);assert(size>0);
    struct wg_id id={.type=1};assert(!wn_gossip_identify(NULL,1,wire,(size_t)size,id.hash));
    wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);
    size_t outer=wendy_net_memory_charge(sizeof(struct manifest_workspace));
    assert(memory.limit_bytes-memory.current_bytes>outer);
    wendy_net_memory_reservation_t competing={0};
    assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),&competing,
        memory.limit_bytes-memory.current_bytes-outer,WENDY_NET_MEMORY_INTERNAL));
    /* A concurrent ordinary TLS/chain job leaves room for the outer envelope,
     * but not its service-array validation workspace. No carrier is failed. */
    assert(complete(&session,&id,wire,(size_t)size)==WG_DEFER);
    assert(!node.pending_count && !session.record_verification && !session.record_verdict);
    wendy_net_memory_release(&competing);
    assert(!complete(&session,&id,wire,(size_t)size));
    wendy_net_runtime_memory_snapshot(&memory);
    assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),&competing,
        memory.limit_bytes-memory.current_bytes,WENDY_NET_MEMORY_INTERNAL));
    char missing[192];int n=wn_directory_missing_write(principal,false,missing,sizeof missing);assert(n>0);
    assert(wnrs_control(&session,missing,(size_t)n)==1); /* input retained */
    wendy_net_memory_release(&competing);
    assert(!wnrs_control(&session,missing,(size_t)n)); /* exact same frame retries */
}
#endif
/* A normal full manifest can exceed the old copied-body repair budget.
 * Async repair keeps metadata only while the gossip download owns its bytes. */
static void large_manifest_repair_fixture(void)
{
    struct wnrs_node node={0};struct wnrs session={.node=&node,.link=1};
    strcpy(node.clock.tenant,tenant);strcpy(node.clock.device,ids[0]);
    strcpy(session.identity.tenant,tenant);
    assert(!wnd_init(&node.core.directory,tenant,ids[0]));
    const char remote[]="00000000-0000-4000-8000-000000000099";
    uint8_t device[16],signature[80];char principal[106],base[768];
    assert(!wn_uuid_parse(remote,device) && wn_principal(tenant,remote,principal)==105);
    struct wn_origin origin={.router_id=999,.seqno=1};
    int n=wn_manifest_app_write(device,&origin,1,1800000000000,1800000900000,5054,43022,base,sizeof base);assert(n>0);
    struct wn_doc doc;assert(!wn_doc_parse(&doc,base,(size_t)n));
    char *body=malloc(16384),*wire=malloc(16384),*value=malloc(10241);assert(body && wire && value);
    memset(value,'v',10240);value[10240]=0;
    unsigned fields=0;for(unsigned i=1;i<doc.storage[0].next;i=doc.storage[i+1].next)fields++;
    struct wn_writer writer={.data=(uint8_t*)body,.capacity=16384,.maximum=WN_MANIFEST_BODY_MAX};
    wn_map(&writer,fields+1);wn_text(&writer,"z");wn_text(&writer,value);
    for(unsigned i=1;i<doc.storage[0].next;i=doc.storage[i+1].next)
        wn_raw(&writer,doc.text+doc.storage[i].start,doc.storage[i+1].end-doc.storage[i].start);
    n=wn_finish(&writer);assert(n>8192);size_t signature_size;
    assert(!wendy_pki_mesh_sign(NULL,principal,body,(size_t)n,signature,&signature_size));
    n=wn_manifest_wire_write(principal,body,(size_t)n,signature,signature_size,wire,16384);assert(n>8192);
    struct wg_id id={.type=1};assert(!wn_gossip_identify(NULL,1,wire,(size_t)n,id.hash));
    assert(complete(&session,&id,wire,(size_t)n)==WG_DEFER);
    assert(node.pending_count==1 && node.pending && !node.pending_bytes && !node.pending->size);
    assert(!strcmp(node.pending->principal,principal));
    wendy_net_free(node.pending);wnd_deinit(&node.core.directory);free(body);free(wire);free(value);
}
int main(int argc,char **argv)
{
    assert(argc==2 && !wendy_pki_crypto_init());
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    assert(wendy_net_runtime_memory_open());
#endif
    missing_reply_fixture();
    directory_missing_reply_fixture();
    endpoint_availability_fixture();
    FILE *file=fopen(argv[1],"rb");assert(file);uint8_t der[512];size_t size=fread(der,1,sizeof der,file);fclose(file);
    mbedtls_pk_init(&key);assert(!mbedtls_pk_parse_key(&key,der,size,NULL,0));
    large_manifest_repair_fixture();
    identity_repair_expiry_fixture();
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST) && WN_ROUTE_ASYNC
    parser_pressure_recovery_fixture();
#endif
    uint8_t spki[128];int spki_size=mbedtls_pk_write_pubkey_der(&key,spki,sizeof spki);assert(spki_size>0);
    struct wendy_pki_mesh_identity identity={.verified_seconds=1800000000,
        .verified_monotonic_us=1000000,.certificate_expires=1800003600,
        .config_generation=1};
    strcpy(identity.tenant,tenant);strcpy(identity.device,ids[0]);
    struct wnrs_node *node=NULL;struct endpoint peers[2]={{.index=1,.control_backpressure=1},{.index=2}};
    wendy_pki_connection connections[2]={0};
    for(unsigned i=0;i<2;i++){
        strcpy(connections[i].peer.device,ids[i+1]);connections[i].peer.expires=1800003600;
        connections[i].peer.spki_size=(size_t)spki_size;
        memcpy(connections[i].peer.spki,spki+sizeof spki-spki_size,(size_t)spki_size);
        index_available=i==0; /* A later context miss keeps the current copied index. */
        assert(!wnrs_open(&peers[i].session,&node,&connections[i],&identity,ids[i+1],
                          i ? WNR_BLE_COST:FIRST_LINK_COST,send_frame,&peers[i]));
        if(!i){assert(peers[i].session->own_descriptor_pending);assert(!wnrs_tick(peers[i].session));assert(!peers[i].session->own_descriptor_pending);}
    }
    assert(node->core.directory.count==2);
    const char exact_type[16]={'_','s','e','n','s','o','r','l','i','n','k','.','_','t','c','p'};char empty_browse[8];
    assert(wnrs_service_action(peers[0].session,NULL,0,exact_type,sizeof exact_type,empty_browse,sizeof empty_browse,NULL,NULL)==2);
    assert(!strcmp(empty_browse,"[]"));
    assert(index_snapshots==2 && node->certificates.baseline_index_enabled && node->certificates.baseline_index.count==1);
    assert(node->certificates.baseline_current(node->certificates.baseline_context,&node->certificates.baseline_index));
    assert(wnd_memory(&node->core.directory)==sizeof node->core.directory+
        2*(sizeof(struct wnd_entry)+(size_t)spki_size));
    for(struct wnd_entry *entry=node->core.directory.entries;entry;entry=entry->next){
        const uint8_t *retained=entry->peer.spki;
        struct wendy_pki_mesh_peer refreshed=connections[0].peer;
        if(strcmp(entry->peer.device,refreshed.device))refreshed=connections[1].peer;
        refreshed.expires--;
        assert(!wnd_identity(&node->core.directory,&refreshed));
        assert(entry->peer.spki==retained && entry->peer.expires==refreshed.expires);
    }
    assert(!opens && !commits && peers[0].session->node==peers[1].session->node);
    assert(!node->core.checkpoint && !node->core.checkpoint_capacity);
    assert(wnrs_link_id(peers[0].session)!=wnrs_link_id(peers[1].session));
    remote_open(&peers[0],FIRST_LINK_COST);remote_open(&peers[1],WNR_BLE_COST);drain();
    for(unsigned step=0;step<200;step++){
        clock_us+=100000;
        for(unsigned i=0;i<2;i++){
            remote_finish(&peers[i],wb_tick(&peers[i].remote,milliseconds()));
            assert(!wnrs_tick(peers[i].session));
        }
        drain();
    }
    /* The live actor projection remains bounded, allocation-free and stable
     * across ordinary timer work; structural edits invalidate old cursors. */
    size_t topology_before=wnr_memory(&node->core)+wg_memory(&node->pool);
    WendyComNetTopologyPage page=WendyComNetTopologyPage_init_zero;
    assert(!wnrs_topology(node,0,0,&page));
    assert(page.runtime_available && page.has_record && page.record.kind==1 && page.next_cursor);
    assert(sizeof page<=384);
    uint64_t generation=page.generation;unsigned cursor=page.next_cursor,rows=1;
    unsigned kinds[4]={0};kinds[page.record.kind]++;
    node->core.babel.revision++; /* Maintenance counters are not structural. */
    clock_us+=1000;
    while(cursor){
        page=(WendyComNetTopologyPage)WendyComNetTopologyPage_init_zero;
        assert(!wnrs_topology(node,cursor,generation,&page));
        assert(page.has_record && page.generation==generation && page.record.kind<=3);
        rows++;kinds[page.record.kind]++;cursor=page.next_cursor;assert(rows<1024);
    }
    assert(kinds[1]==2 && kinds[2]>=3 && kinds[3]>=2);
    assert(wnr_memory(&node->core)+wg_memory(&node->pool)==topology_before);
    uint32_t old_metric=node->core.babel.routes[0].metric;
    node->core.babel.routes[0].metric++;
    assert(wnrs_topology(node,1,generation,&page)==1);
    node->core.babel.routes[0].metric=(uint16_t)old_metric;
    assert(!wnrs_topology(node,1,generation,&page));
    bool gateway=node->core.config.endpoint_gateway;node->core.config.endpoint_gateway=true;
    assert(!wnrs_topology(node,0,0,&page) && page.partial);
    node->core.config.endpoint_gateway=gateway;
    node->core.stopped=true;
    assert(!wnrs_topology(node,0,0,&page) && !page.runtime_available && !page.has_record && !page.next_cursor);
    node->core.stopped=false;
    printf("topology pages: records=%u dto=%zu heap_delta=0\n",rows,sizeof page);
    uint8_t uuid[2][16],address[2][16];uint16_t port;
    for(unsigned i=0;i<2;i++){
        assert(!wn_uuid_parse(ids[i+1],uuid[i]));wn_address(uuid[i],address[i]);
        assert(wnrs_agent_endpoint(peers[1-i].session,uuid[i],&port) && port==5054);
    }
    for(unsigned from=0;from<2;from++){
        uint8_t packet[40]={0x60};packet[6]=59;packet[7]=8;
        memcpy(packet+8,address[from],16);memcpy(packet+24,address[1-from],16);
        uint64_t outgoing=0;
        assert(wnrs_packet_route(peers[from].session,packet,sizeof packet,true,&outgoing)==1);
        assert(outgoing==wnrs_link_id(peers[1-from].session) && packet[7]==7);
    }
#if defined(WENDY_NET_ROUTE_CRYPTO_HOST_TEST)
    wendy_pki_work_enable();
    gate_owned_route_test(&peers[1],address[1],address[0],wnrs_link_id(peers[0].session));
#endif
    /* Both admitted endpoints remain usable in terminating-only mode. */
    node->core.config.non_transit=true;
    uint8_t packet[40]={0x60};packet[6]=59;packet[7]=8;
    memcpy(packet+8,address[0],16);memcpy(packet+24,address[1],16);
    uint64_t outgoing=0;
    assert(wnrs_packet_route(peers[0].session,packet,sizeof packet,true,&outgoing)==-1);
    assert(packet[7]==8);
    memcpy(packet+24,node->core.directory.self_address,16);
    assert(!wnrs_packet_route(peers[0].session,packet,sizeof packet,true,&outgoing));
    assert(!outgoing && packet[7]==8);
    memcpy(packet+8,node->core.directory.self_address,16);memcpy(packet+24,address[0],16);
    assert(wnrs_packet_route(peers[0].session,packet,sizeof packet,false,&outgoing)==1);
    assert(outgoing==wnrs_link_id(peers[0].session));
    origin(&peers[0],2);assert(gone_messages==2);
    node->core.config.non_transit=false;
    printf("shared two-carrier transit: core=%zu gossip=%zu journal=%zu writes=%u\n",
        wnr_memory(&node->core),wg_memory(&node->pool),journal_size,commits);
    wnrs_close(peers[0].session);peers[0].session=NULL;assert(node);
    assert(wnrs_agent_endpoint(peers[1].session,uuid[1],&port) && port==5054);drain();
    wnrs_close(peers[1].session);peers[1].session=NULL;assert(!node && !opens && !closes && !commits);drain();
    uint64_t previous_router=fixture_router,previous_revision=fixture_revision;
    assert(!wnrs_open(&peers[0].session,&node,&connections[0],&identity,ids[1],
        FIRST_LINK_COST,send_frame,&peers[0]));
    assert(node->certificates.baseline_index_enabled && !node->certificates.baseline_index.count);
    assert(!node->certificates.baseline_current(node->certificates.baseline_context,&node->certificates.baseline_index));
    assert(node->core.babel.config.router!=previous_router);
    assert(fixture_revision>previous_revision && node->core.directory.count==1);
    assert(!node->core.checkpoint && !node->core.checkpoint_capacity);
    wnrs_close(peers[0].session);peers[0].session=NULL;assert(!node);drain();
    assert(!opens && !closes && !commits && !journal_size && !service_journal_size);
    for(unsigned i=0;i<2;i++)wb_deinit(&peers[i].remote);
    mbedtls_pk_free(&key);
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
#endif
    return 0;
}
