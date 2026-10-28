/* Normal immutable records/inventories with transient competing RAM use. */
#include "wendy_net_alloc.h"
#include "wendy_pki_work.h"
#include "wendy_pki_crypto.h"
#include "../../wendy_pki/src/artifact_crypto.h"
#include <assert.h>
#include <mbedtls/pk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Exercise the actual completion/publication entry points before parsing. */
#include "../src/catalog_node.c"
#include "../src/catalog_freshness.c"

struct wendy_pki_connection {unsigned tag;};
static struct wendy_pki_connection connection={1};
static mbedtls_pk_context signer;
static struct wendy_pki_mesh_key peer;
static uint8_t fingerprint[32];
static const char tenant[]="2558fd76-afc7-466e-9613-6b715296a526";
static const char self[]="00000000-0000-4000-8000-000000000004";
static const char remote[]="00000000-0000-4000-8000-000000000005";
static const int64_t unix_ms=1790000000000;
static char remote_principal[106];
static unsigned signature_jobs,revision_calls;
static uint64_t revisions=100;
int wendy_pki_mesh_sign_digest(wendy_pki_connection *c,const char *principal,const uint8_t digest[32],uint8_t signature[80],size_t *written)
{
    assert(c==&connection && strlen(principal)==105);signature_jobs++;
    return mbedtls_pk_sign(&signer,MBEDTLS_MD_SHA256,digest,32,signature,80,written);
}
size_t wendy_pki_artifact_signature_capacity(wendy_pki_connection *c)
{assert(c==&connection);return pki_artifact_signature_capacity(&signer);}
int wendy_pki_artifact_sign(wendy_pki_connection *c,unsigned kind,const char *principal,
    const void *body,size_t size,uint8_t *signature,size_t capacity,size_t *written)
{assert(c==&connection);signature_jobs++;return pki_artifact_sign(&signer,kind,principal,body,size,signature,capacity,written);}
int wendy_pki_mesh_fingerprint(wendy_pki_connection *c,uint8_t out[32])
{assert(c==&connection);memcpy(out,fingerprint,32);return 0;}
static int t_send(void *context,uint64_t id,const void *bytes,size_t size)
{(void)context;assert(id && bytes && size);return 1;}
static int t_fingerprint(void *context,uint8_t out[32])
{(void)context;memcpy(out,fingerprint,32);return 0;}
static int64_t t_expires(void *context){(void)context;return unix_ms+3600000;}
static int t_revision(void *context,uint64_t *out)
{(void)context;revision_calls++;*out=++revisions;return 0;}
static int t_describe(void *context,const char *principal,char *out,size_t capacity)
{
    (void)context;struct wncf_chain description={.count=1};strcpy(description.principal,principal);
    memcpy(description.hashes[0],fingerprint,32);return wncf_descriptor_write(&description,out,capacity);
}
static uint64_t t_next_hop(void *context,const uint8_t device[16],uint64_t exclude)
{(void)context;(void)device;(void)exclude;return 2;}
static bool t_take_verify(void **future,struct wncrypto_verdict *completed)
{return wncrypto_take_verification((struct wncrypto_job **)future,completed);}
static bool t_take_sign(void **future,struct wncrypto_signature *completed)
{return wncrypto_take_signature((struct wncrypto_job **)future,completed);}
static void t_cancel(void **future){wncrypto_cancel((struct wncrypto_job **)future);}
static int t_sign(void *context,bool inventory,const void *body,size_t size,const uint8_t **signature,size_t *written,void **future,struct wncrypto_signature *completed)
{
    struct wnsc_node *node=context;
    return wncrypto_sign_cached((struct wncrypto_job **)future,completed,inventory ? 2:1,&connection,node->principal,body,size,signature,written);
}
static int t_verify(void *context,const struct wns_record *record,void **future,struct wncrypto_verdict *completed)
{
    (void)context;assert(!strcmp(record->principal,remote_principal) && record->expires<=(int64_t)peer.expires*1000);
    assert(!memcmp(record->fingerprint,fingerprint,32));
    return wncrypto_verify_cached((struct wncrypto_job **)future,completed,1,&peer,record->principal,record->body,record->body_size,record->signature,record->signature_size);
}
static int t_inventory(void *context,uint64_t supplier,const struct wns_fresh_request *query,const struct wns_inventory *view,void **future,struct wncrypto_verdict *completed)
{
    (void)context;assert(supplier==2 && !strcmp(query->origin,remote_principal) && view->expires<=(int64_t)peer.expires*1000);
    return wncrypto_verify_cached((struct wncrypto_job **)future,completed,2,&peer,query->origin,view->body,view->body_size,view->signature,view->signature_size);
}
static void pressure(wendy_net_memory_reservation_t *token,size_t headroom)
{
    wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);assert(memory.limit_bytes>memory.current_bytes+headroom);
    assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),token,
        memory.limit_bytes-memory.current_bytes-headroom,WENDY_NET_MEMORY_INTERNAL));
}
static void record_metadata(struct wns_record *record,const char *service)
{
    *record=(struct wns_record){.port=28080,.issued=unix_ms,.expires=unix_ms+900000,.generation=1};
    strcpy(record->mesh,"default");strcpy(record->app,"com.example.sensor");strcpy(record->service,service);
    strcpy(record->type,"_sensorlink._tcp");strcpy(record->instance,"Normal RAM overlap");
}
static size_t signed_remote(char wire[12288],struct wnsc_node *node)
{
    struct wns_record record;record_metadata(&record,"remote");record.txt_count=5;strcpy(record.principal,remote_principal);assert(!wn_uuid_parse(remote,record.device));
    char txt[5][201];const char *values[6]={0};
    for(unsigned i=0;i<5;i++){memset(txt[i],'a'+i,200);txt[i][200]=0;values[i]=txt[i];}
    char body[8192];int n=wns_record_body_write(&record,values,body,sizeof body);assert(n>1000);
    size_t capacity=pki_artifact_signature_capacity(&signer),written=0;uint8_t *signature=malloc(capacity);assert(signature);
    assert(!pki_artifact_sign(&signer,1,remote_principal,body,(size_t)n,signature,capacity,&written));
    n=wns_record_wire_write(body,(size_t)n,fingerprint,signature,written,wire,12288);free(signature);assert(n>0);(void)node;return (size_t)n;
}
static void service_pressure(struct wnsc_node *node,struct wnsc_link *link)
{
    char wire[12288];size_t size=signed_remote(wire,node);struct wg_id id={.type=2};assert(!wn_gossip_identify(NULL,2,wire,size,id.hash));
    assert(complete(link,&id,wire,size)==WG_DEFER && link->record_crypto && wnsc_receive_paused(link));
    assert(wendy_pki_work_poll());wendy_net_memory_reservation_t token={0};pressure(&token,sizeof(struct wns_record)-64);
    assert(complete(link,&id,wire,size)==WG_DEFER);
    assert(!link->record_crypto && link->record_completed.valid && !wnsc_receive_paused(link) && !wendy_pki_handshake_busy());
    wendy_net_memory_release(&token);assert(!complete(link,&id,wire,size));
    assert(!link->record_completed.valid && !link->record_crypto && !wendy_pki_work_poll());
    uint8_t device[16];assert(!wn_uuid_parse(remote,device));assert(wns_store_find(&node->records,device,"com.example.sensor","remote"));
}
static void publication_pressure(struct wnsc_node *node)
{
    struct wns_record record;record_metadata(&record,"own");record.generation=0;unsigned before=signature_jobs,revision_before=revision_calls;
    assert(wnsc_publish(node,&record,NULL,unix_ms,1000)==1 && node->publication && node->publication->crypto);
    assert(wendy_pki_work_poll());wendy_net_memory_reservation_t token={0};pressure(&token,32);
    int retried=wnsc_publish(node,&record,NULL,unix_ms,1000);
    assert(retried==1);
    assert(node->publication && !node->publication->crypto && node->publication->completed.valid && !wendy_pki_handshake_busy());
    wendy_net_memory_release(&token);assert(!wnsc_publish(node,&record,NULL,unix_ms,1000));
    assert(!node->publication && signature_jobs==before+1 && revision_calls==revision_before+1 && !wendy_pki_work_poll());
}
static void inventory_sign_pressure(struct wnsc_node *node,struct wnsc_link *link)
{
    struct wns_fresh_request query={.hops=32};strcpy(query.origin,node->principal);strcpy(query.requester,remote_principal);memset(query.nonce,'a',64);
    struct wnsc_request *q=allocate_request(node,&query,1000);assert(q);q->upstream=link->id;unsigned before=signature_jobs;
    assert(respond(link,q)==1 && q->sign_crypto);assert(wendy_pki_work_poll());
    wendy_net_memory_reservation_t token={0};pressure(&token,32);assert(respond(link,q)==1);
    assert(!q->sign_crypto && q->completed.signature.valid && !wendy_pki_handshake_busy());
    wendy_net_memory_release(&token);assert(!respond(link,q) && q->response && q->data);
    assert(signature_jobs==before+1 && !wendy_pki_work_poll());remove_request(node,q);
}
static void inventory_verify_pressure(struct wnsc_node *node,struct wnsc_link *link)
{
    struct wns_fresh_request query={.hops=32};strcpy(query.origin,remote_principal);strcpy(query.requester,node->principal);memset(query.nonce,'b',64);
    char body[4096],description[1400],wire[8192];int n=wns_inventory_body_write(&node->records,"default",remote_principal,&query,unix_ms,unix_ms+30000,body,sizeof body);assert(n>0);
    size_t capacity=pki_artifact_signature_capacity(&signer),written=0;uint8_t *signature=malloc(capacity);assert(signature);
    assert(!pki_artifact_sign(&signer,2,remote_principal,body,(size_t)n,signature,capacity,&written));
    int described=t_describe(node,remote_principal,description,sizeof description);assert(described>0);
    n=wns_inventory_wire_write(body,(size_t)n,signature,written,description,(size_t)described,wire,sizeof wire);free(signature);assert(n>0);
    struct wnsc_request *q=allocate_request(node,&query,1000);assert(q);q->downstream=link->id;
    q->data=wendy_net_malloc((size_t)n);assert(q->data);memcpy(q->data,wire,(size_t)n);q->size=(size_t)n;
    assert(finish(link,q)==1 && q->verify_crypto);assert(wendy_pki_work_poll());
    wendy_net_memory_reservation_t token={0};pressure(&token,sizeof(struct wns_inventory)-64);
    assert(finish(link,q)==1 && !q->verify_crypto && q->completed.verdict.valid && !wendy_pki_handshake_busy());
    wendy_net_memory_release(&token);assert(!finish(link,q) && !wendy_pki_work_poll());remove_request(node,q);
}
int main(int argc,char **argv)
{
    assert(argc==2 && !wendy_pki_crypto_init() && wendy_net_runtime_memory_open());
    FILE *f=fopen(argv[1],"rb");assert(f);uint8_t der[512];size_t size=fread(der,1,sizeof der,f);fclose(f);
    mbedtls_pk_init(&signer);assert(!mbedtls_pk_parse_key(&signer,der,size,NULL,0));uint8_t spki[2048];int n=mbedtls_pk_write_pubkey_der(&signer,spki,sizeof spki);assert(n>0);
    peer=(struct wendy_pki_mesh_key){.spki=spki+sizeof spki-n,.spki_size=(size_t)n,.expires=(time_t)(unix_ms/1000+3600)};strcpy(peer.device,remote);
    assert(wn_principal(tenant,remote,remote_principal)>0 && !wendy_pki_sha256(peer.spki,peer.spki_size,fingerprint));
    struct wg_pool pool;struct wg_config gossip={.identify=wn_gossip_identify,.objects=16,.pending=8,.bytes=65536};assert(!wg_init(&pool,&gossip));
    struct wnsc_config config={.tenant=tenant,.device=self,.send=t_send,.sign_async=t_sign,.verify_async=t_verify,.verify_inventory_async=t_inventory,
        .take_verification=t_take_verify,.take_signature=t_take_sign,.cancel_crypto=t_cancel,.fingerprint=t_fingerprint,.expires=t_expires,
        .describe=t_describe,.next_hop=t_next_hop,.next_revision=t_revision};
    struct wnsc_node *node;assert(!wnsc_open(&node,&config,&pool,NULL,0));node->config.context=node;
    struct wnsc_link *link;assert(!wnsc_link_open(node,&link,2));link->wall=unix_ms;link->now=1000;link->inventory_done=true;
    wendy_pki_work_enable();service_pressure(node,link);publication_pressure(node);inventory_sign_pressure(node,link);inventory_verify_pressure(node,link);
    /* OFF can retire a protocol owner while its independent verification copy
     * is queued. The worker then finishes without consulting that owner. */
    char wire[12288];size_t wire_size=signed_remote(wire,node);struct wg_id id={.type=2};
    assert(!wn_gossip_identify(NULL,2,wire,wire_size,id.hash));
    assert(complete(link,&id,wire,wire_size)==WG_DEFER && link->record_crypto);
    wnsc_close(node);assert(wendy_pki_work_poll() && !wendy_pki_handshake_busy());
    /* Own signing instead keeps its connection loan until the queued CPU call
     * acknowledges cancellation; draining that loan leaves no OFF state. */
    assert(!wnsc_open(&node,&config,&pool,NULL,0));node->config.context=node;
    struct wns_record cancelled;record_metadata(&cancelled,"cancelled");cancelled.generation=0;
    assert(wnsc_publish(node,&cancelled,NULL,unix_ms,2000)==1 && wncrypto_borrowed(&connection));
    wnsc_close(node);assert(wncrypto_borrowed(&connection));
    assert(wendy_pki_work_poll() && !wncrypto_borrowed(&connection) && !wendy_pki_handshake_busy());
    wg_deinit(&pool);mbedtls_pk_free(&signer);wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
    puts("Normal catalogue/inventory verification and signing survive competing RAM; completed jobs/gates drain before parsers and publication retries do not re-sign");return 0;
}
