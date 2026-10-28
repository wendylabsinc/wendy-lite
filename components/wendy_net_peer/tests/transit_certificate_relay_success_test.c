/* Actual bounded certificate store/control relay between two admitted fixture
 * neighbors. TLS admission/scheduling is isolated by the shared router harness;
 * relayed DER paths and router signatures use the real PKI verification code. */
#define WENDY_NET_REAL_CERT_RELAY_TEST 1
#define main existing_shared_router_main
#include "router_node_success_test.c"
#undef main
#include <mbedtls/x509_crt.h>
#include <time.h>
static const time_t fixture_now=1792424833;
time_t time(time_t *out){if(out)*out=fixture_now;return fixture_now;}
static uint8_t *root_der;static size_t root_size;
static unsigned verified_chains;
int wncv_start(struct wncv_job **out,struct wncs_store *store,
    const struct wncf_chain *chain,const struct wendy_pki_mesh_identity *clock)
{
    assert(!*out);struct wncv_job *job=wendy_net_calloc(1,sizeof *job);if(!job)return 1;
    job->clock=*clock;job->chain=*chain;
    if(wncs_pin_chain(store,chain,&job->loan)){wendy_net_free(job);return 1;}
    job->result=wendy_pki_mesh_chain(job->loan.parts,job->loan.sizes,job->loan.count,
        root_der,root_size,clock->tenant,fixture_now,&job->peer);
    atomic_init(&job->done,true);*out=job;verified_chains++;return 0;
}
void wncv_release(struct wncv_job *job)
{if(job){wncs_unpin(&job->loan);wendy_net_free(job);}}
struct relay_endpoint {char wire[WN_CONTROL_MAX+1];size_t size;bool blocked;};
static int relay_send(void *context,const void *bytes,size_t size,bool control)
{
    struct relay_endpoint *end=context;if(!control)return 0;
    if(end->blocked)return 1;assert(size<=sizeof end->wire);
    memcpy(end->wire,bytes,size);end->size=size;return 0;
}
static uint8_t *fixture_file(const char *directory,const char *name,size_t *size)
{
    char path[4096];snprintf(path,sizeof path,"%s/%s",directory,name);FILE *f=fopen(path,"rb");assert(f);
    assert(!fseek(f,0,SEEK_END));long length=ftell(f);assert(length>0);rewind(f);
    uint8_t *p=calloc(1,(size_t)length+1);assert(p && fread(p,1,(size_t)length,f)==(size_t)length);
    fclose(f);*size=(size_t)length;return p;
}
static void parse_wire(const struct relay_endpoint *end,struct wn_doc *d)
{assert(!wn_doc_parse_bounded(d,end->wire,end->size,WN_CONTROL_MAX));}
static void feed_supplier(struct wnrs *session,struct relay_endpoint *end,
    const struct wncf_chain *chain,const uint8_t *const *parts,const size_t *sizes)
{
    for(unsigned attempts=0;session->fetch.chain || session->node->verification;attempts++){
        assert(attempts<32);end->size=0;assert(!certificate_tick(session));
        if(!session->fetch.waiting || !session->fetch.chain)continue;
        struct wn_doc d;parse_wire(end,&d);struct wncf_request q;
        int at=wn_doc_member(&d,0,"certificate");assert(at>=0);
        assert(!wncf_request_read(&d,(unsigned)wn_doc_member(&d,(unsigned)at,"request"),&q));
        unsigned part=0;while(part<chain->count && memcmp(q.hash,chain->hashes[part],32))part++;
        assert(part<chain->count && q.offset<sizes[part]);size_t n=sizes[part]-q.offset;if(n>WNCF_CHUNK)n=WNCF_CHUNK;
        struct wncf_chunk chunk={.offset=q.offset,.total=sizes[part],.size=n};memcpy(chunk.hash,q.hash,32);
        char wire[WN_CONTROL_MAX+1];int count=wncf_chunk_write(&chunk,parts[part]+q.offset,wire,sizeof wire);assert(count>0);
        assert(!wnrs_control(session,wire,(size_t)count));
    }
}
static void relay_chain(struct wnrs *supplier,struct wnrs *receiver,struct relay_endpoint *output,
    const struct wncf_chain *chain)
{
    assert(!send_descriptor(receiver,chain->principal));struct wn_doc d;parse_wire(output,&d);
    int cert=wn_doc_member(&d,0,"certificate");struct wncf_chain received;
    assert(!wncf_chain_read(&d,(unsigned)wn_doc_member(&d,(unsigned)cert,"chain"),tenant,&received));
    assert(received.count==chain->count && !memcmp(received.hashes,chain->hashes,chain->count*32));
    struct wncs_store downstream;assert(!wncs_open_limits(&downstream,32768,8,4));
    struct wncf_fetch fetch={0};assert(!wncf_start(&fetch,&received,clock_us/1000));
    struct wncf_store store={.context=&downstream,.read=wncs_read,.put=wncs_put,.retain=wncs_retain,.release=wncs_release};
    for(unsigned tries=0;;tries++){
        assert(tries<32);struct wncf_request q;int next=wncf_next(&fetch,&store,clock_us/1000,&q);assert(next>0);
        if(next==2)break;
        char wire[192];int n=wncf_request_write(&q,wire,sizeof wire);assert(n>0);
        assert(!wnrs_control(receiver,wire,(size_t)n));assert(wnrs_receive_paused(receiver));
        wncf_sent(&fetch,clock_us/1000);assert(!certificate_tick(receiver));assert(!wnrs_receive_paused(receiver));
        parse_wire(output,&d);cert=wn_doc_member(&d,0,"certificate");struct wncf_chunk chunk;uint8_t bytes[1024];
        assert(!wncf_chunk_read(&d,(unsigned)wn_doc_member(&d,(unsigned)cert,"chunk"),&chunk,bytes));
        assert(!wncf_receive(&fetch,&store,chunk.hash,chunk.offset,chunk.total,bytes,chunk.size,clock_us/1000));
    }
    struct wncs_loan loan={0};assert(!wncs_pin_chain(&downstream,&received,&loan));struct wendy_pki_mesh_peer verified={0};
    assert(!wendy_pki_mesh_chain(loan.parts,loan.sizes,loan.count,root_der,root_size,tenant,fixture_now,&verified));
    assert(!strcmp(verified.device,supplier->connection->peer.device));wncs_unpin(&loan);wncf_stop(&fetch);wncs_close(&downstream);
}
static void cache_route(struct wnrs *session)
{
    uint8_t uuid[16],signature[80];char body[768],wire[1500],principal[106];
    assert(!wn_uuid_parse(session->connection->peer.device,uuid));struct wn_origin origin={.router_id=777,.seqno=1};
    int64_t wall=node_unix(session->node);int n=wn_manifest_app_write(uuid,&origin,2,wall,wall+60000,5054,43022,body,sizeof body);assert(n>0);
    assert(wn_principal(tenant,session->connection->peer.device,principal)>0);size_t sig_size=0;
    assert(!wendy_pki_mesh_sign(NULL,principal,body,(size_t)n,signature,&sig_size));
    n=wn_manifest_wire_write(principal,body,(size_t)n,signature,sig_size,wire,sizeof wire);assert(n>0);
    struct wg_id id={.type=1};assert(!wn_gossip_identify(NULL,1,wire,(size_t)n,id.hash));
    assert(complete(session,&id,wire,(size_t)n)==WG_DEFER);assert(wendy_pki_work_poll());
    assert(!complete(session,&id,wire,(size_t)n));struct wnd_entry *entry=session->node->core.directory.entries;
    while(entry && memcmp(entry->device,uuid,16))entry=entry->next;assert(entry && entry->gossip_cached && !entry->gossip_retired);
}
static void pressure_uploads(struct wnrs *receiver)
{
    struct wnrs_node *node=receiver->node;uint8_t body[4096],hash[32],out[1024];size_t total;
    for(size_t i=0;i<sizeof body;i++)body[i]=(uint8_t)(i*13+5);
    assert(!wendy_pki_sha256(body,sizeof body,hash) && !wncs_put(&node->certificates,hash,body,sizeof body));
    assert(read_public_part(node,receiver->link,PUBLIC_ROUTER,hash,0,out,&total)==1024);
    assert(total==sizeof body && !memcmp(out,body,1024));release_public_part(node,receiver->link,PUBLIC_ROUTER,hash,0);
    assert(node->uploads); /* Whole part remains pinned after first chunk. */
    for(unsigned i=0;i<12;i++){
        uint8_t fresh[4096],digest[32];memset(fresh,(int)i,sizeof fresh);assert(!wendy_pki_sha256(fresh,sizeof fresh,digest));
        assert(!wncs_put(&node->certificates,digest,fresh,sizeof fresh));
        assert(node->certificates.bytes<=32768 && node->certificates.count<=8 && node->certificates.chains<=4);
    }
    for(size_t offset=1024;offset<sizeof body;offset+=1024){
        assert(read_public_part(node,receiver->link,PUBLIC_ROUTER,hash,offset,out,&total)==1024);
        assert(!memcmp(out,body+offset,1024));
        if(offset==3072){
            /* Actual native reply queue pressure must retain the final-chunk
             * loan until queue admission, not merely until the stack read. */
            struct relay_endpoint *end=receiver->context;end->blocked=true;
            struct wncf_request request={.offset=offset};memcpy(request.hash,hash,32);
            char wire[192];int n=wncf_request_write(&request,wire,sizeof wire);assert(n>0);
            assert(!wnrs_control(receiver,wire,(size_t)n));assert(!certificate_tick(receiver));
            assert(receiver->certificate_reply_pending && wnrs_receive_paused(receiver) && node->uploads);
            uint8_t pressure[4096],pressure_hash[32];memset(pressure,77,sizeof pressure);
            assert(!wendy_pki_sha256(pressure,sizeof pressure,pressure_hash));assert(!wncs_put(&node->certificates,pressure_hash,pressure,sizeof pressure));
            end->blocked=false;assert(!certificate_tick(receiver));assert(!receiver->certificate_reply_pending && !node->uploads);
            struct wn_doc d;parse_wire(end,&d);int at=wn_doc_member(&d,0,"certificate");struct wncf_chunk chunk;uint8_t last[1024];
            assert(!wncf_chunk_read(&d,(unsigned)wn_doc_member(&d,(unsigned)at,"chunk"),&chunk,last));
            assert(chunk.offset==offset && chunk.total==sizeof body && !memcmp(last,body+offset,1024));
        }else release_public_part(node,receiver->link,PUBLIC_ROUTER,hash,offset);
    }
    assert(!node->uploads);
    uint8_t fresh[4096],digest[32];memset(fresh,44,sizeof fresh);assert(!wendy_pki_sha256(fresh,sizeof fresh,digest));
    assert(!wncs_put(&node->certificates,digest,fresh,sizeof fresh));assert(!wncs_read_resident(&node->certificates,hash,0,NULL,&total));
    /* Different control domains retain independent whole-part loans. */
    for(unsigned domain=0;domain<3;domain++)assert(read_public_part(node,receiver->link,(enum public_part_domain)domain,digest,0,out,&total)==1024);
    unsigned count=0;for(struct certificate_upload *u=node->uploads;u;u=u->next)count++;assert(count==3);
    prune_uploads(node,clock_us+INT64_C(60000001));assert(!node->uploads);
    assert(read_public_part(node,receiver->link,PUBLIC_ROUTER,digest,0,out,&total)==1024);
}
int main(int argc,char **argv)
{
    assert(argc==2 && !wendy_pki_crypto_init() && wendy_net_runtime_memory_open());
    wendy_pki_work_enable();
    size_t size;uint8_t *der=fixture_file(argv[1],"device-key.der",&size);mbedtls_pk_init(&key);assert(!mbedtls_pk_parse_key(&key,der,size,NULL,0));free(der);
    mbedtls_x509_crt certificates,roots;mbedtls_x509_crt_init(&certificates);mbedtls_x509_crt_init(&roots);
    uint8_t *pem=fixture_file(argv[1],"identity.pem",&size);assert(!mbedtls_x509_crt_parse(&certificates,pem,size+1));free(pem);
    pem=fixture_file(argv[1],"root.pem",&size);assert(!mbedtls_x509_crt_parse(&roots,pem,size+1));free(pem);
    root_size=roots.raw.len;root_der=malloc(root_size);assert(root_der);memcpy(root_der,roots.raw.p,root_size);
    const uint8_t *parts[2]={certificates.raw.p,root_der};size_t sizes[2]={certificates.raw.len,root_size};struct wendy_pki_mesh_peer real={0};
    assert(!wendy_pki_mesh_chain(parts,sizes,2,root_der,root_size,tenant,fixture_now,&real));assert(!strcmp(real.device,ids[0]));
    struct wendy_pki_mesh_identity identity={.verified_seconds=(uint64_t)fixture_now,.verified_monotonic_us=1000000,.certificate_expires=(uint64_t)fixture_now+3600,.config_generation=1};
    strcpy(identity.tenant,tenant);strcpy(identity.device,ids[2]);struct wnrs_node *node=NULL;
    wendy_pki_connection connections[2]={{.peer=real},{.peer=real}};strcpy(connections[1].peer.device,ids[1]);
    struct relay_endpoint ends[2]={0};struct wnrs *sessions[2]={0};
    unsigned links=WENDY_NET_NON_TRANSIT ? 1:2;
    for(unsigned i=0;i<links;i++)assert(!wnrs_open(&sessions[i],&node,&connections[i],&identity,connections[i].peer.device,WNR_BLE_COST,relay_send,&ends[i]));
    assert(node->core.config.non_transit==!!WENDY_NET_NON_TRANSIT);
    assert(node->certificates.limit==32768 && node->certificates.part_limit==8 && node->certificates.chain_limit==4);
    assert(node->core.directory.key_limit==8 && node->pool.config.pending==8);
    struct wncf_chain chain={.count=2};assert(wn_principal(tenant,real.device,chain.principal)>0);
    for(unsigned i=0;i<2;i++)assert(!wendy_pki_sha256(parts[i],sizes[i],chain.hashes[i]));
    char wire[1400];int n=wncf_chain_write(&chain,wire,sizeof wire);assert(n>0);
    if(node->core.config.non_transit){
        /* The one-link terminating tier retains its already verified key and
         * deliberately avoids keeping relay DER after normal verification. */
        assert(!wnrs_control(sessions[0],wire,(size_t)n) && !sessions[0]->fetch.chain);
        for(unsigned i=0;i<2;i++)assert(!wncs_put(&node->certificates,chain.hashes[i],parts[i],sizes[i]));
        assert(!wncs_chain_put(&node->certificates,&chain,(int64_t)real.expires));
        trim_certificates(node);assert(!node->certificates.count && !node->certificates.chains);
        assert(node->core.directory.key_count==1);wnrs_close(sessions[0]);assert(!node);goto cleanup;
    }
    /* A TLS-admitted neighbor's SPKI exists, but transit still fetches its
     * first full public path so another neighbor can independently verify it. */
    assert(!wnrs_control(sessions[0],wire,(size_t)n) && sessions[0]->fetch.chain);
    feed_supplier(sessions[0],&ends[0],&chain,parts,sizes);assert(verified_chains==1 && node->certificates.count==2);
    struct wncf_chain stored;assert(wncs_chain_get(&node->certificates,chain.principal,fixture_now,&stored)==1);
    trim_certificates(node);assert(node->certificates.count==2);
    relay_chain(sessions[0],sessions[1],&ends[1],&chain);cache_route(sessions[0]);
    pressure_uploads(sessions[1]);assert(node->uploads);
    /* Forgotten verified paths are not refilled merely by another hint. */
    assert(!wnrs_control(sessions[0],wire,(size_t)n) && !sessions[0]->fetch.chain);
    wnrs_close(sessions[1]);assert(node && !node->uploads);wnrs_close(sessions[0]);assert(!node);
 cleanup:
    mbedtls_x509_crt_free(&certificates);mbedtls_x509_crt_free(&roots);mbedtls_pk_free(&key);free(root_der);
    wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
    puts("Two-neighbor constrained transit relays verified DER and signed route bodies, pins complete uploads under FIFO pressure and drains on OFF");return 0;
}
