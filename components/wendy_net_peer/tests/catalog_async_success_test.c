/* Positive ordinary catalogue traffic with deliberately delayed crypto jobs. */
#define main synchronous_fixture_main
#include "catalog_node_success_test.c"
#undef main
struct delayed {size_t size;char body[];};
static unsigned delayed_signatures,delayed_verifications,publication_signatures,revision_calls;
static uint64_t shared_revision=500000;
static bool revision_busy=true;
static int next_revision(void *context,uint64_t *out)
{(void)context;if(revision_busy){revision_busy=false;return 1;}
 revision_calls++;*out=++shared_revision;return 0;}
static bool request_artifact(void *context,const struct wg_id *id,uint64_t now)
{
    struct node *node=context;
    return id->type!=2 || wnsc_wants_remote(node->catalog,now);
}
static int delayed_sign(void *context,bool inventory,const void *body,size_t size,const uint8_t **signature,size_t *written,void **token,struct wncrypto_signature *completed)
{
    if(completed->valid){*signature=completed->signature;*written=completed->signature_size;return completed->result;}
    if(!*token){
        struct delayed *p=malloc(sizeof *p+size);assert(p);
        p->size=size;memcpy(p->body,body,size);*token=p;delayed_signatures++;
        if(!inventory)publication_signatures++;
        return 1;
    }
    struct delayed *p=*token;assert(p->size==size && !memcmp(p->body,body,size));
    completed->signature=wendy_net_malloc(80);assert(completed->signature);
    int r=sign(context,inventory,body,size,completed->signature,written);free(p);*token=NULL;
    completed->valid=true;completed->result=r;completed->signature_size=*written;
    *signature=completed->signature;return r;
}
static int delayed_verify(void *context,const struct wns_record *r,void **token,struct wncrypto_verdict *completed)
{
    (void)completed;
    if(!*token){*token=malloc(1);assert(*token);delayed_verifications++;return 1;}
    free(*token);*token=NULL;return verify(context,r);
}
static int delayed_inventory(void *context,uint64_t supplier,const struct wns_fresh_request *q,const struct wns_inventory *view,void **token,struct wncrypto_verdict *completed)
{
    (void)completed;
    if(!*token){*token=malloc(1);assert(*token);delayed_verifications++;return 1;}
    free(*token);*token=NULL;return verify_inventory(context,supplier,q,view);
}
static void cancel(void **token){free(*token);*token=NULL;}
int main(int argc,char **argv)
{
    assert(argc==2 && !wendy_pki_crypto_init());
    FILE *f=fopen(argv[1],"rb");assert(f);uint8_t der[512];size_t size=fread(der,1,sizeof der,f);fclose(f);
    mbedtls_pk_init(&signer);assert(!mbedtls_pk_parse_key(&signer,der,size,NULL,0));
    uint8_t spki[128];int count=mbedtls_pk_write_pubkey_der(&signer,spki,sizeof spki);assert(count>0);
    key.spki_size=(size_t)count;memcpy(key.spki,spki+sizeof spki-count,(size_t)count);
    assert(!wendy_pki_sha256(key.spki,key.spki_size,fingerprint));
    track_downloads=false;
    for(unsigned i=0;i<3;i++){
        open_node(i);struct wnsc_config *c=&nodes[i].catalog->config;
        c->persist=NULL;c->next_revision=next_revision;c->demand_only=i==0;
        nodes[i].pool.config.context=&nodes[i];
        nodes[i].pool.config.want_object=request_artifact;
        c->sign_async=delayed_sign;c->verify_async=delayed_verify;
        c->verify_inventory_async=delayed_inventory;c->cancel_crypto=cancel;
        nodes[i].pool.config.downloads=1;
    }
    connect(0,1);connect(1,2);
    for(unsigned i=0;i<3;i++){
        struct wns_record r={.port=28080,.issued=wall(),.expires=wall()+900000};
        strcpy(r.app,"com.example.sensor");strcpy(r.service,"temperature");
        strcpy(r.type,"_sensorlink._tcp");strcpy(r.instance,"sensor");
        int result=1;
        for(unsigned step=0;result>0 && step<100;step++){
            /* New wall times on retries must not change the signed draft. */
            r.issued=wall();r.expires=wall()+900000;
            result=wnsc_publish(nodes[i].catalog,&r,NULL,wall(),clock_ms);
            drive(1);
        }
        assert(!result);
    }
    drive(100);
    assert(nodes[0].catalog->records.count==1); /* Own record only, no browser. */
    assert(nodes[0].pool.pending_count && !wnsc_wants_remote(nodes[0].catalog,clock_ms));
    wnsc_browse_demand(nodes[0].catalog,clock_ms);
    assert(wnsc_wants_remote(nodes[0].catalog,clock_ms));
    /* Agent and guest renewals can interleave while signing is
     * deferred. Each must consume its own completion exactly once. */
    struct wns_record publications[2]={
        {.port=5054,.issued=wall(),.expires=wall()+900000},
        {.port=28080,.issued=wall(),.expires=wall()+900000}
    };
    strcpy(publications[0].app,"sh.wendy.lite.agent");strcpy(publications[0].service,"agent");
    strcpy(publications[1].app,"sh.wendy.lite.app");strcpy(publications[1].service,"echo");
    for(unsigned i=0;i<2;i++){strcpy(publications[i].type,"_sensorlink._tcp");strcpy(publications[i].instance,"local");}
    bool acknowledged[2]={false,false};unsigned before=publication_signatures;
    for(unsigned step=0;(!acknowledged[0] || !acknowledged[1]) && step<100;step++){
        for(unsigned i=0;i<2;i++)if(!acknowledged[i]){
            publications[i].issued=wall();publications[i].expires=wall()+900000;
            int r=wnsc_publish(nodes[0].catalog,&publications[i],NULL,wall(),clock_ms);
            assert(r>=0);acknowledged[i]=!r;
        }
        drive(1);
    }
    assert(acknowledged[0] && acknowledged[1]);
    assert(publication_signatures-before==2);
    drive(1500);
    assert(!wnsc_wants_remote(nodes[0].catalog,clock_ms));
    for(unsigned i=0;i<3;i++){
        browse(i,5);assert(!nodes[i].pool.pending_count);
    }
    assert(delayed_signatures>=3 && delayed_verifications>=6);
    assert(revision_calls==publication_signatures);
    for(unsigned i=0;i<3;i++)assert(!nodes[i].journal_size);
    printf("Delayed crypto catalogue: signs=%u verifies=%u, retained download slots drained\n",delayed_signatures,delayed_verifications);
    struct wns_entry *old_self=wns_store_find(&nodes[0].catalog->records,nodes[0].catalog->self,
        publications[0].app,publications[0].service);
    assert(old_self && old_self->wire);
    size_t echo_size=old_self->wire_size;char *echo=malloc(echo_size);assert(echo);
    memcpy(echo,old_self->wire,echo_size);
    for(unsigned i=0;i<3;i++){wnsc_close(nodes[i].catalog);wg_deinit(&nodes[i].pool);free(nodes[i].journal);}
    memset(nodes,0,sizeof nodes);
    /* Closing the mesh drops every owned record/receipt. A fresh runtime
     * relearns peers, but its own publication uses the shared higher counter. */
    uint64_t before_restart=shared_revision;
    memset(&nodes[0],0,sizeof nodes[0]);open_node(0);
    nodes[0].catalog->config.persist=NULL;
    nodes[0].catalog->config.next_revision=next_revision;
    nodes[0].catalog->config.sign_async=delayed_sign;
    nodes[0].catalog->config.cancel_crypto=cancel;
    assert(!nodes[0].catalog->records.count);
    struct wns_record restarted=publications[0];
    restarted.issued=wall();restarted.expires=wall()+900000;
    int result=1;
    for(unsigned step=0;result>0 && step<4;step++)
        result=wnsc_publish(nodes[0].catalog,&restarted,NULL,wall(),clock_ms);
    assert(!result && restarted.generation>before_restart);
    assert(revision_calls==publication_signatures && !nodes[0].journal_size);
    /* A neighbour still has our ordinary signed pre-restart service. Its
     * echo must neither enter foreign verification nor replace the new local
     * generation, and the sole shared download slot must drain. */
    nodes[0].catalog->config.verify_async=delayed_verify;
    nodes[0].pool.config.downloads=1;
    open_node(1);connect(0,1);drive(10);
    struct wg_id echoed={.type=2};
    assert(!wg_offer(&nodes[1].pool,2,echo,echo_size,clock_ms+60000,clock_ms,&echoed));
    struct wg_message have={.op=WG_HAVE,.id=echoed};
    char body[512],frame[WN_CONTROL_MAX+1];
    int body_size=wn_gossip_write(&have,body,sizeof body);assert(body_size>0);
    int frame_size=wn_catalog_fragment_write((uint32_t)body_size,0,body,(size_t)body_size,frame,sizeof frame);
    assert(frame_size>0);
    unsigned verifies_before=delayed_verifications;
    assert(!wnsc_receive(nodes[0].links[1],frame,(size_t)frame_size,wall(),clock_ms));
    drive(100);
    assert(delayed_verifications==verifies_before);
    assert(!nodes[0].pool.pending_count && !nodes[0].links[1]->record_crypto &&
        !nodes[0].links[1]->record_completed.valid);
    struct wns_entry *current=wns_store_find(&nodes[0].catalog->records,nodes[0].catalog->self,
        restarted.app,restarted.service);
    assert(current && current->generation==restarted.generation && current->own);
    free(echo);wnsc_close(nodes[1].catalog);wg_deinit(&nodes[1].pool);free(nodes[1].journal);
    wnsc_close(nodes[0].catalog);wg_deinit(&nodes[0].pool);
    mbedtls_pk_free(&signer);return 0;
}
