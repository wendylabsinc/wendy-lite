/* A normal manifest callback hands off a real P256 signing job while the
 * actual carrier pump is delivering a frame. TLS entry is a counted edge:
 * no read/write/metadata entry may touch the loaned connection. */
#include "crypto_job.h"
#include "certificate_store.h"
#include "certificate_wire.h"
#include "wendy_net_carrier.h"
#include "wendy_net_service_protocol.h"
#include "wendy_pki_work.h"
#include "wendy_pki_crypto.h"
#include "../src/artifact_crypto.h"
#include <assert.h>
#include <mbedtls/pk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define CONFIG_WENDY_NET_ROUTER 1
#define WN_ROUTE_ASYNC 1
struct wendy_pki_connection {
    unsigned reads,writes,metadata;
    uint8_t input[128],output[256];
    size_t input_size,input_at,output_size;
};
struct wnrs_node;
struct wnrs {
    struct wnrs *next;
    uint64_t link;
    struct wnrs_node *node;
    struct wendy_pki_mesh_identity identity;
    wendy_pki_connection *connection;
    void *context;
    int (*send)(void *,const void *,size_t,bool);
};
struct wnrs_node {
    struct wnrs *sessions;
    struct wendy_pki_mesh_identity clock;
    struct wncs_store certificates;
};
struct peer_state {wendy_pki_connection *connection;struct wnrs *router;};
static mbedtls_pk_context signer;
static uint8_t fingerprint[32];
static const char tenant[]="2558fd76-afc7-466e-9613-6b715296a526";
static const char self[]="00000000-0000-4000-8000-000000000004";
static const int64_t wall=1790000000000;
static unsigned signing_calls;
static bool wnrs_receive_paused(const struct wnrs *s){(void)s;return false;}
ssize_t wendy_pki_read(void *context,void *data,size_t size)
{
    wendy_pki_connection *c=context;
    assert(!wncrypto_borrowed(c));c->reads++;
    if(c->input_at==c->input_size)return -2;
    if(size>c->input_size-c->input_at)size=c->input_size-c->input_at;
    memcpy(data,c->input+c->input_at,size);c->input_at+=size;return (ssize_t)size;
}
ssize_t wendy_pki_write(void *context,const void *data,size_t size)
{
    wendy_pki_connection *c=context;
    assert(!wncrypto_borrowed(c));c->writes++;
    if(size>2)size=2; /* Pin one ordinary partial frame across the handoff. */
    assert(size<=sizeof c->output-c->output_size);
    memcpy(c->output+c->output_size,data,size);c->output_size+=size;return (ssize_t)size;
}
int wendy_pki_mesh_fingerprint(wendy_pki_connection *c,uint8_t out[32])
{assert(!wncrypto_borrowed(c));c->metadata++;memcpy(out,fingerprint,32);return 0;}
int wendy_pki_mesh_describe(wendy_pki_connection *c,char *out,size_t size)
{assert(!wncrypto_borrowed(c));c->metadata++;assert(size);out[0]=(char)0xa0;return 1;}
int wncs_chain_get(struct wncs_store *store,const char *principal,int64_t expires,struct wncf_chain *out)
{(void)store;(void)principal;(void)expires;(void)out;return 0;}
size_t wendy_pki_artifact_signature_capacity(wendy_pki_connection *c)
{assert(!wncrypto_borrowed(c));return pki_artifact_signature_capacity(&signer);}
int wendy_pki_mesh_sign_digest(wendy_pki_connection *c,const char *principal,
    const uint8_t digest[32],uint8_t signature[80],size_t *written)
{
    (void)c;assert(strlen(principal)==105);signing_calls++;
    return mbedtls_pk_sign(&signer,MBEDTLS_MD_SHA256,digest,32,signature,80,written);
}
int wendy_pki_artifact_sign(wendy_pki_connection *c,unsigned kind,const char *principal,
    const void *body,size_t size,uint8_t *signature,size_t capacity,size_t *written)
{(void)c;signing_calls++;return pki_artifact_sign(&signer,kind,principal,body,size,signature,capacity,written);}
#include "carrier_loan_callbacks.inc"
struct callback {
    struct wnrs_node *node;
    struct wncrypto_job *job;
    struct wncrypto_signature completed;
    const uint8_t *body;
    size_t size;
    const char *principal;
    unsigned calls;
};
static int receive(void *context,const void *data,size_t size,bool control)
{
    struct callback *callback=context;
    assert(control && size==4 && !memcmp(data,"next",4));callback->calls++;
    const uint8_t *signature=NULL;size_t written=0;
    assert(wncrypto_sign_cached(&callback->job,&callback->completed,0,callback->node->sessions->connection,
        callback->principal,callback->body,callback->size,&signature,&written)==1);
    assert(callback->job && !signature && !written);
    return 0;
}
static int discard(void *context,const void *data,size_t size,bool control)
{(void)context;(void)data;(void)size;(void)control;return 0;}
static int send_metadata(void *context,const void *data,size_t size,bool control)
{(void)context;assert(data && size && control);return 0;}
int main(int argc,char **argv)
{
    assert((argc==2 || argc==3) && !wendy_pki_crypto_init() && wendy_net_runtime_memory_open());
    FILE *file=fopen(argv[1],"rb");assert(file);
    uint8_t der[512];size_t size=fread(der,1,sizeof der,file);fclose(file);
    mbedtls_pk_init(&signer);assert(!mbedtls_pk_parse_key(&signer,der,size,NULL,0));
    uint8_t spki[512];int spki_size=mbedtls_pk_write_pubkey_der(&signer,spki,sizeof spki);assert(spki_size>0);
    assert(!wendy_pki_sha256(spki+sizeof spki-spki_size,(size_t)spki_size,fingerprint));
    struct wns_record record={.port=28080,.issued=wall,.expires=wall+900000,.generation=1};
    assert(wn_principal(tenant,self,record.principal)>0);
    strcpy(record.mesh,"default");strcpy(record.app,"com.example.sensor");
    strcpy(record.service,"sample");strcpy(record.type,"_sensorlink._tcp");
    strcpy(record.instance,"Positive callback handoff");
    uint8_t device[16];assert(!wn_uuid_parse(self,device));struct wn_origin origin={42,7};
    char body[1024];int body_size=wn_manifest_app_write(device,&origin,1,wall,wall+900000,5054,43022,body,sizeof body);assert(body_size>0);
    wendy_pki_connection borrowed={0},other={0};
    struct wnrs_node node={0};strcpy(node.clock.device,self);
    struct wnrs a={.node=&node,.connection=&borrowed,.send=send_metadata},
                b={.node=&node,.connection=&other,.send=send_metadata};
    strcpy(a.identity.tenant,tenant);strcpy(a.identity.device,self);b.identity=a.identity;
    /* The signing callback chooses the node's head session, independently
     * from whichever carrier's receive callback is executing now. */
    node.sessions=&a;a.next=&b;
    struct peer_state owner={.connection=&borrowed,.router=&a},
                      unrelated={.connection=&other,.router=&b};
    uint8_t scratch[2][WN_DATAGRAM_MAX];struct wnc_carrier carrier,second;
    struct wnc_io io={.context=&owner,.read=carrier_read,.write=carrier_write},
                  io2={.context=&unrelated,.read=carrier_read,.write=carrier_write};
    assert(!wnc_init(&carrier,&io,scratch[0],sizeof scratch[0],8192,128));
    assert(!wnc_init(&second,&io2,scratch[1],sizeof scratch[1],8192,128));
    const char outgoing[]="queued";
    assert(!wnc_enqueue(&carrier,outgoing,sizeof outgoing-1,true));
    assert(!wnc_enqueue(&second,outgoing,sizeof outgoing-1,true));
    borrowed.input[0]=1;wn_put32(borrowed.input+1,8);wn_put32(borrowed.input+5,4);
    memcpy(borrowed.input+9,"next",4);borrowed.input_size=13;
    struct callback callback={.node=&node,.body=(const uint8_t *)body,.size=(size_t)body_size,.principal=record.principal};
    wendy_pki_work_enable();
    int unrelated_tls_workspace=0;
    bool overlap=argc==3;
    if(overlap)assert(wendy_pki_handshake_claim(&unrelated_tls_workspace));
    assert(wnc_pump(&carrier,1000,receive,&callback)>0);
    assert(wnc_pump(&carrier,2000,receive,&callback)>0);
    assert(callback.calls==1 && wncrypto_borrowed(&borrowed) && !wncrypto_borrowed(&other));
    unsigned reads=borrowed.reads,writes=borrowed.writes,metadata=borrowed.metadata;
    size_t queued=carrier.queued;void *pinned=carrier.head;
    /* An outer tick would now skip this context. The boundary guards also
     * protect any subsequent same-iteration/reentrant carrier pump call. */
    assert(!wnc_pump(&carrier,3000,receive,&callback));
    assert(borrowed.reads==reads && borrowed.writes==writes);
    assert(carrier.head==pinned && carrier.queued==queued && borrowed.output_size==4);
    assert(describe(&a)==1 && borrowed.metadata==metadata);
    /* An independent live connection progresses while the signing slot is
     * occupied. This is not a global crypto-queue or whole-mesh lock. */
    for(unsigned i=0;i<20;i++)assert(wnc_pump(&second,4000+i,discard,NULL)>=0);
    assert(!second.head && other.output_size==15 && !describe(&b));
    assert(wendy_pki_work_poll() && signing_calls==1 && !wncrypto_borrowed(&borrowed));
    assert(wncrypto_take_signature(&callback.job,&callback.completed));
    struct wendy_pki_mesh_key key={.spki=spki+sizeof spki-spki_size,.spki_size=(size_t)spki_size};
    strcpy(key.device,self);
    assert(!wendy_pki_mesh_verify_key(&key,record.principal,body,(size_t)body_size,
        callback.completed.signature,callback.completed.signature_size));
    for(unsigned i=0;i<20;i++)assert(wnc_pump(&carrier,5000+i,receive,&callback)>=0);
    assert(!carrier.head && borrowed.output_size==15 && !memcmp(borrowed.output,other.output,15));
    assert(!describe(&a));
    wncrypto_signature_clear(&callback.completed);
    /* A receive callback on B can lend head A after A already progressed in
     * this actor pass. The next A boundary must recheck that exact loan. */
    assert(!wnc_enqueue(&carrier,outgoing,sizeof outgoing-1,true));
    assert(!wnc_enqueue(&second,outgoing,sizeof outgoing-1,true));
    memcpy(other.input,borrowed.input,borrowed.input_size);
    other.input_size=borrowed.input_size;other.input_at=0;
    assert(wnc_pump(&carrier,6000,receive,&callback)>0);
    assert(wnc_pump(&second,6001,receive,&callback)>0);
    assert(wnc_pump(&second,6002,receive,&callback)>0);
    assert(callback.calls==2 && wncrypto_borrowed(&borrowed) && !wncrypto_borrowed(&other));
    reads=borrowed.reads;writes=borrowed.writes;
    assert(!wnc_pump(&carrier,6003,receive,&callback));
    assert(borrowed.reads==reads && borrowed.writes==writes);
    for(unsigned i=0;i<20;i++)assert(wnc_pump(&second,6010+i,discard,NULL)>=0);
    assert(!second.head && other.output_size==30);
    assert(wendy_pki_work_poll() && signing_calls==2);
    assert(wncrypto_take_signature(&callback.job,&callback.completed));
    for(unsigned i=0;i<20;i++)assert(wnc_pump(&carrier,7000+i,discard,NULL)>=0);
    assert(!carrier.head && borrowed.output_size==30 && !memcmp(borrowed.output,other.output,30));
    wncrypto_signature_clear(&callback.completed);wnc_deinit(&carrier);wnc_deinit(&second);
    if(overlap){
        int other_workspace=0;
        assert(!wendy_pki_handshake_claim(&other_workspace));
        wendy_pki_handshake_release(&unrelated_tls_workspace);
    }
    assert(wendy_pki_work_stop());mbedtls_pk_free(&signer);
    wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);
    assert(!memory.current_bytes);wendy_net_runtime_memory_close();
    puts("actual callback signing loan: pinned frame/WANT, metadata, other-context progress, P256 completion and OFF drain PASS");
    return 0;
}
