/* Normal delayed flash/signing effects preserve unrelated forwarding. */
#include "wendy_net_router.h"
#include "wendy_pki_crypto.h"
#include <mbedtls/pk.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct driver {bool flash,signature;unsigned packets,writes,signs;};
static int persist(void *context,const void *data,size_t size)
{struct driver *d=context;assert(data && size);if(!d->flash)return 1;d->writes++;return 0;}
static int publish(void *context,const struct wn_origin *origin,int64_t wall,int64_t mono)
{struct driver *d=context;(void)wall;(void)mono;assert(origin->router_id);if(!d->signature)return 1;d->signs++;return 0;}
static int send_packet(void *context,uint64_t link,const void *data,size_t size)
{struct driver *d=context;assert(link && data && size && d->flash && d->signature);d->packets++;return 0;}
/* A newer v4 writer adds descriptive metadata without changing route meaning.
 * Preserve/sign those exact bytes while consuming only known projections. */
static int future_metadata(const void *base,size_t size,char *out,size_t capacity)
{
    struct wn_doc d;assert(!wn_doc_parse(&d,base,size));
    struct wn_writer w={.data=(uint8_t*)out,.capacity=capacity,.maximum=WN_CONTROL_MAX};
    wn_map(&w,14);
    for(unsigned i=1;i<d.tokens[0].next;i=d.tokens[i+1].next){
        unsigned v=i+1;
        if(wn_doc_equal(&d,(int)i,"Expires")){
            wn_text(&w,"future");wn_map(&w,1);wn_text(&w,"items");wn_array(&w,2);
            wn_bool(&w,true);wn_map(&w,1);wn_text(&w,"label");wn_text(&w,"温度");
        }
        if(wn_doc_equal(&d,(int)i,"revision")){wn_text(&w,"requires");wn_array(&w,0);}
        wn_raw(&w,d.text+d.tokens[i].start,d.tokens[i].end-d.tokens[i].start);
        if(wn_doc_equal(&d,(int)i,"caps")){
            wn_array(&w,2);wn_text(&w,"sensors");wn_text(&w,"vendor/future");
        }else if(wn_doc_equal(&d,(int)i,"route")){
            wn_map(&w,4);wn_text(&w,"hint");wn_map(&w,1);wn_text(&w,"color");wn_text(&w,"green");
            for(unsigned j=v+1;j<d.tokens[v].next;j=d.tokens[j+1].next)
                wn_raw(&w,d.text+d.tokens[j].start,d.tokens[j+1].end-d.tokens[j].start);
        }else wn_raw(&w,d.text+d.tokens[v].start,d.tokens[v].end-d.tokens[v].start);
    }
    return wn_finish(&w);
}
int main(int argc,char **argv)
{
    assert(argc==2 && !wendy_pki_crypto_init());
    FILE *f=fopen(argv[1],"rb");assert(f);uint8_t der[512];size_t size=fread(der,1,sizeof der,f);fclose(f);
    mbedtls_pk_context key;mbedtls_pk_init(&key);assert(!mbedtls_pk_parse_key(&key,der,size,NULL,0));
    const char *tenant="2558fd76-afc7-466e-9613-6b715296a526";
    const char *self="00000000-0000-4000-8000-000000000004",*peer="00000000-0000-4000-8000-000000000005";
    struct driver driver={0};struct wnr_core core={0};
    struct wnr_config config={.tenant=tenant,.device=self,.router=44,.context=&driver,.persist=persist,.publish=publish,.send=send_packet};
    const int64_t wall=1800000000000,epoch=1000000;
    assert(!wnr_init(&core,&config,epoch,NULL,0));
    assert(!wnr_start(&core,wall,epoch));assert(!core.stopped && !core.durable && !driver.packets);
    struct wendy_pki_mesh_peer identity={.expires=1800003600};strcpy(identity.device,peer);
    uint8_t public[128];int count=mbedtls_pk_write_pubkey_der(&key,public,sizeof public);assert(count>0);
    identity.spki_size=(size_t)count;memcpy(identity.spki,public+sizeof public-count,(size_t)count);
    assert(!wnr_identity(&core,&identity,wall+1,epoch+1000));
    uint64_t link=0;assert(!wnr_attach(&core,peer,128,wall+2,epoch+2000,&link));assert(link && !driver.packets);
    driver.flash=true;int result=wnr_tick(&core,wall+3,epoch+3000);
    if(result)fprintf(stderr,"tick result=%d stage=%s error=%d pending=%llu\n",result,core.stop_stage,core.stop_error,(unsigned long long)core.babel.pending);
    assert(!result);assert(core.durable && !driver.packets);
    driver.signature=true;assert(!wnr_tick(&core,wall+4,epoch+4000));assert(driver.packets && driver.signs);
    uint8_t uuid[16];assert(!wn_uuid_parse(peer,uuid));
    struct wn_origin origin={.router_id=55,.seqno=1};char body[768],principal[106],wire[2048];
    char base[768];
    int n=wn_manifest_capabilities_write(uuid,&origin,1,wall+5,wall+900000,5054,43022,
        "Temperature node",true,base,sizeof base);assert(n>0);
    n=future_metadata(base,(size_t)n,body,sizeof body);assert(n>0);
    size_t body_size=(size_t)n;
    assert(wn_principal(tenant,peer,principal)==105);
    uint8_t hash[32],signature[80];size_t sig_size=0;
    assert(!wendy_pki_mesh_digest(principal,body,(size_t)n,hash));
    assert(!mbedtls_pk_sign(&key,MBEDTLS_MD_SHA256,hash,sizeof hash,signature,sizeof signature,&sig_size));
    struct wendy_pki_mesh_key view={.spki=identity.spki,.spki_size=identity.spki_size,.expires=identity.expires};
    strcpy(view.device,peer);assert(!wendy_pki_mesh_verify_key(&view,principal,body,(size_t)n,signature,sig_size));
    n=wn_manifest_wire_write(principal,body,(size_t)n,signature,sig_size,wire,sizeof wire);assert(n>0);
    driver.flash=false;assert(wnr_manifest_verified(&core,wire,(size_t)n,wall+5,epoch+5000)==4);
    assert(core.directory.entries->pending_receipt);
    assert(core.directory.entries->manifest.platform_lite && core.directory.entries->manifest.sensors);
    assert(core.directory.entries->manifest.agent_mtls && core.directory.entries->manifest.agent_port==5054);
    assert(!wendy_pki_sha256((const uint8_t*)body,body_size,hash));
    assert(!memcmp(hash,core.directory.entries->body_hash,sizeof hash));
    uint8_t self_uuid[16],address[16];assert(!wn_uuid_parse(self,self_uuid));wn_address(self_uuid,address);
    struct wb_route route;assert(wnr_lookup(&core,address,epoch+5000,&route));
    driver.flash=true;assert(!wnr_tick(&core,wall+6,epoch+6000));
    assert(!core.directory.entries->pending_receipt && core.durable && !core.stopped);
    wnr_deinit(&core);mbedtls_pk_free(&key);
    puts("Delayed journal and signature effects resume; unrelated local forwarding remains usable");
}
