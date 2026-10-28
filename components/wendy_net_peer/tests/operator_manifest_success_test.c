#include "wendy_net_operator.h"
#include "wendy_net_router.h"
#include "wendy_pki_crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *load(const char *path,size_t *size)
{
    FILE *f=fopen(path,"rb");assert(f);assert(!fseek(f,0,SEEK_END));long n=ftell(f);assert(n>0 && n<128*1024);rewind(f);
    uint8_t *bytes=malloc((size_t)n);assert(bytes && fread(bytes,1,(size_t)n,f)==(size_t)n);assert(!fclose(f));*size=(size_t)n;return bytes;
}
static int publish(void *context,const struct wn_origin *origin,int64_t wall,int64_t now)
{(void)context;(void)origin;(void)wall;(void)now;return 0;}
static int discard(void *context,uint64_t link,const void *data,size_t size)
{(void)context;(void)link;(void)data;(void)size;return 0;}
static size_t packet(uint8_t out[256],const struct wno_manifest *proof)
{
    out[0]=42;out[1]=2;size_t at=4;
    struct wb_message m={.type=WB_HELLO,.seqno=1,.interval=400};size_t n=wb_encode(&m,out+at,256-at);assert(n);at+=n;
    m=(struct wb_message){.type=WB_IHU,.metric=128,.interval=1600};n=wb_encode(&m,out+at,256-at);assert(n);at+=n;
    m=(struct wb_message){.type=WB_UPDATE,.router=proof->origin.router_id,.seqno=proof->origin.seqno,.metric=0,.interval=1600,.prefix={.family=6,.bits=128}};
    memcpy(m.prefix.bytes,proof->address,16);n=wb_encode(&m,out+at,256-at);assert(n);at+=n;wn_put16(out+2,(uint16_t)(at-4));return at;
}
static void qualify(const struct wno_manifest *proof,const struct wendy_pki_operator_peer *identity,bool gateway)
{
    struct wnr_core *core=calloc(1,sizeof *core);assert(core);
    struct wnr_config cfg={.tenant="11111111-1111-4111-8111-111111111111",.device="55555555-5555-4555-8555-555555555555",.router=55,.seed=1,.non_transit=gateway,.endpoint_gateway=gateway,.publish=publish,.send=discard};
    const int64_t wall=proof->issued,now=1000000;
    assert(!wnr_init(core,&cfg,now,NULL,0));assert(!wnr_start(core,wall,now));
    uint64_t link=0;assert(!wnr_attach(core,"22222222-2222-4222-8222-222222222222",128,wall,now,&link));assert(link);
    size_t before=wnr_memory(core);
    int result=wnr_operator_manifest_verified(core,proof,identity,wall,now);
    if(gateway){assert(result==1 && !core->operators && wnr_memory(core)==before);}
    else{
        assert(!result && core->operators && core->operators->count==1);
        uint8_t wire[256];size_t size=packet(wire,proof);assert(!wnr_receive(core,link,wire,size,wall,now));
    }
    struct wb_route route;assert(wnr_lookup(core,proof->address,now,&route) && route.link==link && !route.local);
    uint8_t ip[48]={0x60};ip[7]=64;wn_put16(ip+4,8);memcpy(ip+8,proof->address,16);memcpy(ip+24,core->directory.self_address,16);
    assert(wn_ip_admits(core->directory.self,ip,sizeof ip,true));
    uint64_t outgoing=99;assert(wnr_packet(core,link,ip,sizeof ip,now,&outgoing)==0 && outgoing==0);
    memcpy(ip+8,core->directory.self_address,16);memcpy(ip+24,proof->address,16);
    assert(wn_ip_admits(core->directory.self,ip,sizeof ip,false));
    assert(wnr_packet(core,0,ip,sizeof ip,now,&outgoing)==1 && outgoing==link);
    printf("%s operator source/native-IP acceptance: %zu live bytes, %zu operator metadata bytes\n",gateway ? "C6 gateway":"C5 router",wnr_memory(core),core->operators ? sizeof *core->operators+wno_memory(core->operators):0);
    wnr_deinit(core);free(core);
}
int main(int argc,char **argv)
{
    assert(argc==4 && !wendy_pki_crypto_init());size_t leaf_size,root_size,wire_size;
    uint8_t *leaf=load(argv[1],&leaf_size),*roots=load(argv[2],&root_size),*wire=load(argv[3],&wire_size);
    struct wno_manifest proof;assert(!wno_manifest_read(wire,wire_size,"11111111-1111-4111-8111-111111111111",&proof));
    struct wendy_pki_operator_peer *peer=calloc(1,sizeof *peer);assert(peer);const uint8_t *chain[]={leaf};size_t sizes[]={leaf_size};
    assert(!wendy_pki_operator_chain(chain,sizes,1,roots,root_size,"11111111-1111-4111-8111-111111111111",(time_t)(proof.issued/1000),peer));
    assert(!wendy_pki_operator_manifest_verify(peer,proof.body,proof.body_size,proof.signature,proof.signature_size));
    qualify(&proof,peer,false);qualify(&proof,peer,true);
    free(peer);free(wire);free(roots);free(leaf);return 0;
}
