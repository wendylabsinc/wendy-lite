/* Ordinary native CBOR signing, route leases, replacement and RAM snapshots. */
#include "wendy_net_directory.h"
#include "wendy_pki_crypto.h"
#include <assert.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char tenant[]="2558fd76-afc7-466e-9613-6b715296a526";
static const char self[]="00000000-0000-4000-8000-000000000005";
static const char peer_id[]="00000000-0000-4000-8000-000000000004";
static int envelope(mbedtls_pk_context *key,const void *body,size_t bytes,char *out,size_t capacity)
{
    static const char domain[]="wendy-local-mesh/manifest/4";
    char principal[106];uint8_t hash[32],signature[80];size_t size=0,written=0;
    assert(wn_principal(tenant,peer_id,principal)==105);
    psa_hash_operation_t op=PSA_HASH_OPERATION_INIT;
    const uint8_t principal_size[]={0,0,0,105};
    assert(psa_hash_setup(&op,PSA_ALG_SHA_256)==PSA_SUCCESS);
    assert(psa_hash_update(&op,(const uint8_t*)domain,sizeof domain)==PSA_SUCCESS);
    assert(psa_hash_update(&op,principal_size,sizeof principal_size)==PSA_SUCCESS);
    assert(psa_hash_update(&op,(const uint8_t*)principal,105)==PSA_SUCCESS);
    assert(psa_hash_update(&op,body,bytes)==PSA_SUCCESS);
    assert(psa_hash_finish(&op,hash,sizeof hash,&written)==PSA_SUCCESS && written==32);
    assert(!mbedtls_pk_sign(key,MBEDTLS_MD_SHA256,hash,32,signature,sizeof signature,&size));
    return wn_manifest_wire_write(principal,body,bytes,signature,size,out,capacity);
}
static int body_write(uint8_t uuid[16],struct wn_origin *origin,uint64_t revision,uint16_t port,bool withdraw,char body[2048])
{
    int n=wn_manifest_app_write(uuid,origin,revision,INT64_C(1800000000000),INT64_C(1800000060000),port,43022,body,2048);
    assert(n>0);
    if(withdraw){
        /* One optional current-format boolean, after the ordinary map fields. */
        assert((uint8_t)body[0]==0xad);body[0]=(char)0xae;
        struct wn_writer w={.data=(uint8_t*)body,.capacity=2048,.maximum=2048,.size=(size_t)n};
        wn_key(&w,"withdraw");wn_bool(&w,true);n=wn_finish(&w);assert(n>0);
    }
    return n;
}
int main(int argc,char **argv)
{
    assert(argc==2 && !wendy_pki_crypto_init());
    FILE *file=fopen(argv[1],"rb");assert(file);
    uint8_t keybytes[1024];size_t keysize=fread(keybytes,1,sizeof keybytes,file);assert(feof(file));fclose(file);
    mbedtls_pk_context key;mbedtls_pk_init(&key);assert(!mbedtls_pk_parse_key(&key,keybytes,keysize,NULL,0));
    struct wendy_pki_mesh_peer peer={.expires=1800003600};memcpy(peer.device,peer_id,37);
    uint8_t spki[128];int spki_size=mbedtls_pk_write_pubkey_der(&key,spki,sizeof spki);assert(spki_size>0);
    memcpy(peer.spki,spki+sizeof spki-spki_size,(size_t)spki_size);peer.spki_size=(size_t)spki_size;
    struct wnd_directory d;assert(!wnd_init(&d,tenant,self));
    size_t idle=wnd_memory(&d);assert(!d.count && !d.entries && idle==sizeof d);
    uint8_t uuid[16],address[16];assert(!wn_uuid_parse(peer_id,uuid));wn_address(uuid,address);
    struct wn_origin origin={.router_id=UINT64_MAX-1,.seqno=65535};
    char body[2048],wire[4096],old[4096];uint64_t revision=UINT64_C(9007199254740993);
    int n=body_write(uuid,&origin,revision,5054,false,body);
    /* The public parser honors operation-owned token storage, too. */
    struct wn_doc doc;struct wn_token tokens[WN_TOKENS];struct wnd_manifest manifest;
    assert(!wn_doc_parse_into(&doc,body,(size_t)n,WN_MANIFEST_BODY_MAX,tokens,WN_TOKENS));
    assert(!wnd_manifest_read(&doc,0,&manifest) && manifest.revision==revision);
    int size=envelope(&key,body,(size_t)n,wire,sizeof wire);assert(size>0);
    memcpy(old,wire,(size_t)size);int old_size=size;
    assert(wnd_accept(&d,wire,(size_t)size,INT64_C(1800000000000),100)==2 && !d.count);
    assert(!wnd_identity(&d,&peer) && d.count==1);
    assert(!wnd_accept(&d,wire,(size_t)size,INT64_C(1800000000000),100));
    assert(wnd_authorizes(&d,address,origin.router_id,origin.seqno,100));
    assert(!wnd_authorizes(&d,address,origin.router_id,0,100));
    assert(d.entries->manifest.agent_mtls && d.entries->manifest.tls_app_port==43022);
    assert(d.entries->revision==revision);int64_t deadline=d.entries->deadline_us;
    assert(!wnd_accept(&d,wire,(size_t)size,INT64_C(1800000000000),1000));
    assert(d.entries->deadline_us==deadline);
    /* A restarted service may immediately publish a new port/revision. */
    n=body_write(uuid,&origin,revision+1,5055,false,body);size=envelope(&key,body,(size_t)n,wire,sizeof wire);
    assert(size>0 && !wnd_accept(&d,wire,(size_t)size,INT64_C(1800000000000),100));
    assert(d.entries->manifest.agent_port==5055 && d.entries->revision==revision+1);
    origin.seqno=0;
    n=body_write(uuid,&origin,revision+2,5055,true,body);size=envelope(&key,body,(size_t)n,wire,sizeof wire);
    assert(size>0 && !wnd_accept(&d,wire,(size_t)size,INT64_C(1800000000000),100));
    assert(!wnd_address(&d,address,100));
    uint8_t receipts[WND_RECEIPTS_MAX];int saved=wnd_save(&d,receipts,sizeof receipts);assert(saved==62);
    struct wnd_directory restarted;assert(!wnd_init(&restarted,tenant,self));
    assert(!wnd_restore(&restarted,receipts,(size_t)saved));
    assert(!wnd_address(&restarted,address,100) && restarted.entries->revision==revision+2);
    assert(!wnd_identity(&restarted,&peer));
    assert(wnd_accept(&restarted,old,(size_t)old_size,INT64_C(1800000000000),100)==1);
    assert(!wnd_accept(&restarted,wire,(size_t)size,INT64_C(1800000000000),100));
    assert(!wnd_address(&restarted,address,100));
    assert(wnd_accept(&d,wire,(size_t)size,INT64_C(1800000060000),100)==1);
    printf("Native signed directory: idle=%zu one=%zu RAM receipt=%d bytes\n",idle,wnd_memory(&d),saved);
    wnd_deinit(&d);wnd_deinit(&restarted);mbedtls_pk_free(&key);return 0;
}
