/* A valid signature waits for ordinary temporary allocation pressure to clear. */
#include "crypto_job.h"
#include "wendy_pki_work.h"
#include "wendy_pki_crypto.h"
#include "wendy_net_alloc.h"
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* This verification-only fixture never lends a TLS signing context. */
size_t wendy_pki_artifact_signature_capacity(wendy_pki_connection *c){(void)c;return 0;}
int wendy_pki_artifact_sign(wendy_pki_connection *c,unsigned k,const char *p,const void *b,size_t n,uint8_t *s,size_t z,size_t *w)
{(void)c;(void)k;(void)p;(void)b;(void)n;(void)s;(void)z;(void)w;return -1;}
int wendy_pki_mesh_sign_digest(wendy_pki_connection *c,const char *p,const uint8_t h[32],uint8_t s[80],size_t *n)
{(void)c;(void)p;(void)h;(void)s;(void)n;return -1;}
int wendy_pki_mesh_fingerprint(wendy_pki_connection *c,uint8_t h[32]){(void)c;(void)h;return -1;}
int main(int argc,char **argv)
{
    assert(argc==2);
    assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,wendy_net_memory_scoped_free));
    assert(!wendy_pki_crypto_init());
    FILE *f=fopen(argv[1],"rb");assert(f);uint8_t der[512];size_t n=fread(der,1,sizeof der,f);fclose(f);
    mbedtls_pk_context key;mbedtls_pk_init(&key);assert(!mbedtls_pk_parse_key(&key,der,n,NULL,0));
    uint8_t spki[128],signature[80],digest[32];int public_size=mbedtls_pk_write_pubkey_der(&key,spki,sizeof spki);assert(public_size>0);
    const char principal[]="spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/00000000-0000-4000-8000-000000000004";
    const uint8_t body[]={0xa1,0x61,'x',0x01};size_t signature_size;
    assert(!wendy_pki_artifact_digest(0,principal,body,sizeof body,digest));
    assert(!mbedtls_pk_sign(&key,MBEDTLS_MD_SHA256,digest,32,signature,sizeof signature,&signature_size));
    struct wendy_pki_mesh_key peer={.spki=spki+sizeof spki-(size_t)public_size,.spki_size=(size_t)public_size};
    strcpy(peer.device,principal+69);
    assert(wendy_net_memory_open(wendy_net_runtime_memory_ledger(),64*1024,false));
    wendy_net_memory_scope_t prior=wendy_net_runtime_scope_enter();wendy_pki_work_enable();
    struct wncrypto_job *job=NULL;struct wncrypto_verdict completed={0};
    assert(wncrypto_verify_cached(&job,&completed,0,&peer,principal,body,sizeof body,signature,signature_size)==1 && job);
    wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);
    wendy_net_memory_reservation_t pressure={0};
    assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),&pressure,memory.limit_bytes-memory.current_bytes,WENDY_NET_MEMORY_INTERNAL));
    assert(wendy_pki_work_poll() && wncrypto_take_verification(&job,&completed));
    assert(completed.valid && completed.result==1 && !job);
    wendy_net_memory_release(&pressure);
    assert(wncrypto_verify_cached(&job,&completed,0,&peer,principal,body,sizeof body,signature,signature_size)==1 && job);
    assert(wendy_pki_work_poll());
    assert(!wncrypto_verify_cached(&job,&completed,0,&peer,principal,body,sizeof body,signature,signature_size) && !job);
    wendy_net_memory_scope_leave(prior);wendy_net_runtime_memory_close();
    assert(wendy_net_runtime_memory_drained());mbedtls_pk_free(&key);
    puts("valid native signature retries after bounded allocation pressure and releases all scoped workspace PASS");
}
