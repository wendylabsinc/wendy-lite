/* Normal cache turnover after upstream certificate-path verification. */
#include "wendy_net_directory.h"
#include "wendy_pki_crypto.h"
#include <mbedtls/pk.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct wnd_entry *entry(struct wnd_directory *d,unsigned id)
{
    for(struct wnd_entry *e=d->entries;e;e=e->next)
        if(e->device[15]==id)return e;
    return NULL;
}
int main(int argc,char **argv)
{
    assert(argc==2 && !wendy_pki_crypto_init());
    FILE *f=fopen(argv[1],"rb");assert(f);
    uint8_t der[512];size_t size=fread(der,1,sizeof der,f);fclose(f);
    mbedtls_pk_context key;mbedtls_pk_init(&key);
    assert(!mbedtls_pk_parse_key(&key,der,size,NULL,0));
    uint8_t spki[128];int n=mbedtls_pk_write_pubkey_der(&key,spki,sizeof spki);assert(n>0);
    struct wendy_pki_mesh_peer peer={.expires=1800003600,.spki_size=(size_t)n};
    memcpy(peer.spki,spki+sizeof spki-n,(size_t)n);
    struct wnd_directory d;
    assert(!wnd_init(&d,"2558fd76-afc7-466e-9613-6b715296a526",
        "00000000-0000-4000-8000-0000000000ff"));
    assert(!wnd_key_limit(&d,8));
    for(unsigned i=1;i<=8;i++){
        snprintf(peer.device,sizeof peer.device,"00000000-0000-4000-8000-%012x",i);
        assert(!wnd_identity(&d,&peer));
    }
    assert(d.key_count==8 && d.count==8);
    assert(!wnd_key_pin(&d,entry(&d,1)->device,true));
    struct wnd_entry *old=entry(&d,2);
    old->revision=42;old->deadline_us=9000;
    old->manifest.origin=(struct wn_origin){.router_id=22,.seqno=3};
    snprintf(peer.device,sizeof peer.device,"00000000-0000-4000-8000-%012x",9);
    assert(!wnd_identity(&d,&peer));
    assert(d.key_count==8 && d.count==9 && entry(&d,1)->peer.spki_size);
    assert(!old->peer.spki_size && !old->peer.spki && old->revision==42);
    assert(wnd_authorizes(&d,old->address,22,3,100));
    /* A fresh fetched/verified key can occupy another slot; no DER retained. */
    snprintf(peer.device,sizeof peer.device,"00000000-0000-4000-8000-%012x",2);
    assert(!wnd_identity(&d,&peer));
    assert(entry(&d,2)->peer.spki_size && !entry(&d,3)->peer.spki_size);
    assert(entry(&d,2)->revision==42 && d.key_count==8);
    old->deadline_us=9000;
    /* A constrained node lends one of its eight key slots to a typed operator.
     * Pinned next hops and already-verified device projections survive. */
    assert(!wnd_key_limit(&d,7));
    assert(d.key_count==7 && entry(&d,1)->peer.spki_size && old->revision==42);
    assert(wnd_authorizes(&d,old->address,22,3,100));
    assert(!wnd_key_limit(&d,8));
    snprintf(peer.device,sizeof peer.device,"00000000-0000-4000-8000-%012x",10);
    assert(!wnd_identity(&d,&peer));assert(d.key_count==8);
    /* Full-router default retains every origin key instead of this tiny tier. */
    size_t bytes=wnd_memory(&d);
    printf("8-key FIFO with live7/8 trim: SPKI=%zu bytes, %u origin projections plus keys=%zu bytes\n",
        (size_t)n,d.count,bytes);
    wnd_deinit(&d);
    assert(!wnd_init(&d,"2558fd76-afc7-466e-9613-6b715296a526",
        "00000000-0000-4000-8000-0000000000ff"));
    for(unsigned i=1;i<=12;i++){
        snprintf(peer.device,sizeof peer.device,"00000000-0000-4000-8000-%012x",i);
        assert(!wnd_identity(&d,&peer));
    }
    assert(d.key_count==12 && entry(&d,1)->peer.spki_size);
    wnd_deinit(&d);mbedtls_pk_free(&key);
    return 0;
}
