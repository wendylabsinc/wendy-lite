/* Independent Go signer -> production C reader, plus C -> Go byte equality. */
#include "wendy_net_directory.h"
#include "wendy_pki_crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static size_t load(const char *path,uint8_t *bytes,size_t cap)
{FILE *f=fopen(path,"rb");assert(f);size_t n=fread(bytes,1,cap,f);assert(fgetc(f)==EOF && !ferror(f));fclose(f);return n;}
int main(int argc,char **argv)
{
    assert((argc==4 || argc==5) && !wendy_pki_crypto_init());
    bool unsupported=argc==5;
    const char *tenant="2558fd76-afc7-466e-9613-6b715296a526";
    const char *device="00000000-0000-4000-8000-000000000004";
    uint8_t wire[WN_MANIFEST_WIRE_MAX];
    struct wendy_pki_mesh_peer peer={.expires=1800003600};strcpy(peer.device,device);
    uint8_t public_der[4096];size_t public_size=load(argv[1],public_der,sizeof public_der);
    if(!unsupported){assert(public_size<=sizeof peer.spki);memcpy(peer.spki,public_der,public_size);peer.spki_size=public_size;}
    size_t size=load(argv[2],wire,sizeof wire);
    struct wnd_directory d;assert(!wnd_init(&d,tenant,"00000000-0000-4000-8000-000000000005"));
    if(unsupported){
        assert(wnd_accept(&d,wire,size,INT64_C(1800000000000),100)==WND_UNSUPPORTED);
        assert(!d.entries && !d.count);wnd_deinit(&d);
        puts("Larger unsupported origin signature is classified without retaining state");return 0;
    }
    assert(!wnd_identity(&d,&peer));
    assert(!wnd_accept(&d,wire,size,INT64_C(1800000000000),100));
    assert(d.entries && d.entries->manifest.sensors && d.entries->manifest.platform_lite);
    assert(d.entries->manifest.agent_port==5054 && d.entries->manifest.tls_app_port==43022);
    struct wn_doc doc;assert(!wn_doc_parse_array_view(&doc,wire,size,sizeof wire,"services"));
    int body=wn_doc_member(&doc,0,"body");assert(body>=0);
    int array=wn_doc_member(&doc,(unsigned)body,"services");assert(array>=0);
    const struct wn_token *t=wn_doc_token(&doc,array);assert(t);
    char encoded[WN_MANIFEST_BODY_MAX];uint8_t uuid[16];assert(!wn_uuid_parse(device,uuid));
    struct wn_origin origin={.router_id=444,.seqno=7};
    int written=wn_manifest_services_write(uuid,&origin,42,INT64_C(1800000000000),INT64_C(1800000900000),
        5054,43022,"interop",true,doc.text+t->start,t->end-t->start,encoded,sizeof encoded);
    assert(written>0);FILE *out=fopen(argv[3],"wb");assert(out);
    assert(fwrite(encoded,1,(size_t)written,out)==(size_t)written);assert(!fclose(out));
    printf("Native Go-signed manifest: SPKI=%zu envelope=%zu C body=%d bytes\n",peer.spki_size,size,written);
    wnd_deinit(&d);return 0;
}
