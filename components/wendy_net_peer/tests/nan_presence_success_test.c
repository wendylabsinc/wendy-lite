/* Normal binary discovery interop; no malformed or adversarial vectors. */
#include "wendy_net_nan_protocol.h"
#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(int argc,char **argv)
{
    uint8_t tenant[16],device[16],wire[WN_NAN_PRESENCE_SIZE];
    const uint8_t mesh[]={0x8e,0x6d,0x83,0xe9,0xd1,0x3f,0xfe,0x98};
    assert(!wn_uuid_parse("5b8c6c8e-2f9f-4b4a-9a4f-6e2d8c9a0b12",tenant));
    assert(!wn_uuid_parse("018b8657-2f1a-4d3e-9c1a-2b4f6a8c0d1e",device));
    assert(wn_nan_presence_write(tenant,device,mesh,true,wire)==sizeof wire);
    if(argc==2 && !strcmp(argv[1],"--emit")){
        for(unsigned i=0;i<sizeof wire;i++)printf("%02x",wire[i]);
        puts("");return 0;
    }
    if(argc==3 && !strcmp(argv[1],"--read")){
        assert(strlen(argv[2])==sizeof wire*2);
        for(unsigned i=0;i<sizeof wire;i++){
            unsigned value;assert(sscanf(argv[2]+i*2,"%2x",&value)==1);wire[i]=(uint8_t)value;
        }
    }
    struct wn_nan_hint hint;
    assert(wn_nan_presence_read(tenant,mesh,wire,sizeof wire,&hint));
    assert(!memcmp(device,hint.device,16));
    if(argc==3)printf("tls_only=%u\n",(unsigned)hint.tls_only);
    else{
        assert(hint.tls_only);
        assert(wn_nan_presence_write(tenant,device,mesh,false,wire)==sizeof wire);
        assert(wn_nan_presence_read(tenant,mesh,wire,sizeof wire,&hint));
        assert(!hint.tls_only);
        uint8_t wrapped[WN_NAN_PRESENCE_SIZE+4]={0x50,0x6f,0x9a,0};
        memcpy(wrapped+4,wire,sizeof wire);
        assert(wn_nan_presence_read(tenant,mesh,wrapped,sizeof wrapped,&hint));
        assert(!memcmp(device,hint.device,16) && !hint.tls_only);
        puts("normal QUIC-capable and TLS-only NAN presence roundtrips pass");
    }
    return 0;
}
