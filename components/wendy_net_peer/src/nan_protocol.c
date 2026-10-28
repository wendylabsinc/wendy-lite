#include "wendy_net_nan_protocol.h"
#include <string.h>

int wn_nan_presence_write(const uint8_t tenant[16],const uint8_t device[16],
    const uint8_t mesh[8],bool tls_only,uint8_t out[WN_NAN_PRESENCE_SIZE])
{
    if(!tenant || !device || !mesh || !out)return -1;
    memcpy(out,"WNAN",4);out[4]=1;out[5]=1 | (tls_only ? 2:0);
    memcpy(out+6,tenant,16);memcpy(out+22,device,16);memcpy(out+38,mesh,8);
    return WN_NAN_PRESENCE_SIZE;
}
bool wn_nan_presence_read(const uint8_t tenant[16],const uint8_t mesh[8],
    const void *bytes,size_t size,struct wn_nan_hint *out)
{
    if(!tenant || !mesh || !bytes || !out)return false;
    const uint8_t *p=bytes;
    // IDF exposes the optional WFA generic service envelope; Linux strips it.
    if(size==WN_NAN_PRESENCE_SIZE+4 && !memcmp(p,"\x50\x6f\x9a\x00",4)){
        p+=4;size-=4;
    }
    if(size!=WN_NAN_PRESENCE_SIZE)return false;
    if(memcmp(p,"WNAN",4) || p[4]!=1 || (p[5]&~3) || !(p[5]&1) ||
       memcmp(p+6,tenant,16) || memcmp(p+38,mesh,8))return false;
    memcpy(out->device,p+22,16);out->tls_only=(p[5]&2)!=0;return true;
}
