#include "wendy_roughtime.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t read_file(const char *dir, const char *name, unsigned char *buffer, size_t max)
{
    char path[1024]; snprintf(path,sizeof path,"%s/%s",dir,name);
    FILE *f=fopen(path,"rb"); assert(f);
    size_t n=fread(buffer,1,max,f); assert(!ferror(f)); assert(fgetc(f)==EOF); fclose(f); return n;
}
int main(int argc,char **argv)
{
    assert(argc==2); uint8_t key[32], nonce[32], response[4096], expected[1024], request[1024];
    assert(read_file(argv[1],"key.bin",key,32)==32);
    assert(read_file(argv[1],"nonce.bin",nonce,32)==32);
    size_t n=read_file(argv[1],"valid.bin",response,sizeof response);
    struct wendy_rt_interval out;
    assert(!wendy_rt_verify(response,n,nonce,key,&out));
    assert(out.lower==1799999999000000LL && out.upper==1800000001000000LL);
    for (size_t i=0;i<n;i++) assert(wendy_rt_verify(response,i,nonce,key,&out));
    key[0]^=1; assert(wendy_rt_verify(response,n,nonce,key,&out)); key[0]^=1;
    nonce[0]^=1; assert(wendy_rt_verify(response,n,nonce,key,&out)); nonce[0]^=1;
    const char *bad[]={"bad-signature.bin","bad-delegation.bin","bad-path.bin","bad-index.bin",
                       "bad-radius.bin","bad-midpoint.bin","bad-offset.bin","bad-version.bin","bad-nonce.bin"};
    for (size_t i=0;i<sizeof bad/sizeof bad[0];i++) {
        n=read_file(argv[1],bad[i],response,sizeof response);
        assert(wendy_rt_verify(response,n,nonce,key,&out));
    }
    wendy_rt_request(request,nonce,key);
    assert(read_file(argv[1],"request.bin",expected,sizeof expected)==1024);
    assert(!memcmp(request,expected,1024));
    struct wendy_rt_interval v[4]={{10,20},{15,25},{100,120},{110,130}};
    assert(wendy_rt_consensus(v,1,&out));
    assert(!wendy_rt_consensus(v,3,&out) && out.lower==15 && out.upper==20);
    assert(wendy_rt_consensus(v,5,&out));
    assert(wendy_rt_consensus(v,15,&out)); /* Two disjoint quorums are ambiguous. */
    v[2]=(struct wendy_rt_interval){16,19};
    assert(!wendy_rt_consensus(v,15,&out) && out.lower==16 && out.upper==19);
    assert(wendy_rt_find_server("roughtime.cloudflare.com:2003")==0);
    assert(wendy_rt_find_server("roughtime.int08h.com:2002")==1);
    assert(wendy_rt_find_server("time.txryan.com:2002")==3);
    const char *unpinned[]={"roughtime.cloudflare.com:2002","roughtime.cloudflare.com:20030",
                            "roughtime.cloudflare.com:","roughtime.cloudflare.com","roughtime.cloudflare","",
                            "roughtime.cloudflare.comX2003","xroughtime.cloudflare.com:2003"};
    for (size_t i=0;i<sizeof unpinned/sizeof unpinned[0];i++) assert(wendy_rt_find_server(unpinned[i])<0);
    puts("Roughtime signatures, nonce binding, framing, bounds, quorum and server pins verified");
    return 0;
}
