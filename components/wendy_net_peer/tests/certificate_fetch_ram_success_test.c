/* Normal fetched chain remains stable while the surrounding FIFO turns over. */
#include "../src/certificate_store.h"
#include "wendy_pki_crypto.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct baseline {const uint8_t *bytes,*hash;size_t size;bool busy;};
static int own_part(void *context,const uint8_t hash[32],size_t offset,uint8_t out[1024],size_t *total)
{
    struct baseline *own=context;if(own->busy)return -2;
    if(memcmp(hash,own->hash,32))return 0;
    *total=own->size;if(!out)return 1;
    assert(offset<own->size);size_t n=own->size-offset;if(n>1024)n=1024;memcpy(out,own->bytes+offset,n);return 1;
}
int main(void)
{
    assert(wendy_net_runtime_memory_open());struct wncs_store store;
    assert(!wncs_open_limits(&store,8192,8,2));
    struct wncf_store storage={.context=&store,.read=wncs_read,.put=wncs_put,.retain=wncs_retain,.release=wncs_release};
    struct wncf_chain chain={.count=3};strcpy(chain.principal,"spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/00000000-0000-4000-8000-000000000004");
    uint8_t data[3][1500];for(unsigned i=0;i<3;i++){
        for(size_t j=0;j<sizeof data[i];j++)data[i][j]=(uint8_t)(j*13+i);
        assert(!wendy_pki_sha256(data[i],sizeof data[i],chain.hashes[i]));
    }
    struct baseline own={.bytes=data[0],.hash=chain.hashes[0],.size=sizeof data[0]};
    wncs_set_baseline(&store,&own,own_part);
    assert(!wncs_put(&store,chain.hashes[0],data[0],sizeof data[0]) && !store.count);
    struct wncf_fetch fetch={0};assert(!wncf_start(&fetch,&chain,0));
    int64_t now=1;unsigned churn=0;
    own.busy=true;struct wncf_request waiting;
    assert(!wncf_next(&fetch,&storage,now++,&waiting) && !fetch.index);own.busy=false;
    for(;;){
        struct wncf_request request;int result=wncf_next(&fetch,&storage,now++,&request);assert(result==1 || result==2);
        if(result==2)break;
        unsigned index=fetch.index;assert(index>0 && index<3);wncf_sent(&fetch,now++);
        size_t n=sizeof data[index]-request.offset;if(n>WNCF_CHUNK)n=WNCF_CHUNK;
        assert(!wncf_receive(&fetch,&storage,request.hash,request.offset,sizeof data[index],data[index]+request.offset,n,now++));
        /* New unrelated public entries would evict the first chain part if
         * fetch had not retained it. Bounded FIFO still admits other traffic. */
        for(unsigned j=0;j<4;j++){
            uint8_t unrelated[700],hash[32];memset(unrelated,(int)++churn,sizeof unrelated);
            assert(!wendy_pki_sha256(unrelated,sizeof unrelated,hash));assert(!wncs_put(&store,hash,unrelated,sizeof unrelated));
            assert(store.bytes<=store.limit);
        }
    }
    struct wncs_loan job={0};assert(!wncs_pin_chain(&store,&chain,&job));
    wncf_stop(&fetch);assert(!wncf_memory(&fetch));wncs_close(&store);
    wendy_net_runtime_memory_close();assert(!wendy_net_runtime_memory_drained());
    assert(!job.parts[0] && job.sizes[0]==sizeof data[0]); /* independent worker resolves own baseline */
    for(unsigned i=1;i<3;i++)assert(job.sizes[i]==sizeof data[i] && !memcmp(job.parts[i],data[i],sizeof data[i]));
    wncs_unpin(&job);assert(wendy_net_runtime_memory_drained());
    puts("Fetch pins reused and downloaded DER during FIFO turnover, then hands immutable bytes to verification");return 0;
}
