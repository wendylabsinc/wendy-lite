/* Normal RAM-cache turnover, shared immutable loans and empty-off lifecycle. */
#include "../src/certificate_store.h"
#include "wendy_pki_crypto.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void fill(uint8_t *data,size_t size,unsigned generation,uint8_t hash[32])
{
    for(size_t j=0;j<size;j++)data[j]=(uint8_t)(generation+j*13);
    assert(!wendy_pki_sha256(data,size,hash));
}
int main(void)
{
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    assert(wendy_net_runtime_memory_open());
#endif
    struct wncs_store store;assert(!wncs_open_limits(&store,65536,32,4) && !store.bytes && !store.count);
    uint8_t data[6144],hashes[50][32];
    for(unsigned generation=0;generation<50;generation++){
        fill(data,sizeof data,generation,hashes[generation]);
        assert(!wncs_put(&store,hashes[generation],data,sizeof data));
        assert(store.bytes<=store.limit && store.count<=32);
    }
    assert(store.count==10);
    uint8_t part[WNCF_CHUNK];size_t total=0;
    assert(!wncs_read(&store,hashes[0],0,part,&total));
    assert(wncs_read(&store,hashes[49],1024,part,&total)==1 && total==sizeof data);
    assert(!memcmp(part,data+1024,sizeof part));
    struct wncf_chain chain={.count=3};
    strcpy(chain.principal,"spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/00000000-0000-4000-8000-000000000004");
    for(unsigned i=0;i<3;i++)memcpy(chain.hashes[i],hashes[47+i],32);
    assert(!wncs_chain_put(&store,&chain,10000));
    struct wncf_chain loaded;assert(wncs_chain_get(&store,chain.principal,1000,&loaded)==1);
    assert(loaded.count==chain.count && !memcmp(loaded.hashes,chain.hashes,chain.count*32));
    uint8_t *complete=NULL;size_t size=0;
    assert(wncs_load(&store,hashes[49],&complete,&size)==1 && size==sizeof data && !memcmp(complete,data,size));wendy_net_free(complete);
    uint8_t workspace[sizeof data+18];memset(workspace,0xa5,sizeof workspace);
    assert(wncs_load_into(&store,hashes[49],workspace+9,sizeof data,&size)==1);
    assert(size==sizeof data && !memcmp(workspace+9,data,sizeof data));
    for(unsigned i=0;i<9;i++)assert(workspace[i]==0xa5 && workspace[sizeof data+9+i]==0xa5);
    struct wncs_loan loan={0};assert(!wncs_pin_chain(&store,&chain,&loan) && loan.count==3);
    const uint8_t *last=loan.parts[2];assert(!memcmp(last,data,sizeof data));
    /* FIFO skips active verification/upload bytes while other generations turn. */
    for(unsigned generation=50;generation<100;generation++){
        uint8_t hash[32];fill(data,sizeof data,generation,hash);
        assert(!wncs_put(&store,hash,data,sizeof data));assert(store.bytes<=store.limit);
    }
    assert(wncs_read(&store,hashes[49],0,part,&total)==1);
    assert(!memcmp(part,last,sizeof part));
    /* Constrained verify-then-forget policy removes all idle DER/descriptors,
     * preserving active fetch/worker loans until their explicit release. */
    assert(wncs_trim(&store)>0 && store.count==3 && !store.chains);
    assert(!wncs_chain_get(&store,chain.principal,1000,&loaded));
    assert(wncs_read(&store,hashes[49],0,part,&total)==1);
    /* Off releases cache state, but a worker still owns its immutable loan. */
    wncs_close(&store);assert(!store.opened && !store.bytes && !store.count && !store.chains);
    fill(data,sizeof data,49,hashes[49]);assert(!memcmp(last,data,sizeof data));
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    wendy_net_runtime_memory_close();assert(!wendy_net_runtime_memory_drained());
#endif
    wncs_unpin(&loan);assert(!loan.count);
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    assert(wendy_net_runtime_memory_drained());assert(wendy_net_runtime_memory_open());
#endif
    /* New boot/session starts empty: no NVS read/write/recovery path exists. */
    assert(!wncs_open_limits(&store,8192,2,2));assert(!wncs_read(&store,hashes[49],0,NULL,&total));
    assert(!wncs_put(&store,hashes[49],data,sizeof data));
    assert(!wncs_pin_part(&store,hashes[49],&loan));
    uint8_t next_hash[32];fill(data,sizeof data,100,next_hash);
    assert(wncs_put(&store,next_hash,data,sizeof data)==1); /* normal pressure: pinned cache cannot grow */
    wncs_unpin(&loan);assert(!wncs_put(&store,next_hash,data,sizeof data));
    assert(!wncs_read(&store,hashes[49],0,NULL,&total));
    assert(!wncs_pin_part(&store,next_hash,&loan));
    assert(!wncs_chain_put(&store,&chain,10000));
    assert(wncs_trim(&store)>0 && store.count==1 && !store.chains);
    wncs_unpin(&loan);assert(wncs_trim(&store)>0 && !store.bytes && !store.count);
    assert(!wncs_read(&store,next_hash,0,NULL,&total));wncs_close(&store);
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
#endif
    puts("Public peer DER and descriptors stay in bounded RAM; active loans survive cache close");return 0;
}
