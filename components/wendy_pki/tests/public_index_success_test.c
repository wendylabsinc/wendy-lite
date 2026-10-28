/* Normal identity turnover, RAM-only size queries and independent loans. */
#include "wendy_pki_public_index.h"
#include "wendy_pki_crypto.h"
#include "../../wendy_net_peer/src/certificate_store.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint64_t current_generation=10;
static bool resetting;
bool wendy_conf_snapshot_current(uint64_t generation)
{return generation==current_generation;}
bool wendy_pki_reset_in_progress(void){return resetting;}
struct baseline {
    struct wendy_pki_mesh_identity clock;
    unsigned reads;
    uint8_t bytes[4096];
};
static bool current(void *context,const struct wendy_pki_mesh_public_index *index)
{return wendy_pki_mesh_public_index_current(index,&((struct baseline *)context)->clock);}
static int read_part(void *context,const uint8_t hash[32],size_t offset,
    uint8_t out[1024],size_t *total)
{
    (void)hash;struct baseline *source=context;
    source->reads++;
    /* Availability must never reach this stand-in for the NVS/DER reader. */
    assert(out && offset<sizeof source->bytes);
    *total=sizeof source->bytes;
    size_t n=*total-offset;if(n>1024)n=1024;
    memcpy(out,source->bytes+offset,n);return 1;
}
static void set_index(struct wendy_pki_mesh_public_index *index,
    struct baseline *source,size_t size)
{
    *index=(struct wendy_pki_mesh_public_index){.count=1,
        .certificate_epoch=pki_public_certificate_epoch(),
        .config_generation=current_generation};
    index->sizes[0]=(uint32_t)size;
    assert(!wendy_pki_sha256(source->bytes,size,index->hashes[0]));
    source->clock.config_generation=current_generation;
}
int main(void)
{
    assert(wendy_net_runtime_memory_open());
    struct wncs_store *store=wendy_net_calloc(1,sizeof *store);assert(store);
    assert(!wncs_open_limits(store,8192,2,2));
    struct baseline source={0};
    for(unsigned i=0;i<sizeof source.bytes;i++)source.bytes[i]=(uint8_t)i;
    struct wendy_pki_mesh_public_index index;
    set_index(&index,&source,sizeof source.bytes);
    wncs_set_baseline(store,&source,read_part);
    wncs_set_baseline_index(store,&index,current);
    size_t size=0;
    for(unsigned i=0;i<10;i++){
        assert(wncs_read(store,index.hashes[0],0,NULL,&size)==1 && size==sizeof source.bytes);
        void *retained=wncs_retain(store,index.hashes[0]);assert(retained);wncs_release(retained);
    }
    struct wncf_chain chain={.count=1};memcpy(chain.hashes[0],index.hashes[0],32);
    struct wncs_loan loan={0};assert(!wncs_pin_chain(store,&chain,&loan));
    assert(loan.count==1 && !loan.parts[0] && loan.sizes[0]==sizeof source.bytes);
    assert(!wncs_put(store,index.hashes[0],source.bytes,sizeof source.bytes));
    assert(!store->count && !source.reads);
    uint8_t absent[32]={0},out[1024];
    assert(!wncs_read(store,absent,0,NULL,&size) && !source.reads);
    assert(wncs_read(store,index.hashes[0],1024,out,&size)==1 && source.reads==1);
    assert(!memcmp(out,source.bytes+1024,sizeof out));
    /* Configuration change and same-generation certificate renewal both
     * retire old availability immediately, without consulting storage. */
    current_generation++;
    assert(!wncs_read(store,index.hashes[0],0,NULL,&size));
    source.clock.config_generation=current_generation;
    assert(!wncs_read(store,index.hashes[0],0,NULL,&size));
    set_index(&index,&source,3072);wncs_set_baseline_index(store,&index,current);
    assert(wncs_read(store,index.hashes[0],0,NULL,&size)==1 && size==3072);
    pki_public_certificate_changed();
    assert(!wncs_read(store,index.hashes[0],0,NULL,&size));
    set_index(&index,&source,2048);wncs_set_baseline_index(store,&index,current);
    assert(wncs_read(store,index.hashes[0],0,NULL,&size)==1 && size==2048);
    resetting=true;assert(!wncs_read(store,index.hashes[0],0,NULL,&size));resetting=false;
    /* An unavailable metadata snapshot remains a RAM miss, with no legacy
     * fallback to a size-only NVS query. */
    wncs_set_baseline_index(store,NULL,current);
    assert(!wncs_read(store,index.hashes[0],0,NULL,&size) && source.reads==1);
    wncs_close(store);wendy_net_free(store);
    wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
    /* Loan stores copied metadata, not a pointer into the retired store. */
    assert(loan.sizes[0]==4096);wncs_unpin(&loan);
    printf("Own public index: %zu bytes/store; normal availability has zero DER/NVS reads; off drains\n",sizeof index);
    return 0;
}
