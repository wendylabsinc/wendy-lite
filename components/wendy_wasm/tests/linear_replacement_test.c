#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tlsf.h"
#include "linear_replacement.h"

typedef uint8_t uint8;
typedef uint64_t uint64;
#define WASM_MEM_DUAL_BUS_MIRROR 0
#define WASM_MEM_ALLOC_WITH_USAGE 0
#define WASM_ENABLE_SHARED_MEMORY 0
#define BH_PLATFORM_ESP_IDF 1
#define GET_MAX_LINEAR_MEMORY_SIZE(ignored) UINT32_MAX
#define BHT_ERROR (-1)
#define BHT_OK 0
#define MALLOC_CAP_8BIT 1
#define MMAP_PROT_NONE 0
#define MMAP_PROT_READ 1
#define MMAP_PROT_WRITE 2
#define MMAP_PROT_EXEC 4
#define MMAP_MAP_NONE 0
#define bh_assert assert
#define align_as_and_cast(value,alignment) (((value)+(alignment)-1)&~((uint64)(alignment)-1))
typedef int os_file_handle;
typedef struct {
    uint8 *memory_data;
    uint64 memory_data_size, num_bytes_per_page, cur_page_count, max_page_count;
} WASMMemoryInstance;

bool tlsf_check_hook(void *start,size_t size,bool is_free)
{ (void)start;(void)size;(void)is_free;return true; }
void block_absorb_post_hook(void *start,size_t size,bool is_free)
{ (void)start;(void)size;(void)is_free; }

static tlsf_t heap;
static unsigned allocations, releases;
static size_t last_request;
static void *heap_caps_malloc(size_t size, unsigned caps)
{
    (void)caps;
    last_request = size;
    void *p = tlsf_malloc(heap, size);
    if(p) allocations++;
    return p;
}
static void fixture_free(void *p) { if(p){ releases++; tlsf_free(heap,p); } }
static int os_getpagesize(void) { return 4096; }
static int os_get_invalid_handle(void) { return -1; }
static int os_mprotect(void *p,size_t n,int prot) { (void)p;(void)n;(void)prot;return 0; }
static void *os_mremap(void *p,size_t old,size_t n) { (void)p;(void)old;(void)n;abort(); }
static void os_free(void *);
static void *wasm_mmap_linear_memory(uint64,uint64);
#define free fixture_free
#include "linear_production.inc"
#undef free

static WASMMemoryInstance mapping(size_t bytes)
{
    WASMMemoryInstance m = {.num_bytes_per_page=bytes,.cur_page_count=1,.max_page_count=1};
    assert(wasm_allocate_linear_memory(&m.memory_data,false,false,bytes,1,1,&m.memory_data_size)==BHT_OK);
    return m;
}
static size_t largest_raw;
static bool walk(void *p,size_t n,int used,void *context)
{
    (void)p;(void)context;
    if(!used && n>largest_raw)largest_raw=n;
    return true;
}
static size_t largest(void)
{
    largest_raw=0;tlsf_walk_pool(tlsf_get_pool(heap),walk,NULL);
    return tlsf_fit_size(heap,largest_raw);
}
static void *tail_blocks[64];
static unsigned tail_count;
static void occupy_tail(void)
{
    while(largest()>=2048){
        assert(tail_count<64);
        tail_blocks[tail_count]=heap_caps_malloc(largest(),1);
        assert(tail_blocks[tail_count]);tail_count++;
    }
}
static void release_tail(void)
{
    while(tail_count)fixture_free(tail_blocks[--tail_count]);
}
static void dispose(WASMMemoryInstance *m) { wasm_deallocate_linear_memory(m);assert(!m->memory_data); }

#include "core_replacement_lifecycle.inc"

int main(void)
{
    const size_t five=5*1024*1024, pool_bytes=8*1024*1024;
    void *pool=malloc(pool_bytes);assert(pool);
    heap=tlsf_create_with_pool(pool,pool_bytes,0);assert(heap);

    /* Baseline direct free/reallocation succeeds: the allocator already paid
     * for the rounded backing. Small metadata then makes that old hole unfit. */
    WASMMemoryInstance old=mapping(five);
    const size_t backing=tlsf_block_size((uintptr_t *)old.memory_data-1);
    assert(last_request==five+4+sizeof(uintptr_t));
    assert(backing==five+128*1024);
    occupy_tail();
    dispose(&old);
    old=mapping(five); /* Same untouched hole succeeds. */
    dispose(&old);
    void *metadata=heap_caps_malloc(2048,1);assert(metadata);
    assert(largest()==five);
    WASMMemoryInstance failed={0};
    assert(wasm_allocate_linear_memory(&failed.memory_data,false,false,five,1,1,&failed.memory_data_size)==BHT_ERROR);
    fixture_free(metadata);release_tail();

    old=mapping(five);memset(old.memory_data,0xa5,five);
    occupy_tail();
    void *old_base=old.memory_data;
    uint32_t generation=wwlr_begin(old_base);assert(generation);
    assert(!wwlr_begin(old_base));
    unsigned before=releases;
    dispose(&old);assert(releases==before); /* Mapping remains owned, no hole. */
    /* Ordinary metadata has a small separate budget during replacement. */
    unsigned tail_releases=tail_count;
    release_tail();
    metadata=heap_caps_malloc(2048,1);assert(metadata);
    unsigned alloc_before=allocations;
    WASMMemoryInstance next=mapping(five);
    assert(next.memory_data==old_base && allocations==alloc_before);
    for(size_t i=0;i<five;i++)assert(next.memory_data[i]==0);
    wwlr_finish(generation);assert(releases==before+tail_releases); /* Only tail was freed. */
    dispose(&next);fixture_free(metadata);

    /* A smaller app releases the old retained mapping before ordinary alloc. */
    old=mapping(five);generation=wwlr_begin(old.memory_data);assert(generation);dispose(&old);
    before=releases;next=mapping(64*1024);assert(releases==before+1);
    wwlr_finish(generation);dispose(&next);

    /* Reinit/load failure before reuse and instantiate failure after reuse. */
    old=mapping(five);generation=wwlr_begin(old.memory_data);dispose(&old);
    before=releases;wwlr_finish(generation+1);assert(releases==before);
    wwlr_finish(generation);assert(releases==before+1);
    old=mapping(five);generation=wwlr_begin(old.memory_data);dispose(&old);
    next=mapping(five);dispose(&next);before=releases;
    wwlr_finish(generation);assert(releases==before); /* No double release. */

    /* A previous grow/move leaves only the CURRENT base eligible. */
    old=mapping(64*1024);memset(old.memory_data,0x37,64*1024);
    WASMMemoryInstance grown=mapping(128*1024);
    memcpy(grown.memory_data,old.memory_data,64*1024);dispose(&old);
    old_base=grown.memory_data;generation=wwlr_begin(old_base);dispose(&grown);
    next=mapping(128*1024);assert(next.memory_data==old_base);
    for(size_t i=0;i<128*1024;i++)assert(next.memory_data[i]==0);
    wwlr_finish(generation);dispose(&next);

    /* Generic/executable mappings and unrelated linear frees never transfer. */
    old=mapping(five);generation=wwlr_begin(old.memory_data);
    WASMMemoryInstance other=mapping(4096);before=releases;dispose(&other);
    assert(releases==before+1);wwlr_finish(generation);dispose(&old);
    void *generic=os_mmap(NULL,4096,0,0,0);assert(generic);
    before=releases;os_munmap(generic,4096);assert(releases==before+1);
    assert(os_mmap(NULL,4096,MMAP_PROT_EXEC,0,0)==NULL);
    assert(allocations==releases);core_replacement_lifecycle();assert(tlsf_check(heap)==0);
    printf("linear replacement PASS: 5MiB backing=%zu largest-after-metadata=%zu; zeroed single transfer, shrink/failure/baseline/final release\n",backing,five);
    tlsf_destroy(heap);free(pool);
    return 0;
}
