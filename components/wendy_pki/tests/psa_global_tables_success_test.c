/* Ordinary baseline keys coexist with temporary mesh keys and mesh OFF. */
#include "wendy_net_alloc.h"
#include "wendy_pki_crypto.h"
#include <mbedtls/platform.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>
struct table {void *pointer;size_t bytes;bool mesh_origin,freed;};
static struct table tables[8];
static unsigned table_count;
static void *table_calloc(size_t count,size_t size)
{
    assert(table_count<8);
    wendy_net_memory_snapshot_t before,after;wendy_net_runtime_memory_snapshot(&before);
    void *pointer=wendy_pki_crypto_shared_calloc(count,size);assert(pointer);
    wendy_net_runtime_memory_snapshot(&after);
    assert(before.current_bytes==after.current_bytes && before.allocation_count==after.allocation_count);
    tables[table_count++]=(struct table){pointer,count*size,wendy_net_memory_scope_current().owner!=NULL,false};
    return pointer;
}
static void all_free(void *pointer)
{
    for(unsigned i=0;i<table_count;i++)if(pointer && tables[i].pointer==pointer && !tables[i].freed){tables[i].freed=true;break;}
    wendy_net_memory_scoped_free(pointer);
}
static psa_key_id_t import_key(unsigned value)
{
    uint8_t bytes[16];memset(bytes,(int)value,sizeof bytes);
    psa_key_attributes_t attributes=PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes,PSA_KEY_TYPE_AES);psa_set_key_bits(&attributes,128);
    psa_set_key_usage_flags(&attributes,PSA_KEY_USAGE_EXPORT);
    psa_key_id_t key=0;assert(psa_import_key(&attributes,bytes,sizeof bytes,&key)==PSA_SUCCESS);
    psa_reset_key_attributes(&attributes);return key;
}
static void usable(psa_key_id_t key,unsigned value)
{
    uint8_t bytes[16];size_t size=0;
    assert(psa_export_key(key,bytes,sizeof bytes,&size)==PSA_SUCCESS && size==sizeof bytes);
    for(unsigned i=0;i<size;i++)assert(bytes[i]==(uint8_t)value);
}
struct baseline_reader {psa_key_id_t key;atomic_bool stop;atomic_uint reads;};
static void *baseline_read(void *context)
{
    struct baseline_reader *reader=context;
    do{usable(reader->key,99);atomic_fetch_add(&reader->reads,1);}while(!atomic_load(&reader->stop));
    return NULL;
}
int main(void)
{
    /* Same universal prefix/free ABI as production; registration precedes all
     * PSA initialization. A normal late attempt cannot alter existing rows. */
    assert(!mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc,all_free));
    assert(mbedtls_psa_set_key_slot_table_allocator(table_calloc)==PSA_SUCCESS);
    assert(!wendy_pki_crypto_init());
    assert(mbedtls_psa_set_key_slot_table_allocator(table_calloc)==PSA_ERROR_BAD_STATE);
    psa_key_id_t baseline[8],temporary[17];
    for(unsigned i=0;i<8;i++)baseline[i]=import_key(i+1);
    assert(wendy_net_memory_open(wendy_net_runtime_memory_ledger(),2*1024*1024,true));
    wendy_net_memory_scope_t previous=wendy_net_runtime_scope_enter();
    for(unsigned i=0;i<17;i++)temporary[i]=import_key(i+30);
    unsigned extra=table_count-1;assert(tables[extra].mesh_origin && !tables[extra].freed);
    wendy_net_memory_scope_leave(previous);
    /* This baseline key occupies the same extra table that mesh caused to
     * grow. Its ID and bytes must survive OFF and every cleanup attempt. */
    psa_key_id_t live=import_key(99);
    struct baseline_reader reader={.key=live};pthread_t thread;
    assert(!pthread_create(&thread,NULL,baseline_read,&reader));
    while(!atomic_load(&reader.reads))sched_yield();
    for(unsigned i=0;i<17;i++)assert(psa_destroy_key(temporary[i])==PSA_SUCCESS);
    wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
    size_t freed=123;assert(mbedtls_psa_trim_empty_key_slots(&freed)==PSA_SUCCESS && !freed);
    for(unsigned i=0;i<100;i++)assert(mbedtls_psa_trim_empty_key_slots(&freed)==PSA_SUCCESS && !freed);
    atomic_store(&reader.stop,true);assert(!pthread_join(thread,NULL) && atomic_load(&reader.reads));
    assert(!tables[extra].freed);usable(live,99);
    for(unsigned i=0;i<8;i++){usable(baseline[i],i+1);assert(psa_destroy_key(baseline[i])==PSA_SUCCESS);}
    usable(live,99);assert(psa_destroy_key(live)==PSA_SUCCESS);
    assert(mbedtls_psa_trim_empty_key_slots(&freed)==PSA_SUCCESS && freed==tables[extra].bytes);
    assert(tables[extra].freed && wendy_net_runtime_memory_drained());
    /* A later normal mesh epoch reuses the retired slice index/free head. */
    assert(wendy_net_memory_open(wendy_net_runtime_memory_ledger(),2*1024*1024,true));
    previous=wendy_net_runtime_scope_enter();
    for(unsigned i=0;i<17;i++)temporary[i]=import_key(i+50);
    unsigned again=table_count-1;assert(again>extra && tables[again].mesh_origin);
    for(unsigned i=0;i<17;i++){usable(temporary[i],i+50);assert(psa_destroy_key(temporary[i])==PSA_SUCCESS);}
    wendy_net_memory_scope_leave(previous);wendy_net_runtime_memory_close();
    wendy_pki_crypto_cleanup();assert(tables[again].freed && wendy_net_runtime_memory_drained());
    printf("PSA shared tables preserve baseline keys/IDs through mesh OFF; empty extra table payload=%zu retired, no charged mesh remainder\n",freed);
    return 0;
}
