/* Production partition loader and byte-release helper, with bounded SDK edges. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef int esp_err_t;
typedef unsigned esp_partition_mmap_handle_t;
typedef struct {uint32_t size;} esp_partition_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_STATE -2
#define ESP_ERR_INVALID_ARG -3
#define ESP_ERR_NOT_FOUND -4
#define ESP_ERR_INVALID_SIZE -5
#define ESP_ERR_NO_MEM -6
#define ESP_PARTITION_TYPE_DATA 1
#define ESP_PARTITION_MMAP_INST 2
#define MALLOC_CAP_INTERNAL 1
#define MALLOC_CAP_8BIT 2
#define CONFIG_WENDY_WASM_AOT_XIP 1
#define CONFIG_WENDY_WASM_PREFER_RTC_RAM 0
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define WENDY_WASM_STATE_LOADED 1
struct wendy_wasm_module {
    void *wasm_module,*module_inst,*exec_env;
    unsigned state;
    uint8_t *wasm_buf;
    uint32_t wasm_len;
    esp_partition_mmap_handle_t flash_mapping;
    bool mapped;
};
typedef struct wendy_wasm_module *wendy_wasm_module_handle_t;
static bool s_initialized=true;
static struct {uint32_t stack_size;} s_config;
static esp_partition_t partition={128};
static uint32_t binary[32]={16};
static bool map_failure,xip;
static unsigned fail_stage,allocated,mapped,loaded,instantiated,executions,reads;
static const esp_partition_t *esp_partition_find_first(int type,int subtype,const char *label)
{(void)type;(void)subtype;return label ? &partition:NULL;}
static int esp_partition_read(const esp_partition_t *p,unsigned offset,void *out,size_t len)
{assert(p==&partition && offset+len<=p->size);reads++;memcpy(out,(char *)binary+offset,len);return ESP_OK;}
static int esp_partition_mmap(const esp_partition_t *p,unsigned offset,size_t len,int kind,const void **out,unsigned *handle)
{assert(p==&partition && !offset && kind==ESP_PARTITION_MMAP_INST && len<=p->size);if(map_failure)return ESP_FAIL;*out=binary;*handle=7;mapped++;return ESP_OK;}
static void esp_partition_munmap(unsigned handle) {assert(handle==7 && mapped);mapped--;}
static bool wasm_runtime_is_xip_file(void *bytes,uint32_t size)
{assert(bytes==(char *)binary+4 && size==16);return xip;}
static void *wasm_runtime_malloc(size_t size)
{if(fail_stage==1)return NULL;void *p=malloc(size);assert(p);allocated++;return p;}
static void wasm_runtime_free(void *p) {assert(p && allocated);allocated--;free(p);}
static void *wasm_runtime_load(void *bytes,uint32_t size,char *error,size_t n)
{(void)error;(void)n;assert(bytes && size==16);if(fail_stage==2)return NULL;loaded++;return (void *)1;}
static void wasm_runtime_unload(void *p) {assert(p==(void *)1 && loaded);assert(mapped || allocated);loaded--;}
static void *instantiate(struct wendy_wasm_module *m,char *error,uint32_t n)
{(void)error;(void)n;assert(m->wasm_module==(void *)1);if(fail_stage==3)return NULL;instantiated++;return (void *)2;}
static void wasm_runtime_deinstantiate(void *p) {assert(p==(void *)2 && instantiated);assert(mapped || allocated);instantiated--;}
static void *wasm_runtime_create_exec_env(void *p,uint32_t size)
{(void)size;assert(p==(void *)2);if(fail_stage==4)return NULL;executions++;return (void *)3;}
static void wasm_runtime_destroy_exec_env(void *p) {assert(p==(void *)3 && executions);executions--;}
#include "partition_loader_production.inc"
static void drain(wendy_wasm_module_handle_t mod)
{
    wasm_runtime_destroy_exec_env(mod->exec_env);
    wasm_runtime_deinstantiate(mod->module_inst);
    wasm_runtime_unload(mod->wasm_module);
    release_module_bytes(mod);free(mod);
}
int main(void)
{
    /* Mapped XIP, ordinary bytecode, and unavailable instruction mapping. */
    for(unsigned mode=0;mode<3;mode++)for(fail_stage=0;fail_stage<=4;fail_stage++){
        xip=mode==0;map_failure=mode==2;reads=0;
        wendy_wasm_module_handle_t out=NULL;
        int result=wendy_wasm_load_from_partition("wasm_a",&out);
        bool succeeds=!fail_stage || (xip && fail_stage==1);
        assert((result==ESP_OK)==succeeds);
        if(succeeds){assert(out && out->mapped==xip);assert(reads==(xip ? 1:2));drain(out);}
        else assert(!out);
        assert(!allocated && !mapped && !loaded && !instantiated && !executions);
    }
    fail_stage=0;partition.size=3;
    /* Too-small partitions are rejected before the length read. */
    wendy_wasm_module_handle_t out=NULL;reads=0;
    assert(wendy_wasm_load_from_partition("wasm_a",&out)==ESP_ERR_INVALID_SIZE);
    assert(!reads);
    puts("partition loader PASS: XIP/writable fallback, map failure, allocation/load/instantiate/exec failure lifetimes");
}
