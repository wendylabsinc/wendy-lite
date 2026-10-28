#include "wasm_export.h"
#include "memory_limit.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv)
{
    (void)argc;(void)argv;
    /* (module (memory 1) (func (export "grow_by") (param i32) (result i32)
     *   local.get 0 memory.grow)) -- mutable because WAMR's loader owns edits. */
    unsigned char fixture[]={0,0x61,0x73,0x6d,1,0,0,0,
        1,6,1,0x60,1,0x7f,1,0x7f,3,2,1,0,5,3,1,0,1,
        7,11,1,7,'g','r','o','w','_','b','y',0,0,
        10,8,1,6,0,0x20,0,0x40,0,0x0b};
    size_t size=sizeof fixture;unsigned char *bytes=malloc(size);assert(bytes);
    memcpy(bytes,fixture,size);
    RuntimeInitArgs initialization={.mem_alloc_type=Alloc_With_System_Allocator};
    assert(wasm_runtime_full_init(&initialization));
    char error[128]={0};uint32_t max_pages;
    assert(wendy_wasm_memory_limit(bytes,(size_t)size,96,0,&max_pages,error,sizeof error));
    assert(max_pages==96);
    wasm_module_t module=wasm_runtime_load(bytes,(uint32_t)size,error,sizeof error);assert(module);
    assert(wendy_wasm_memory_limit(bytes,(size_t)size,96,0,&max_pages,error,sizeof error) && max_pages==96);
    InstantiationArgs arguments={.default_stack_size=16384,.host_managed_heap_size=0,.max_memory_pages=max_pages};
    wasm_module_inst_t instance=wasm_runtime_instantiate_ex(module,&arguments,error,sizeof error);assert(instance);
    wasm_exec_env_t execution=wasm_runtime_create_exec_env(instance,16384);assert(execution);
    wasm_function_inst_t grow=wasm_runtime_lookup_function(instance,"grow_by");assert(grow);
    wasm_memory_inst_t memory=wasm_runtime_get_memory(instance,0);assert(memory);
    assert(wasm_memory_get_cur_page_count(memory)==1 && wasm_memory_get_max_page_count(memory)==96);
    uint32_t parameters[1]={95};
    assert(wasm_runtime_call_wasm(execution,grow,1,parameters) && parameters[0]==1);
    assert(wasm_memory_get_cur_page_count(memory)==96);
    parameters[0]=1;
    assert(wasm_runtime_call_wasm(execution,grow,1,parameters) && parameters[0]==UINT32_MAX);
    assert(wasm_memory_get_cur_page_count(memory)==96);
    wasm_runtime_destroy_exec_env(execution);wasm_runtime_deinstantiate(instance);
    /* Host-managed heap insertion is inside the same byte ceiling too. */
    assert(wendy_wasm_memory_limit(bytes,(size_t)size,96,16384,&max_pages,error,sizeof error));
    arguments.host_managed_heap_size=16384;arguments.max_memory_pages=max_pages;
    instance=wasm_runtime_instantiate_ex(module,&arguments,error,sizeof error);assert(instance);
    memory=wasm_runtime_get_memory(instance,0);assert(memory);
    uint64_t maximum=wasm_memory_get_max_page_count(memory),current=wasm_memory_get_cur_page_count(memory);
    assert(maximum*wasm_memory_get_bytes_per_page(memory)<=UINT64_C(96)*65536);
    execution=wasm_runtime_create_exec_env(instance,16384);assert(execution);
    grow=wasm_runtime_lookup_function(instance,"grow_by");assert(grow);
    parameters[0]=(uint32_t)(maximum-current);
    assert(wasm_runtime_call_wasm(execution,grow,1,parameters) && parameters[0]==current);
    parameters[0]=1;
    assert(wasm_runtime_call_wasm(execution,grow,1,parameters) && parameters[0]==UINT32_MAX);
    wasm_runtime_destroy_exec_env(execution);wasm_runtime_deinstantiate(instance);wasm_runtime_unload(module);
    wasm_runtime_destroy();free(bytes);
    puts("Actual WAMR memory.grow obeys byte ceiling with and without host heap");
    return 0;
}
