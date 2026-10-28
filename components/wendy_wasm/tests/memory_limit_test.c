#include "memory_limit.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static void fixture(const char *path,bool bounded,uint32_t expected)
{
    FILE *file=fopen(path,"rb");assert(file);assert(!fseek(file,0,SEEK_END));
    long length=ftell(file);assert(length>0);rewind(file);
    void *bytes=malloc((size_t)length);assert(bytes && fread(bytes,1,(size_t)length,file)==(size_t)length);fclose(file);
    uint32_t pages=999;char error[128]={0};
    assert(wendy_wasm_memory_limit(bytes,(size_t)length,96,0,&pages,error,sizeof error)==bounded);
    if(bounded)assert(pages==expected);
    assert(wendy_wasm_memory_limit(bytes,(size_t)length,0,0,&pages,error,sizeof error) && !pages);
    free(bytes);
}
static void boundaries(void)
{
    unsigned char wasm[]={0,0x61,0x73,0x6d,1,0,0,0,5,4,1,1,1,100};
    uint32_t pages=0;char error[128];
    assert(wendy_wasm_memory_limit(wasm,sizeof wasm,96,0,&pages,error,sizeof error) && pages==96);
    wasm[12]=97;
    assert(!wendy_wasm_memory_limit(wasm,sizeof wasm,96,0,&pages,error,sizeof error));
    wasm[12]=1;
    assert(wendy_wasm_memory_limit(wasm,sizeof wasm,96,16384,&pages,error,sizeof error) && pages==94);
    wasm[13]=1;
    assert(!wendy_wasm_memory_limit(wasm,sizeof wasm,1,1,&pages,error,sizeof error));
    assert(wendy_wasm_memory_limit(wasm,sizeof wasm,2,16384,&pages,error,sizeof error) && pages==1);
    /* AOT init-data section: coalesced pages count in bytes, never policy pages. */
    unsigned char aot[]={0,0x61,0x6f,0x74,4,0,0,0,1,0,0,0,24,0,0,0,
        0,0,0,0,1,0,0,0,0,0,0,0,0,0,96,0,1,0,0,0,1,0,0,0};
    assert(wendy_wasm_memory_limit(aot,sizeof aot,96,0,&pages,error,sizeof error) && pages==1);
    assert(!wendy_wasm_memory_limit(aot,sizeof aot,95,0,&pages,error,sizeof error));
    assert(!wendy_wasm_memory_limit(aot,sizeof aot,96,1,&pages,error,sizeof error));
    assert(wendy_wasm_memory_limit(NULL,0,0,0,&pages,error,sizeof error) && !pages);
    puts("linear memory admission boundaries and unchanged uncapped policy passed");
}
int main(int argc,char **argv)
{
    boundaries();
    if(argc==1)return 0;
    assert(argc==5);
    fixture(argv[1],true,96);
    fixture(argv[2],true,1);
    fixture(argv[3],false,0);
    fixture(argv[4],false,0);
    return 0;
}
