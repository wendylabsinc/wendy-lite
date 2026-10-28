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
int main(int argc,char **argv)
{
    assert(argc==5);
    fixture(argv[1],true,96); /* Six MiB bytecode uses96 standard pages. */
    fixture(argv[2],true,1);  /* Matching AOT uses one widened6MiB page. */
    fixture(argv[3],false,0); /* Old valid7.5MiB application exceeds resource quota. */
    fixture(argv[4],false,0); /* Its AOT one-page optimization cannot bypass byte cap. */
    puts("Six MiB bytecode/AOT admission and unchanged uncapped policy passed");
    return 0;
}
