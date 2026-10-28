#include "memory_limit.h"
#include <stdio.h>
#include <string.h>

struct input {const unsigned char *bytes;size_t size,at;};
struct memory {uint64_t page_bytes,initial,maximum;unsigned count;};
static bool fail(char *out,size_t size,const char *message)
{if(out && size)snprintf(out,size,"%s",message);return false;}
static bool byte(struct input *in,unsigned *out)
{if(in->at>=in->size)return false;*out=in->bytes[in->at++];return true;}
static bool uleb(struct input *in,uint64_t *out)
{
    *out=0;
    for(unsigned shift=0;shift<64;shift+=7){
        unsigned b;if(!byte(in,&b) || (shift==63 && (b&0xfe)))return false;
        *out|=(uint64_t)(b&0x7f)<<shift;if(!(b&0x80))return true;
    }
    return false;
}
static bool u32(struct input *in,uint32_t *out)
{
    if(in->size-in->at<4)return false;
    const unsigned char *p=in->bytes+in->at;in->at+=4;
    *out=(uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
    return true;
}
static bool skip_name(struct input *in)
{uint64_t n;if(!uleb(in,&n) || n>in->size-in->at)return false;in->at+=(size_t)n;return true;}
static bool limits(struct input *in,struct memory *memory,bool retain)
{
    uint64_t flags,initial,maximum=65536;
    if(!uleb(in,&flags) || (flags&~UINT64_C(7)) || !uleb(in,&initial) ||
       ((flags&1) && !uleb(in,&maximum)))return false;
    if(retain){memory->count++;memory->page_bytes=65536;memory->initial=initial;memory->maximum=maximum;}
    return true;
}
static bool value_type(struct input *in)
{
    unsigned type;if(!byte(in,&type))return false;
    /* Typed reference encodings also carry a signed LEB heap-type index. */
    if(type==0x63 || type==0x64){
        for(unsigned n=0;n<5;n++){if(!byte(in,&type))return false;if(!(type&0x80))return true;}
        return false;
    }
    return true;
}
static bool wasm_memory(struct input input,struct memory *memory)
{
    input.at=8;
    while(input.at<input.size){
        unsigned section;uint64_t size;
        if(!byte(&input,&section) || !uleb(&input,&size) || size>input.size-input.at)return false;
        struct input part={input.bytes+input.at,(size_t)size,0};input.at+=(size_t)size;
        if(section!=2 && section!=5)continue;
        uint64_t count;if(!uleb(&part,&count))return false;
        for(uint64_t i=0;i<count;i++){
            if(section==5){if(!limits(&part,memory,true))return false;}
            else{
                unsigned kind;if(!skip_name(&part) || !skip_name(&part) || !byte(&part,&kind))return false;
                uint64_t ignored;unsigned attribute;
                switch(kind){
                case 0:if(!uleb(&part,&ignored))return false;break;
                case 1:if(!value_type(&part) || !limits(&part,memory,false))return false;break;
                case 2:if(!limits(&part,memory,true))return false;break;
                case 3:if(!value_type(&part) || !byte(&part,&attribute))return false;break;
                case 4:if(!byte(&part,&attribute) || !uleb(&part,&ignored))return false;break;
                default:return false;
                }
            }
            if(memory->count>1)return false;
        }
    }
    return true;
}
static bool aot_memory(struct input input,struct memory *memory)
{
    input.at=8;
    while(input.at<input.size){
        size_t padding=(4-input.at%4)%4;
        if(padding>input.size-input.at)return false;
        input.at+=padding;
        uint32_t section,size;
        if(!u32(&input,&section) || !u32(&input,&size) || size>input.size-input.at)return false;
        struct input part={input.bytes+input.at,size,0};input.at+=size;
        if(section!=1)continue; /* WAMR2.4 init-data section starts with memory info. */
        uint32_t imports,count,flags,page_bytes,initial,maximum;
        if(!u32(&part,&imports) || imports || !u32(&part,&count) || count>1)return false;
        memory->count=count;if(!count)return true;
        if(!u32(&part,&flags) || !u32(&part,&page_bytes) || !u32(&part,&initial) || !u32(&part,&maximum))return false;
        (void)flags;memory->page_bytes=page_bytes;memory->initial=initial;memory->maximum=maximum;
        return true;
    }
    return false;
}
bool wendy_wasm_memory_limit(const void *bytes,size_t size,uint32_t limit_pages,
    uint32_t host_heap_bytes,uint32_t *runtime_max_pages,char *error,size_t error_size)
{
    if(!runtime_max_pages)return false;
    *runtime_max_pages=0;
    if(!limit_pages)return true;
    if(!bytes || size<8)return fail(error,error_size,"cannot inspect linear memory");
    struct input input={bytes,size,0};struct memory memory={0};
    bool known=!memcmp(bytes,"\0asm",4) ? wasm_memory(input,&memory):
               !memcmp(bytes,"\0aot",4) ? aot_memory(input,&memory):false;
    if(!known)return fail(error,error_size,"bounded profile requires one inspectable linear memory");
    if(!memory.count){*runtime_max_pages=limit_pages;return true;}
    if(!memory.page_bytes || memory.maximum<memory.initial)
        return fail(error,error_size,"invalid linear memory dimensions");
    uint64_t cap=(uint64_t)limit_pages*65536;
    uint64_t pages=cap/memory.page_bytes;
    if(host_heap_bytes && memory.initial==1 && memory.maximum==1){
        /* WAMR appends host heap to one fixed page, changing its byte size. */
        if(memory.page_bytes>cap || host_heap_bytes>cap-memory.page_bytes)
            return fail(error,error_size,"linear memory plus host heap exceeds configured limit");
        pages=1;
    }else if(host_heap_bytes){
        /* Heap insertion can round to pages and retain a 1KiB tail guard. */
        uint64_t reserve=((uint64_t)host_heap_bytes+memory.page_bytes-1)/memory.page_bytes+1;
        pages=pages>reserve ? pages-reserve:0;
    }
    if(!pages || memory.initial>pages)
        return fail(error,error_size,"initial linear memory exceeds configured limit");
    if(pages>memory.maximum)pages=memory.maximum;
    if(pages>UINT32_MAX)pages=UINT32_MAX;
    *runtime_max_pages=(uint32_t)pages;
    return true;
}
