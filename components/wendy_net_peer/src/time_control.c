#include "wendy_net_alloc.h"
#include "time_control.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct wnt_job *wnt_new(uint64_t id,const void *query,size_t size,int64_t deadline)
{
    if(!id || !query || !size || size>128)return NULL;
    struct wnt_job *job=wendy_net_calloc(1,sizeof *job);if(!job)return NULL;
    atomic_init(&job->references,1);atomic_init(&job->done,false);
    job->id=id;job->deadline=deadline;job->query_size=size;job->result=-1;
    memcpy(job->query,query,size);return job;
}
void wnt_retain(struct wnt_job *job){atomic_fetch_add(&job->references,1);}
void wnt_release(struct wnt_job *job)
{if(job && atomic_fetch_sub(&job->references,1)==1){if(job->reply_external)free(job->reply);else wendy_net_free(job->reply);
#if ESP_PLATFORM
    wendy_net_memory_release(&job->reply_charge);
#endif
    wendy_net_free(job);}}
int wnt_request_write(const struct wnt_job *job,char *out,size_t cap)
{
    if(!job || !out)return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,"time");wn_key(&w,"time");wn_map(&w,3);
    wn_key(&w,"id");wn_uint(&w,job->id);wn_key(&w,"op");wn_text(&w,job->offset ? "next":"request");
    if(job->offset){wn_key(&w,"offset");wn_uint(&w,job->offset);}
    else {wn_key(&w,"data");wn_bytes(&w,job->query,job->query_size);}
    return wn_finish(&w);
}
int wnt_reply_write(const struct wnt_job *job,char *out,size_t cap)
{
    if(!job || !out)return -1;
    size_t size=job->size-job->offset;if(size>1024)size=1024;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,"time");wn_key(&w,"time");wn_map(&w,job->result ? 2:5);
    wn_key(&w,"id");wn_uint(&w,job->id);wn_key(&w,"op");wn_text(&w,job->result ? "error":"reply");
    if(!job->result){
        wn_key(&w,"data");wn_bytes(&w,job->reply+job->offset,size);
        wn_key(&w,"total");wn_uint(&w,job->size);wn_key(&w,"offset");wn_uint(&w,job->offset);
    }
    return wn_finish(&w);
}
static int number(const struct wn_doc *doc,unsigned at,const char *key,uint64_t *out)
{return wn_doc_u64(doc,wn_doc_member(doc,at,key),out);}
static int decoded(const struct wn_doc *doc,unsigned at,uint8_t *out,size_t cap,size_t *size)
{
    return wn_doc_copy_bytes(doc,wn_doc_member(doc,at,"data"),out,cap,size);
}
struct wnt_job *wnt_request_read(const struct wn_doc *doc,unsigned at,int64_t deadline)
{
    uint64_t id;uint8_t bytes[128];size_t size;
    if(number(doc,at,"id",&id) || decoded(doc,at,bytes,sizeof bytes,&size))return NULL;
    return wnt_new(id,bytes,size,deadline);
}
int wnt_reply_read(struct wnt_job *job,const struct wn_doc *doc,unsigned at)
{
    uint64_t id,total,offset;uint8_t bytes[1024];size_t size;
    if(number(doc,at,"id",&id))return -1;
    if(id!=job->id || atomic_load(&job->done))return 0;
    if(wn_doc_equal(doc,wn_doc_member(doc,at,"op"),"error")){
        job->result=-1;atomic_store(&job->done,true);return 0;
    }
    if(number(doc,at,"total",&total) || !total || total>65536 ||
       number(doc,at,"offset",&offset) || offset!=job->offset ||
       decoded(doc,at,bytes,sizeof bytes,&size) || !size || offset+size>total ||
       (job->reply && total!=job->size))return -1;
    if(!job->reply){job->reply=wendy_net_malloc((size_t)total);if(!job->reply)return -1;job->size=(size_t)total;}
    memcpy(job->reply+offset,bytes,size);job->offset+=size;
    job->sent=false;
    if(job->offset==job->size){job->result=0;atomic_store(&job->done,true);}
    return 0;
}
