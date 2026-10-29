/* SPDX-License-Identifier: Apache-2.0 */
#include "certificate_fetch.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_crypto.h"
#include <stdlib.h>
#include <string.h>

struct wncf_hold {void *parts[WNCF_CHAIN_MAX];void (*release)(void *);};
static int retain_part(struct wncf_fetch *f,const struct wncf_store *store,unsigned index)
{
    if(!store->retain)return 0;
    if(!f->hold || !store->release)return -1;
    if(!f->hold->parts[index])f->hold->parts[index]=store->retain(store->context,f->chain->hashes[index]);
    return f->hold->parts[index] ? 0:1;
}
void wncf_stop(struct wncf_fetch *f)
{
    if(!f)return;
    if(f->hold){
        for(unsigned i=0;i<WNCF_CHAIN_MAX;i++)if(f->hold->parts[i])f->hold->release(f->hold->parts[i]);
        wendy_net_free(f->hold);
    }
    wendy_net_free(f->bytes);wendy_net_free(f->chain);memset(f,0,sizeof *f);
}
int wncf_start(struct wncf_fetch *f,const struct wncf_chain *chain,int64_t now)
{
    if(!f || !chain || !chain->count || chain->count>WNCF_CHAIN_MAX ||
       chain->principal[105] || memchr(chain->principal,0,105) ||
       now<0 || now>INT64_MAX-60000)return -1;
    struct wncf_chain *copy=wendy_net_malloc(sizeof *copy);
    if(!copy)return 1;
    *copy=*chain;
    wncf_stop(f);f->chain=copy;f->deadline=now+60000;f->progress=now;
    return 0;
}
int wncf_start_hashes(struct wncf_fetch *f,const uint8_t hashes[][32],unsigned count,int64_t now)
{
    if(!f || !hashes || !count || count>WNCF_CHAIN_MAX || now<0 || now>INT64_MAX-60000)return -1;
    struct wncf_chain *copy=wendy_net_calloc(1,sizeof *copy);if(!copy)return 1;
    copy->count=count;memcpy(copy->hashes,hashes,count*32);
    wncf_stop(f);f->chain=copy;f->deadline=now+60000;f->progress=now;return 0;
}
static int save_part(struct wncf_fetch *f,const struct wncf_store *store)
{
    if(!f->total || f->offset!=f->total)return 0;
    uint8_t hash[32];
    if(wendy_pki_sha256(f->bytes,f->total,hash) ||
       memcmp(hash,f->chain->hashes[f->index],32))return -1;
    int r=store->put(store->context,hash,f->bytes,f->total);
    if(r)return r<0 ? -1:1;
    r=retain_part(f,store,f->index);if(r)return r;
    wendy_net_free(f->bytes);f->bytes=NULL;f->offset=f->total=0;f->index++;
    return 0;
}
int wncf_next(struct wncf_fetch *f,const struct wncf_store *store,int64_t now,
              struct wncf_request *request)
{
    if(!f || !f->chain || !store || !store->read || !store->put || !request ||
       now<f->progress || now>=f->deadline)return -1;
    if(store->retain && !f->hold){
        if(!store->release)return -1;
        f->hold=wendy_net_calloc(1,sizeof *f->hold);if(!f->hold)return 0;
        f->hold->release=store->release;
    }
    int saved=save_part(f,store);
    if(saved)return saved<0 ? -1:0;
    if(f->waiting && now-f->progress<5000)return 0;
    f->waiting=false;
    while(f->index<f->chain->count && !f->offset){
        size_t total=0;
        int r=store->read(store->context,f->chain->hashes[f->index],0,NULL,&total);
        if(r==-2)return 0;
        if(r<0)return -1;
        if(!r)break;
        if(!total || total>WNCF_PART_MAX)return -1;
        int retained=retain_part(f,store,f->index);if(retained)return retained<0 ? -1:0;
        f->index++;
    }
    if(f->index==f->chain->count)return 2;
    memcpy(request->hash,f->chain->hashes[f->index],32);
    request->offset=f->offset;
    return 1;
}
void wncf_sent(struct wncf_fetch *f,int64_t now)
{
    if(f && f->chain){f->waiting=true;f->progress=now;}
}
int wncf_receive(struct wncf_fetch *f,const struct wncf_store *store,
    const uint8_t hash[32],size_t offset,size_t total,const void *bytes,size_t size,
    int64_t now)
{
    if(!f || !f->chain || !store || !store->put || !bytes || !size ||
       !f->waiting || f->index>=f->chain->count || now<f->progress ||
       now>=f->deadline || memcmp(hash,f->chain->hashes[f->index],32) ||
       offset!=f->offset || !total || total>WNCF_PART_MAX || offset>=total ||
       offset%WNCF_CHUNK || size!=(total-offset<WNCF_CHUNK ? total-offset:WNCF_CHUNK) ||
       (f->total && f->total!=total))return -1;
    f->waiting=false;
    if(!f->bytes){
        f->bytes=wendy_net_malloc(total);
        if(!f->bytes)return 1; /* Retry the same public chunk after pressure. */
        f->total=total;
    }
    memcpy(f->bytes+offset,bytes,size);f->offset+=size;f->progress=now;
    return save_part(f,store);
}
size_t wncf_memory(const struct wncf_fetch *f)
{
    return f ? (f->chain ? sizeof *f->chain:0)+(f->bytes ? f->total:0)+(f->hold ? sizeof *f->hold:0):0;
}

bool wncf_missing(struct wncf_fetch *f,const struct wncf_request *q)
{
    if(!f || !q || !f->chain || !f->waiting || f->index>=f->chain->count ||
       q->offset!=f->offset || memcmp(q->hash,f->chain->hashes[f->index],32))return false;
    wncf_stop(f);return true;
}
