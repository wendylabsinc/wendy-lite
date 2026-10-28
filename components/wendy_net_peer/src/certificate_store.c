/* SPDX-License-Identifier: Apache-2.0 */
#include "certificate_store.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_crypto.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

struct wncs_part {
    struct wncs_part *next;
    atomic_uint references;
    size_t size;
    uint8_t hash[32],data[];
};
struct wncs_descriptor {
    struct wncs_descriptor *next;
    int64_t expires;
    struct wncf_chain chain;
};
static struct wncs_part *find(struct wncs_store *s,const uint8_t hash[32])
{
    if(!s || !s->opened || !hash)return NULL;
    for(struct wncs_part *p=s->first;p;p=p->next)if(!memcmp(p->hash,hash,32))return p;
    return NULL;
}
static void release(struct wncs_part *p)
{
    if(p && atomic_fetch_sub(&p->references,1)==1)wendy_net_free(p);
}
static int evict_part(struct wncs_store *s)
{
    struct wncs_part *previous=NULL;
    for(struct wncs_part *p=s->first;p;previous=p,p=p->next){
        if(atomic_load(&p->references)!=1)continue;
        if(previous)previous->next=p->next;else s->first=p->next;
        if(s->last==p)s->last=previous;
        s->bytes-=sizeof *p+p->size;s->count--;release(p);return 0;
    }
    return 1;
}
static int evict_chain(struct wncs_store *s)
{
    struct wncs_descriptor *p=s->chains_first;if(!p)return 1;
    s->chains_first=p->next;if(!s->chains_first)s->chains_last=NULL;
    s->chains--;s->bytes-=sizeof *p;wendy_net_free(p);return 0;
}
size_t wncs_trim(struct wncs_store *s)
{
    if(!s || !s->opened)return 0;
    size_t before=s->bytes;
    while(!evict_part(s)){}
    while(!evict_chain(s)){}
    return before-s->bytes;
}
static int room(struct wncs_store *s,size_t bytes)
{
    if(bytes>s->limit)return 1;
    while(s->bytes>s->limit-bytes){
        if(evict_part(s) && evict_chain(s))return 1;
    }
    return 0;
}
int wncs_open_limits(struct wncs_store *s,size_t limit,unsigned parts,unsigned chains)
{
    if(!s || limit<sizeof(struct wncs_part)+1 || !parts || parts>256 || !chains || chains>256)return -1;
    memset(s,0,sizeof *s);s->limit=limit;s->part_limit=parts;s->chain_limit=chains;s->opened=true;return 0;
}
void wncs_set_baseline(struct wncs_store *s,void *context,
    int (*read)(void *,const uint8_t[32],size_t,uint8_t[WNCF_CHUNK],size_t *))
{if(s){s->baseline_context=context;s->baseline_read=read;}}
void wncs_set_baseline_index(struct wncs_store *s,const struct wendy_pki_mesh_public_index *index,
    bool (*current)(void *,const struct wendy_pki_mesh_public_index *))
{
    if(!s)return;
    s->baseline_index=index ? *index:(struct wendy_pki_mesh_public_index){0};
    s->baseline_index_enabled=true;s->baseline_current=current;
}
static int baseline_size(struct wncs_store *s,const uint8_t hash[32],size_t *size)
{
    *size=0;
    if(s->baseline_index_enabled){
        const struct wendy_pki_mesh_public_index *index=&s->baseline_index;
        if(!s->baseline_current || index->count>8 ||
           !s->baseline_current(s->baseline_context,index))return 0;
        for(unsigned i=0;i<index->count;i++)if(!memcmp(index->hashes[i],hash,32)){
            *size=index->sizes[i];return *size ? 1:0;
        }
        return 0;
    }
    return s->baseline_read ? s->baseline_read(s->baseline_context,hash,0,NULL,size):0;
}
int wncs_open(struct wncs_store *s,size_t limit)
{return wncs_open_limits(s,limit,32,32);}
void wncs_close(struct wncs_store *s)
{
    if(!s)return;
    while(s->first){struct wncs_part *p=s->first;s->first=p->next;release(p);}
    while(!evict_chain(s)){}
    memset(s,0,sizeof *s);
}
int wncs_load_into(struct wncs_store *s,const uint8_t hash[32],uint8_t *data,size_t capacity,size_t *size)
{
    if(!data || !size)return -1;
    *size=0;struct wncs_part *p=find(s,hash);if(!p)return 0;
    if(capacity<p->size)return -1;
    memcpy(data,p->data,p->size);*size=p->size;return 1;
}
int wncs_load(struct wncs_store *s,const uint8_t hash[32],uint8_t **out,size_t *size)
{
    if(!out || !size)return -1;
    *out=NULL;*size=0;struct wncs_part *p=find(s,hash);if(!p)return 0;
    uint8_t *data=wendy_net_malloc(p->size);if(!data)return -1;
    memcpy(data,p->data,p->size);*out=data;*size=p->size;return 1;
}
int wncs_read_resident(struct wncs_store *s,const uint8_t hash[32],size_t offset,
    uint8_t out[WNCF_CHUNK],size_t *total)
{
    if(!total)return -1;
    *total=0;struct wncs_part *p=find(s,hash);if(!p)return 0;
    *total=p->size;if(!out)return 1;
    if(offset>=p->size)return -1;
    size_t n=p->size-offset;if(n>WNCF_CHUNK)n=WNCF_CHUNK;
    memcpy(out,p->data+offset,n);return 1;
}
int wncs_read(void *context,const uint8_t hash[32],size_t offset,uint8_t out[WNCF_CHUNK],size_t *total)
{
    int r=wncs_read_resident(context,hash,offset,out,total);if(r)return r;
    struct wncs_store *s=context;
    if(!s || !s->opened)return 0;
    if(!out)return baseline_size(s,hash,total);
    return s->baseline_read ? s->baseline_read(s->baseline_context,hash,offset,out,total):0;
}
int wncs_put(void *context,const uint8_t hash[32],const void *bytes,size_t size)
{
    struct wncs_store *s=context;
    if(!s || !s->opened || !hash || !bytes || !size || size>WNCF_PART_MAX)return -1;
    struct wncs_part *old=find(s,hash);if(old)return old->size==size ? 0:-1;
    if(s->baseline_index_enabled || s->baseline_read){
        size_t baseline=0;int found=baseline_size(s,hash,&baseline);
        if(found==-2)return 1;
        if(found==1)return baseline==size ? 0:-1;
    }
    uint8_t digest[32];if(wendy_pki_sha256(bytes,size,digest) || memcmp(digest,hash,32))return -1;
    while(s->count>=s->part_limit)if(evict_part(s))return 1;
    if(room(s,sizeof(struct wncs_part)+size))return 1;
    struct wncs_part *p=wendy_net_malloc(sizeof *p+size);if(!p)return 1;
    p->next=NULL;atomic_init(&p->references,1);p->size=size;memcpy(p->hash,hash,32);memcpy(p->data,bytes,size);
    if(s->last)s->last->next=p;else s->first=p;s->last=p;
    s->count++;s->bytes+=sizeof *p+size;return 0;
}
void wncs_unpin(struct wncs_loan *loan)
{
    if(!loan)return;
    for(unsigned i=0;i<loan->count;i++)release(loan->entries[i]);
    memset(loan,0,sizeof *loan);
}
int wncs_pin_chain(struct wncs_store *s,const struct wncf_chain *chain,struct wncs_loan *loan)
{
    return chain ? wncs_pin_hashes(s,chain->hashes,chain->count,loan):-1;
}
int wncs_pin_hashes(struct wncs_store *s,const uint8_t hashes[][32],unsigned count,struct wncs_loan *loan)
{
    if(!s || !s->opened || !hashes || !loan || loan->count || !count || count>WNCF_CHAIN_MAX)return -1;
    for(unsigned i=0;i<count;i++){
        struct wncs_part *p=find(s,hashes[i]);
        if(!p){
            size_t size=0;
            if(baseline_size(s,hashes[i],&size)!=1 ||
               !size || size>WNCF_PART_MAX){wncs_unpin(loan);return 1;}
            loan->sizes[i]=size;loan->count++;continue;
        }
        atomic_fetch_add(&p->references,1);loan->entries[i]=p;loan->parts[i]=p->data;loan->sizes[i]=p->size;loan->count++;
    }
    return 0;
}
int wncs_pin_part(struct wncs_store *s,const uint8_t hash[32],struct wncs_loan *loan)
{
    if(!s || !s->opened || !hash || !loan || loan->count)return -1;
    struct wncs_part *p=find(s,hash);if(!p)return 1;
    atomic_fetch_add(&p->references,1);loan->entries[0]=p;loan->parts[0]=p->data;loan->sizes[0]=p->size;loan->count=1;return 0;
}
int wncs_chain_put(struct wncs_store *s,const struct wncf_chain *chain,int64_t expires)
{
    if(!s || !s->opened || !chain || !chain->count || chain->count>WNCF_CHAIN_MAX ||
       chain->principal[105] || memchr(chain->principal,0,105) || expires<=0)return -1;
    for(struct wncs_descriptor *p=s->chains_first;p;p=p->next)
        if(!strcmp(p->chain.principal,chain->principal)){p->chain=*chain;p->expires=expires;return 0;}
    while(s->chains>=s->chain_limit)if(evict_chain(s))return 1;
    if(room(s,sizeof(struct wncs_descriptor)))return 1;
    struct wncs_descriptor *p=wendy_net_calloc(1,sizeof *p);if(!p)return 1;
    p->chain=*chain;p->expires=expires;
    if(s->chains_last)s->chains_last->next=p;else s->chains_first=p;s->chains_last=p;
    s->chains++;s->bytes+=sizeof *p;return 0;
}
int wncs_chain_get(struct wncs_store *s,const char *principal,int64_t now,struct wncf_chain *out)
{
    if(!s || !s->opened || !principal || !out || strlen(principal)!=105)return -1;
    for(struct wncs_descriptor *p=s->chains_first;p;p=p->next)
        if(!strcmp(p->chain.principal,principal)){
            if(p->expires<=now)return 0;
            *out=p->chain;return 1;
        }
    return 0;
}

static char baseline_token;
void *wncs_retain(void *context,const uint8_t hash[32])
{
    struct wncs_store *s=context;struct wncs_part *p=find(s,hash);
    if(!p){
        size_t size=0;
        return s && s->opened && baseline_size(s,hash,&size)==1 && size ? &baseline_token:NULL;
    }
    atomic_fetch_add(&p->references,1);return p;
}
void wncs_release(void *part){if(part!=&baseline_token)release(part);}
