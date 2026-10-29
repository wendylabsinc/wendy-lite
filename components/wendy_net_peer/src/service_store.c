/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_service_store.h"
#include "wendy_net_alloc.h"
#include "wendy_net_peer_protocol.h"
#include "wendy_pki_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>

struct wire_storage {size_t references;char bytes[];};
static struct wire_storage *wire_storage(const void *bytes)
{return (struct wire_storage *)((char *)bytes - offsetof(struct wire_storage,bytes));}
void wns_wire_retain(const void *bytes)
{if(bytes)wire_storage(bytes)->references++;}
void wns_wire_release(const void *bytes)
{if(bytes){struct wire_storage *wire=wire_storage(bytes);if(!--wire->references)wendy_net_free(wire);}}
static char *copy_wire(const void *bytes,size_t size)
{
    struct wire_storage *wire=wendy_net_malloc(sizeof *wire+size);if(!wire)return NULL;
    wire->references=1;memcpy(wire->bytes,bytes,size);return wire->bytes;
}

static size_t entry_size(const struct wns_entry *e)
{return sizeof *e+strlen(e->key)+1+strlen(wns_entry_service(e))+1+strlen(wns_entry_type(e))+1;}
const char *wns_entry_service(const struct wns_entry *e){return e->key+strlen(e->key)+1;}
const char *wns_entry_type(const struct wns_entry *e){const char *id=wns_entry_service(e);return id+strlen(id)+1;}
bool wns_store_retire_wire(struct wns_store *s,const void *wire)
{
    if(!s || !wire)return false;
    for(struct wns_entry *e=s->entries;e;e=e->next)if(e->wire==wire){
        s->bytes-=e->wire_size;wns_wire_release(e->wire);e->wire=NULL;e->wire_size=0;
        e->body_retired=true;return true;
    }
    return false;
}
void wns_store_init(struct wns_store *s,size_t limit,size_t byte_limit)
{memset(s,0,sizeof *s);s->limit=limit;s->byte_limit=byte_limit;}
void wns_store_clear(struct wns_store *s)
{
    while(s->entries){struct wns_entry *e=s->entries;s->entries=e->next;wns_wire_release(e->wire);wendy_net_free(e);}
    s->bytes=0;s->count=0;
}
void wns_store_remove_origin(struct wns_store *s,const uint8_t device[16])
{
    for(struct wns_entry **at=&s->entries;*at;){
        struct wns_entry *e=*at;
        if(memcmp(e->device,device,16)){at=&e->next;continue;}
        *at=e->next;s->count--;s->bytes-=entry_size(e)+e->wire_size;
        wns_wire_release(e->wire);wendy_net_free(e);
    }
}
struct wns_entry *wns_store_find(const struct wns_store *s,const uint8_t device[16],
    const char *app,const char *service)
{
    for(struct wns_entry *e=s->entries;e;e=e->next)
        if(!memcmp(e->device,device,16) && !strcmp(e->key,app) && !strcmp(wns_entry_service(e),service))return e;
    return NULL;
}
int wns_store_put(struct wns_store *s,const struct wns_record *r,const void *wire,size_t size,bool own)
{
    if(!s || !r || !wire || !size || size>WNS_WIRE_MAX || !r->body || !r->body_size)return -1;
    uint8_t hash[32];if(wendy_pki_sha256((const uint8_t*)r->body,r->body_size,hash))return -1;
    struct wns_entry *old=wns_store_find(s,r->device,r->app,r->service);
    if(old && old->generation>r->generation)return 1;
    if(old && old->generation==r->generation){
        if(memcmp(old->hash,hash,32))return -1;
        if(old->wire || old->body_retired || r->withdraw)return 1;
        /* A forgotten body must not refill from an old duplicate. Its bounded
         * RAM receipt permits only a new generation to make it live again. */
        if(old->own || old->unavailable)return 1;
    }
    size_t metadata=sizeof(struct wns_entry)+strlen(r->app)+strlen(r->service)+strlen(r->type)+3;
    size_t previous=old ? entry_size(old)+old->wire_size:0;
    size_t next=metadata+size;
    if((!old && s->count>=s->limit) || s->bytes-previous>s->byte_limit ||
       next>s->byte_limit-(s->bytes-previous))return 2;
    struct wns_entry *e=wendy_net_calloc(1,metadata);if(!e)return -2;
    e->wire=copy_wire(wire,size);if(!e->wire){wendy_net_free(e);return -2;}
    e->wire_size=size;
    memcpy(e->device,r->device,16);memcpy(e->hash,hash,32);
    e->generation=r->generation;e->issued=r->issued;e->expires=r->expires;e->withdraw=r->withdraw;e->own=own;
    e->port=r->port;e->gateway=r->gateway;e->summary_verified=!r->withdraw;
    e->unavailable=r->withdraw;
    strcpy(e->key,r->app);strcpy(e->key+strlen(r->app)+1,r->service);
    strcpy(e->key+strlen(r->app)+strlen(r->service)+2,r->type);
    if(old){
        struct wns_entry **at=&s->entries;while(*at!=old)at=&(*at)->next;
        e->next=old->next;*at=e;wns_wire_release(old->wire);wendy_net_free(old);
    }else{e->next=s->entries;s->entries=e;s->count++;}
    s->bytes=s->bytes-previous+next;return 0;
}
void wns_store_prune(struct wns_store *s,int64_t now)
{
    for(struct wns_entry **at=&s->entries;*at;){
        struct wns_entry *e=*at;
        if(!e->own && e->expires<=now){
            *at=e->next;s->bytes-=entry_size(e)+e->wire_size;s->count--;wns_wire_release(e->wire);wendy_net_free(e);
        }else at=&e->next;
    }
}