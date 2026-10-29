/* SPDX-License-Identifier: Apache-2.0 */
#include "catalog_internal.h"
#include "wendy_net_alloc.h"
#include <stdlib.h>
#include <string.h>
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
#include "esp_log.h"
#endif
struct workspace {struct wns_record record;const char *txt[WNS_TXT_MAX];char strings[1201];};
static int decode_txt(struct workspace *w)
{
    size_t at=0;
    for(unsigned i=0;i<w->record.txt_count;i++){
        int n=wns_record_txt(&w->record,i,w->strings+at,sizeof w->strings-at);
        if(n<0)return -1;
        w->txt[i]=w->strings+at;at+=(size_t)n+1;
    }
    return 0;
}
static int publish(struct wnsc_node *node,struct workspace *w,int listener,int64_t wall,uint64_t now)
{
    struct wns_record *r=&w->record;
    strcpy(r->app,WNS_GUEST_APP_ID);r->issued=wall;r->expires=wall+900000;
    int64_t expires=node->config.expires(node->config.context);if(r->expires>expires)r->expires=expires;
    if(r->expires<=wall)return 1;
    int result=wnsc_publish(node,r,w->txt,wall,now);
    if(!result){
        struct wns_entry *e=wns_store_find(&node->records,node->self,WNS_GUEST_APP_ID,r->service);
        if(e)e->listener=listener;
    }
    return result;
}
static int guest_publish_binary(struct wnsc_node *node,const void *spec,size_t size,
    wnsc_listener_owner owner,void *context,int64_t wall,uint64_t now)
{
    if(!node || !spec || !owner)return -1;
    struct workspace *w=wendy_net_calloc(1,sizeof *w);if(!w)return 1;
    int r=wns_spec_read(spec,size,&w->record),listener=-1;
    if(!r){
        bool datagram=!strcmp(w->record.type+strlen(w->record.type)-4,"_udp");
        listener=owner(context,w->record.port,datagram);
        r=listener<0 ? -1:decode_txt(w);
    }
    if(!r)r=publish(node,w,listener,wall,now);
    wendy_net_free(w);return r;
}
int wnsc_guest_withdraw(struct wnsc_node *node,const char *service,int64_t wall,uint64_t now)
{
    if(!node || !service || !wns_label_valid(service))return -1;
    const struct wns_entry *e=wns_store_find(&node->records,node->self,WNS_GUEST_APP_ID,service);
    /* Withdrawal removes local intent; the next complete manifest carries
     * that omission under its one signature and inherited expiry. */
    if(e && e->withdraw && e->wire && e->expires>wall)return 0;
    struct workspace *w=wendy_net_calloc(1,sizeof *w);if(!w)return 1;
    strcpy(w->record.service,service);w->record.withdraw=true;
    int r=publish(node,w,0,wall,now);wendy_net_free(w);return r;
}
struct registration {
    struct registration *next;
    size_t size;
    int listener;
    uint16_t port;
    bool datagram;
    bool dirty;
    char service[64];
    char spec[];
};
struct wnsc_registry {struct registration *entries;size_t count,bytes;
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
    uint64_t next_probe;
#endif
};
static int guest_register_binary(struct wnsc_registry **owner,const void *spec,size_t size,
    wnsc_listener_owner listener_owner,void *context)
{
    if(!owner || !spec || !size || !listener_owner)return -1;
    struct wns_record *r=wendy_net_malloc(sizeof *r);if(!r)return 1;
    int result=wns_spec_read(spec,size,r),listener=-1;
    bool datagram=false;
    if(!result){
        datagram=!strcmp(r->type+strlen(r->type)-4,"_udp");
        listener=listener_owner(context,r->port,datagram);if(listener<0)result=-1;
    }
    if(result){wendy_net_free(r);return result;}
    struct wnsc_registry *registry=*owner;
    if(!registry){registry=wendy_net_calloc(1,sizeof *registry);if(!registry){wendy_net_free(r);return 1;}}
    struct registration **at=&registry->entries;
    while(*at && strcmp((*at)->service,r->service))at=&(*at)->next;
    struct registration *old=*at;
    /* Guest replay is idempotent for the same listener incarnation and exact
     * normalized specification. Preserve an existing dirty flag, generation,
     * publication deadline and in-flight signing work. */
    if(old && old->listener==listener && old->size==size &&
       !memcmp(old->spec,spec,size)){wendy_net_free(r);return 0;}
    size_t previous=old ? sizeof *old+old->size:0;
    size_t needed=sizeof(struct registration)+size;
    if((!old && registry->count>=64) || needed>(WN_MANIFEST_BODY_MAX-2048)-(registry->bytes-previous))result=1;
    struct registration *entry=!result ? wendy_net_malloc(needed):NULL;
    if(!entry)result=1;
    if(!result){
        entry->next=old ? old->next:NULL;entry->size=size;entry->listener=listener;
        entry->port=r->port;entry->datagram=datagram;entry->dirty=true;
        strcpy(entry->service,r->service);memcpy(entry->spec,spec,size);
        *at=entry;registry->bytes=registry->bytes-previous+needed;if(!old)registry->count++;
        wendy_net_free(old);*owner=registry;
    }else if(!*owner)wendy_net_free(registry);
    wendy_net_free(r);return result;
}
int wnsc_guest_tick(struct wnsc_registry **owner,struct wnsc_node *node,
    wnsc_listener_owner listener_owner,void *context,int64_t wall,uint64_t now)
{
    if(!owner || !*owner)return 0;
    struct wnsc_registry *registry=*owner;
    for(struct registration **at=&registry->entries;*at;){
        struct registration *e=*at;
        bool live=listener_owner(context,e->port,e->datagram)==e->listener;
        if(!live){
            int r=node ? wnsc_guest_withdraw(node,e->service,wall,now):0;
            if(r){at=&e->next;continue;}
            *at=e->next;registry->count--;registry->bytes-=sizeof *e+e->size;wendy_net_free(e);continue;
        }
        if(node){
            struct wns_entry *published=wns_store_find(&node->records,node->self,WNS_GUEST_APP_ID,e->service);
            if(e->dirty || !published || published->withdraw || published->unavailable ||
               published->listener!=e->listener){
                int result=guest_publish_binary(node,e->spec,e->size,listener_owner,context,wall,now);
                if(!result)e->dirty=false;
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
                if(result && now>=registry->next_probe){
                    registry->next_probe=now+15000;
                    ESP_LOGI("wendy_net_catalog","guest publication pending: service=%s result=%d records=%u bytes=%u",
                        e->service,result,(unsigned)node->records.count,(unsigned)node->records.bytes);
                }
#endif
            }
        }
        at=&e->next;
    }
    if(!registry->entries){wendy_net_free(registry);*owner=NULL;}
    return 0;
}
int wnsc_guest_unregister(struct wnsc_registry **owner,struct wnsc_node *node,const char *service,
    int64_t wall,uint64_t now)
{
    if(!owner || !service || !wns_label_valid(service))return -1;
    if(!node)return 1;
    int r=wnsc_guest_withdraw(node,service,wall,now);if(r)return r;
    struct wnsc_registry *registry=*owner;if(!registry)return 0;
    for(struct registration **at=&registry->entries;*at;at=&(*at)->next){
        struct registration *e=*at;if(strcmp(e->service,service))continue;
        *at=e->next;registry->count--;registry->bytes-=sizeof *e+e->size;wendy_net_free(e);break;
    }
    if(!registry->entries){wendy_net_free(registry);*owner=NULL;}
    return 0;
}
void wnsc_guest_clear(struct wnsc_registry **owner)
{
    if(!owner || !*owner)return;
    struct wnsc_registry *r=*owner;
    while(r->entries){struct registration *e=r->entries;r->entries=e->next;wendy_net_free(e);}
    wendy_net_free(r);*owner=NULL;
}

int wnsc_guest_publish(struct wnsc_node *node,const void *json,size_t size,
    wnsc_listener_owner owner,void *context,int64_t wall,uint64_t now)
{
    char *binary=NULL;size_t bytes=0;int r=wns_spec_from_json(json,size,&binary,&bytes);
    if(!r)r=guest_publish_binary(node,binary,bytes,owner,context,wall,now);
    /* wns_spec_from_json returns a public libc-owned output buffer. */
    free(binary);return r==-2 ? 1:r;
}
int wnsc_guest_register(struct wnsc_registry **owner,const void *json,size_t size,
    wnsc_listener_owner listener_owner,void *context)
{
    char *binary=NULL;size_t bytes=0;int r=wns_spec_from_json(json,size,&binary,&bytes);
    if(!r)r=guest_register_binary(owner,binary,bytes,listener_owner,context);
    /* wns_spec_from_json returns a public libc-owned output buffer. */
    free(binary);return r==-2 ? 1:r;
}
