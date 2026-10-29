/* SPDX-License-Identifier: Apache-2.0 */
#include "catalog_internal.h"
#include "wendy_net_alloc.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Compact service maps: a app, m mesh, n instance, p port, s service, t type,
 * x TXT. Device, revision and the sole expiry belong to the enclosing manifest. */
static void service_write(struct wn_writer *w,const struct wns_record *r,const char *const *txt)
{
    wn_map(w,6+(r->txt_count!=0));
    wn_text(w,"a");wn_text(w,r->app);wn_text(w,"m");wn_text(w,r->mesh);
    wn_text(w,"n");wn_text(w,r->instance);wn_text(w,"p");wn_uint(w,r->port);
    wn_text(w,"s");wn_text(w,r->service);wn_text(w,"t");wn_text(w,r->type);
    if(r->txt_count){wn_text(w,"x");wn_array(w,r->txt_count);
        for(unsigned i=0;i<r->txt_count;i++)wn_text(w,txt[i]);}
}


int wnsc_manifest_publish(struct wnsc_node *node,struct wns_record *r,const char *const *txt)
{
    struct wns_entry *old=wns_store_find(&node->records,node->self,r->app,r->service);
    if(r->withdraw){
        if(old){
            struct wns_entry **at=&node->records.entries;while(*at!=old)at=&(*at)->next;
            *at=old->next;node->records.count--;
            node->records.bytes-=sizeof *old+strlen(old->key)+strlen(wns_entry_service(old))+strlen(wns_entry_type(old))+3+old->wire_size;
            wns_wire_release(old->wire);wendy_net_free(old);
            if(node->config.services_changed)node->config.services_changed(node->config.context);
        }
        return 0;
    }
    struct wn_writer measure={.maximum=WNS_BODY_MAX};service_write(&measure,r,txt);
    int size=wn_finish(&measure);if(size<0)return -1;
    char *wire=wendy_net_malloc((size_t)size+1);if(!wire)return 1;
    struct wn_writer writer={.data=(uint8_t *)wire,.capacity=(size_t)size+1,.maximum=WNS_BODY_MAX};
    service_write(&writer,r,txt);int result=wn_finish(&writer)==size ? 0:-1;
    if(!result && old && !old->withdraw && old->wire_size==(size_t)size && !memcmp(old->wire,wire,(size_t)size)){
        r->generation=old->generation;wendy_net_free(wire);return 0;
    }
    /* Reserve room for identity/route metadata before accepting this intent. */
    size_t complete=2048+(size_t)size;unsigned count=1;
    for(const struct wns_entry *e=node->records.entries;e;e=e->next)
        if(e->own && !e->withdraw && e!=old){complete+=e->wire_size;count++;}
    if(complete>WN_MANIFEST_BODY_MAX || count>256){wendy_net_free(wire);return -1;}
    r->generation=old ? old->generation+1:1;r->body=wire;r->body_size=(size_t)size;
    if(!result)result=wns_store_put(&node->records,r,wire,(size_t)size,true);
    wendy_net_free(wire);r->body=NULL;r->body_size=0;
    if(!result && node->config.services_changed)node->config.services_changed(node->config.context);
    return result==-2 || result==2 ? 1:result;
}

static int compare(const void *x,const void *y)
{
    const struct wns_entry *a=*(const struct wns_entry *const *)x,*b=*(const struct wns_entry *const *)y;
    int n=strcmp(a->key,b->key);return n ? n:strcmp(wns_entry_service(a),wns_entry_service(b));
}
int wnsc_services_write(const struct wnsc_node *node,char *out,size_t cap)
{
    size_t count=0;for(const struct wns_entry *e=node->records.entries;e;e=e->next)if(e->own && !e->withdraw)count++;
    const struct wns_entry **rows=count ? wendy_net_malloc(count*sizeof *rows):NULL;if(count && !rows)return -1;
    size_t at=0;for(const struct wns_entry *e=node->records.entries;e;e=e->next)if(e->own && !e->withdraw)rows[at++]=e;
    if(count>1)qsort(rows,count,sizeof *rows,compare);
    struct wn_writer writer={.data=(uint8_t *)out,.capacity=cap,.maximum=WN_MANIFEST_BODY_MAX-2048};
    wn_array(&writer,count);for(at=0;at<count;at++)wn_raw(&writer,rows[at]->wire,rows[at]->wire_size);
    wendy_net_free(rows);return wn_finish(&writer);
}

int wnsc_manifest_services(struct wnsc_node *node,const struct wn_doc *d,unsigned body,
    const uint8_t device[16],uint64_t revision,int64_t issued,int64_t expires,bool withdraw)
{
    struct wns_store staged;wns_store_init(&staged,node->records.limit,node->records.byte_limit);
    struct workspace {struct wn_doc child;struct wns_record record;};
    struct workspace *w=wendy_net_malloc(sizeof *w);
    if(!w){wns_store_remove_origin(&node->records,device);return 0;}
    int services=wn_doc_member(d,body,"s"),result=0;size_t cursor=0,count=0;
    if(services<0){result=-1;goto done;}
    for(;;){
        int next=wn_doc_array_next(d,services,&cursor,&w->child);if(!next)break;
        if(next<0 || ++count>256 || wns_manifest_service_read(&w->child,&w->record)){result=-1;goto done;}
        struct wns_record *r=&w->record;
        /* Child document positions reference the entire enclosing wire. Trim
         * the map span while rebasing TXT offsets for the stored compact row. */
        const struct wn_token *span=wn_doc_token(&w->child,0);
        r->body=d->text+span->start;r->body_size=span->end-span->start;
        for(unsigned i=0;i<r->txt_count;i++)r->txt[i].offset-=(uint16_t)span->start;
        memcpy(r->device,device,16);r->generation=revision;r->issued=issued;r->expires=expires;
        if(strcmp(r->mesh,"default") || withdraw)continue;
        if(wns_store_find(&staged,device,r->app,r->service)){result=-1;goto done;}
        int put=wns_store_put(&staged,r,r->body,r->body_size,false);
        if(put==-2)continue;
        if(put<0){result=-1;goto done;}
        /* A small device can retain a bounded subset of verified summaries.
         * The whole payload is still parsed and covered by one signature. */
    }
    wns_store_remove_origin(&node->records,device);
    while(staged.entries){
        struct wns_entry *e=staged.entries;staged.entries=e->next;
        size_t bytes=sizeof *e+strlen(e->key)+strlen(wns_entry_service(e))+strlen(wns_entry_type(e))+3+e->wire_size;
        while(node->records.count>=node->records.limit || bytes>node->records.byte_limit-node->records.bytes){
            /* These are derived lookup rows, never upload-pinned blobs. Keep
             * local app intent and evict the oldest foreign summary first. */
            struct wns_entry **victim=NULL;
            for(struct wns_entry **at=&node->records.entries;*at;at=&(*at)->next)
                if(!(*at)->own)victim=at;
            if(!victim)break;
            struct wns_entry *old=*victim;*victim=old->next;node->records.count--;
            node->records.bytes-=sizeof *old+strlen(old->key)+strlen(wns_entry_service(old))+strlen(wns_entry_type(old))+3+old->wire_size;
            wns_wire_release(old->wire);wendy_net_free(old);
        }
        if(node->records.count>=node->records.limit || bytes>node->records.byte_limit-node->records.bytes){
            wns_wire_release(e->wire);wendy_net_free(e);continue;
        }
        e->next=node->records.entries;node->records.entries=e;node->records.count++;node->records.bytes+=bytes;
    }
    staged.count=staged.bytes=0;
done:
    wns_store_clear(&staged);wendy_net_free(w);return result;
}

int wnsc_entry_record(const struct wnsc_node *node,const struct wns_entry *entry,int64_t wall,struct wns_record *out)
{
    (void)wall;
    struct wn_doc *d=wendy_net_malloc(sizeof *d);if(!d)return -2;
    int result=wn_doc_parse_bounded(d,entry->wire,entry->wire_size,WNS_BODY_MAX) || wns_manifest_service_read(d,out);
    wendy_net_free(d);if(result)return -1;
    memcpy(out->device,entry->device,16);char device[37];wn_uuid_format(entry->device,device);
    if(wn_principal(node->config.tenant,device,out->principal)<0)return -1;
    out->generation=entry->generation;out->expires=entry->expires;out->issued=entry->issued;
    return 0;
}

void wnsc_manifest_committed(struct wnsc_node *node,uint64_t revision,int64_t issued,int64_t expires)
{
    for(struct wns_entry *e=node->records.entries;e;e=e->next)if(e->own){e->generation=revision;e->issued=issued;e->expires=expires;}
}
