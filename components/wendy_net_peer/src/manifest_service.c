/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_service_protocol.h"
#include "wendy_net_alloc.h"
#include <limits.h>
#include <string.h>
int wns_manifest_service_read(const struct wn_doc *d,struct wns_record *r)
{
    uint64_t port;memset(r,0,sizeof *r);
    if(!d || wn_doc_string(d,wn_doc_member(d,0,"a"),r->app,sizeof r->app)<0 || !wns_app_id_valid(r->app) ||
       wn_doc_string(d,wn_doc_member(d,0,"m"),r->mesh,sizeof r->mesh)<0 || !wns_label_valid(r->mesh) ||
       wn_doc_string(d,wn_doc_member(d,0,"s"),r->service,sizeof r->service)<0 || !wns_label_valid(r->service) ||
       wn_doc_string(d,wn_doc_member(d,0,"n"),r->instance,sizeof r->instance)<0 || strpbrk(r->instance,"\r\n") ||
       wn_doc_string(d,wn_doc_member(d,0,"t"),r->type,sizeof r->type)<0 ||
       wn_doc_u64(d,wn_doc_member(d,0,"p"),&port) || port>UINT16_MAX)return -1;
    r->port=(uint16_t)port;
    int txt=wn_doc_member(d,0,"x");size_t total=0;
    if(txt>=0){
        const struct wn_token *array=wn_doc_token(d,txt);if(!array || array->type!='[')return -1;
        for(unsigned at=(unsigned)txt+1;at<array->next;at=wn_doc_token(d,(int)at)->next){
            char value[256];const struct wn_token *t=wn_doc_token(d,(int)at);
            int n=wn_doc_string(d,(int)at,value,sizeof value);
            if(n<=0 || strpbrk(value,"\r\n") || r->txt_count==WNS_TXT_MAX || total+(size_t)n+1>1200)return -1;
            total+=(size_t)n+1;r->txt[r->txt_count++]=(struct wns_text){(uint16_t)t->start,(uint16_t)(t->end-t->start)};
        }
    }
    r->gateway=!strcmp(r->app,"wendy.mesh.system") && !strcmp(r->service,"internet-gateway");
    if(!strcmp(r->app,"wendy.mesh.system") || !strcmp(r->service,"internet-gateway")){
        if(!r->gateway || r->port || *r->type || *r->instance || r->txt_count)return -1;
    }else{
        if(!r->port || !*r->instance || !wns_type_valid(r->type))return -1;
    }
    r->body=d->text;r->body_size=d->size;return 0;
}

int wns_manifest_services_validate(const struct wn_doc *d,unsigned body)
{
    struct service_key {uint16_t start[3],size[3];};
    struct workspace {struct wn_doc child;struct wns_record record;};
    struct workspace *w=wendy_net_malloc(sizeof *w);if(!w)return 4;
    struct service_key *keys=NULL;size_t capacity=0;
    int array=wn_doc_member(d,body,"s"),result=0;size_t cursor=0,count=0;
    if(array<0){wendy_net_free(w);return -1;}
    for(;;){
        int n=wn_doc_array_next(d,array,&cursor,&w->child);if(!n)break;
        if(n<0 || count==256 || wns_manifest_service_read(&w->child,&w->record)){result=-1;break;}
        struct service_key key={0};static const char *const names[]={"m","a","s"};
        for(unsigned i=0;i<3;i++){
            const struct wn_token *t=wn_doc_token(&w->child,wn_doc_member(&w->child,0,names[i]));
            if(!t || t->start+t->header>UINT16_MAX || t->end-t->start-t->header>UINT16_MAX){result=-1;break;}
            key.start[i]=(uint16_t)(t->start+t->header);key.size[i]=(uint16_t)(t->end-t->start-t->header);
        }
        if(result)break;
        /* Exact identity equality, with borrowed spans instead of copied names
         * or a hash whose collision could conflate two distinct services. */
        for(size_t j=0;j<count;j++){
            bool equal=true;
            for(unsigned i=0;i<3;i++)if(key.size[i]!=keys[j].size[i] ||
                memcmp(d->text+key.start[i],d->text+keys[j].start[i],key.size[i])){equal=false;break;}
            if(equal){result=-1;break;}
        }
        if(result)break;
        if(count==capacity){
            size_t next=capacity ? capacity*2:4;
            void *grown=wendy_net_realloc(keys,next*sizeof *keys);
            if(!grown){result=4;break;}keys=grown;capacity=next;
        }
        keys[count++]=key;
    }
    wendy_net_free(keys);wendy_net_free(w);return result;
}
