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
        size_t n=strlen(r->type);
        if(!r->port || !*r->instance || n<7 || r->type[0]!='_' || n>21 ||
           (strcmp(r->type+n-5,"._tcp") && strcmp(r->type+n-5,"._udp")))return -1;
        for(size_t i=1;i<n-5;i++)if(!((r->type[i]>='a' && r->type[i]<='z') ||
            (r->type[i]>='0' && r->type[i]<='9') || r->type[i]=='-'))return -1;
    }
    r->body=d->text;r->body_size=d->size;return 0;
}

int wns_manifest_services_validate(const struct wn_doc *d,unsigned body)
{
    struct workspace {struct wn_doc child;struct wns_record record;};
    struct workspace *w=wendy_net_malloc(sizeof *w);if(!w)return 4;
    int array=wn_doc_member(d,body,"s"),result=0;size_t cursor=0,count=0;
    if(array<0){wendy_net_free(w);return -1;}
    for(;;){int n=wn_doc_array_next(d,array,&cursor,&w->child);if(!n)break;
        if(n<0 || ++count>256 || wns_manifest_service_read(&w->child,&w->record)){result=-1;break;}}
    wendy_net_free(w);return result;
}
