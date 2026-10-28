/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_service_protocol.h"
#include "wendy_net_alloc.h"
#include "wendy_net_peer_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
static bool alnum(unsigned c)
{return (c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9');}
bool wns_label_valid(const char *s)
{
    size_t n=strlen(s);if(!n || n>63 || !((*s>='a' && *s<='z') || (*s>='0' && *s<='9')))return false;
    for(size_t i=1;i<n;i++)if(!((s[i]>='a' && s[i]<='z') || (s[i]>='0' && s[i]<='9')) && !strchr("._-",s[i]))return false;
    return true;
}
bool wns_app_id_valid(const char *s)
{
    size_t n=strlen(s);if(!n || n>253)return false;
    for(size_t i=0;i<n;i++)if(!alnum((unsigned char)s[i]) && !strchr("._-",s[i]))return false;
    return strspn(s,".")!=n;
}
bool wns_type_valid(const char *s)
{
    size_t n=strlen(s);if(n<7 || n>21 || s[0]!='_')return false;
    const char *dot=strchr(s,'.');if(!dot || dot-s<2 || dot-s>16 ||
        (strcmp(dot,"._tcp") && strcmp(dot,"._udp")))return false;
    for(const char *p=s+1;p<dot;p++)if(!((*p>='a' && *p<='z') || (*p>='0' && *p<='9') || *p=='-'))return false;
    return true;
}
static int emit_utf8(uint32_t c,char *out,size_t cap,size_t *at)
{
    if(c>0x10ffff || (c>=0xd800 && c<=0xdfff))return -1;
    unsigned bytes=c<0x80 ? 1:c<0x800 ? 2:c<0x10000 ? 3:4;
    if(*at>cap || bytes>=cap-*at)return -1;
    if(bytes==1)out[(*at)++]=(char)c;
    else {
        out[(*at)++]=(char)((bytes==2 ? 0xc0:bytes==3 ? 0xe0:0xf0)|(c>>(6*(bytes-1))));
        for(unsigned i=bytes-1;i>0;i--)out[(*at)++]=(char)(0x80|((c>>(6*(i-1)))&63));
    }
    return 0;
}
/* Read an encoded CBOR text item while retaining only its original span. */
static int text(const char *s,size_t n,char *out,size_t cap)
{
    if(!s || !n || !out || !cap || ((unsigned char)s[0]>>5)!=3)return -1;
    unsigned small=(unsigned char)s[0]&31;size_t h=1,bytes=small;
    if(small==24){if(n<2)return -1;h=2;bytes=(unsigned char)s[1];}
    else if(small==25){if(n<3)return -1;h=3;bytes=wn_get16((const uint8_t*)s+1);}
    else if(small>=26)return -1;
    if(bytes!=n-h)return -1;
    size_t at=0;
    for(size_t p=h;p<n;){
        uint32_t c=(unsigned char)s[p++];
        if(c>=0x80){
            unsigned extra;uint32_t minimum;
            if(c>=0xc2 && c<=0xdf){extra=1;minimum=0x80;c&=31;}
            else if(c>=0xe0 && c<=0xef){extra=2;minimum=0x800;c&=15;}
            else if(c>=0xf0 && c<=0xf4){extra=3;minimum=0x10000;c&=7;}
            else return -1;
            if(n-p<extra)return -1;
            for(unsigned i=0;i<extra;i++){unsigned x=(unsigned char)s[p++];if((x&0xc0)!=0x80)return -1;c=(c<<6)|(x&63);}
            if(c<minimum)return -1;
        }
        if(!c || emit_utf8(c,out,cap,&at))return -1;
    }
    out[at]=0;return (int)at;
}
static int field(const struct wn_doc *doc,unsigned object,const char *key,char *out,size_t cap)
{
    const struct wn_token *t=wn_doc_token(doc,wn_doc_member(doc,object,key));
    return !t || t->type!='"' ? -1:text(doc->text+t->start,t->end-t->start,out,cap);
}
static int number(const struct wn_doc *doc,unsigned object,const char *key,uint64_t *value)
{return wn_doc_u64(doc,wn_doc_member(doc,object,key),value);}
int wns_record_txt(const struct wns_record *r,unsigned index,char *out,size_t cap)
{
    if(!r || index>=r->txt_count)return -1;
    struct wns_text t=r->txt[index];
    if(t.offset>r->body_size || t.size>r->body_size-t.offset)return -1;
    return text(r->body+t.offset,t.size,out,cap);
}
int wns_spec_read(const void *data,size_t size,struct wns_record *r)
{
    struct workspace {struct wn_doc doc;char decoded[256];};
    if(!data || !size || size>WNS_BODY_MAX || !r)return -1;
    memset(r,0,sizeof *r);struct workspace *w=wendy_net_malloc(sizeof *w);if(!w)return -2;
    struct wn_doc *d=&w->doc;uint64_t port;int result=-1;
    static const char *const fields[]={"serviceId","type","instance","port","txt",NULL};
    if(wn_doc_parse_bounded(d,data,size,WNS_BODY_MAX) || !wn_doc_fields(d,0,fields) ||
       field(d,0,"serviceId",r->service,sizeof r->service)<0 || !wns_label_valid(r->service) ||
       !strcmp(r->service,"internet-gateway") ||
       field(d,0,"type",r->type,sizeof r->type)<0 || !wns_type_valid(r->type) ||
       field(d,0,"instance",r->instance,sizeof r->instance)<=0 || strpbrk(r->instance,"\r\n") ||
       number(d,0,"port",&port) || !port || port>65535)goto done;
    r->port=(uint16_t)port;r->body=data;r->body_size=size;
    int txt=wn_doc_member(d,0,"txt");size_t total=0;
    if(txt>=0){
        const struct wn_token *array=wn_doc_token(d,txt);
        if(!array || array->type!='[')goto done;
        for(unsigned at=(unsigned)txt+1;at<array->next;){
            const struct wn_token *t=wn_doc_token(d,(int)at);
            if(!t || t->type!='"' || r->txt_count==WNS_TXT_MAX)goto done;
            int n=text(d->text+t->start,t->end-t->start,w->decoded,sizeof w->decoded);
            if(n<=0 || strpbrk(w->decoded,"\r\n") || total+(size_t)n+1>1200)goto done;
            total+=(size_t)n+1;
            r->txt[r->txt_count++]=(struct wns_text){(uint16_t)t->start,(uint16_t)(t->end-t->start)};
            at=t->next;
        }
    }
    result=0;
done:
    wendy_net_free(w);return result;
}
