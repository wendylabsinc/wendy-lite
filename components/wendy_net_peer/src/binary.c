/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_peer_protocol.h"
#include <limits.h>
#include <string.h>

/* The protocol uses definite CBOR maps, arrays, UTF-8 text, raw byte strings,
 * integers and booleans. Token payloads borrow the frame. No parser heap and no
 * text/base64 expansion. Unknown map values remain structurally skippable. */
static int argument(const uint8_t *data,size_t size,size_t *at,uint8_t *major,
                    uint8_t *header,uint64_t *out)
{
    if(*at>=size)return -1;
    uint8_t first=data[*at],small=first&31;*major=first>>5;*header=1;
    if(small<24){*out=small;(*at)++;return 0;}
    if(small>27)return -1;
    unsigned bytes=1U<<(small-24);
    if(bytes>size-*at-1)return -1;
    uint64_t value=0;for(unsigned i=0;i<bytes;i++)value=(value<<8)|data[*at+1+i];
    if(value<24 || (bytes>1 && value< (UINT64_C(1)<<(8*(bytes/2)))))return -1;
    *header=(uint8_t)(1+bytes);*at+=*header;*out=value;return 0;
}
static bool utf8(const uint8_t *bytes,size_t size)
{
    for(size_t at=0;at<size;){
        uint32_t code=bytes[at++];unsigned rest;
        if(code<0x80)continue;
        if(code>=0xc2 && code<=0xdf){rest=1;code&=0x1f;}
        else if(code>=0xe0 && code<=0xef){rest=2;code&=0x0f;}
        else if(code>=0xf0 && code<=0xf4){rest=3;code&=7;}
        else return false;
        unsigned count=rest;if(rest>size-at)return false;
        while(rest--){unsigned c=bytes[at++];if((c&0xc0)!=0x80)return false;code=(code<<6)|(c&0x3f);}
        if((count==2 && code<0x800) || (count==3 && code<0x10000) ||
           (code>=0xd800 && code<=0xdfff) || code>0x10ffff)return false;
    }
    return true;
}
static int value(struct wn_doc *d,size_t *at,unsigned depth,const char *view,bool compact)
{
    if(depth>16 || d->count==d->capacity || *at>UINT32_MAX)return -1;
    unsigned index=d->count++;struct wn_token *t=d->storage+index;
    t->start=(uint32_t)*at;uint8_t major;uint64_t count;
    if(argument((const uint8_t*)d->text,d->size,at,&major,&t->header,&count))return -1;
    t->type=major==0 ? '0':major==1 ? '-':major==2 ? 'b':major==3 ? '"':
        major==4 ? '[':major==5 ? '{':major==7 && count==20 ? 'f':
        major==7 && count==21 ? 't':major==7 && count==22 ? 'n':'x';
    if(major==2 || major==3){
        if(count>d->size-*at)return -1;
        if(major==3 && !utf8((const uint8_t*)d->text+*at,(size_t)count))return -1;
        *at+=(size_t)count;
    }else if(major==4 || major==5){
        if(count>1024 || (major==5 && count>64))return -1;
        for(uint64_t i=0;i<count;i++){
            bool child_compact=false;
            if(major==5){
                int key=value(d,at,depth+1,NULL,false);
                if(key<0 || d->storage[key].type!='"')return -1;
                for(unsigned old=index+1;old<(unsigned)key;old=d->storage[old+1].next){
                    const struct wn_token *a=d->storage+old,*b=d->storage+key;
                    size_t n=a->end-a->start-a->header;
                    if(n==b->end-b->start-b->header &&
                       !memcmp(d->text+a->start+a->header,d->text+b->start+b->header,n))return -1;
                }
                child_compact=view && wn_doc_equal(d,key,wn_key_name(view));
            }
            if(value(d,at,depth+1,view,child_compact)<0)return -1;
            if(major==4 && compact)d->count=index+1;
        }
    }else if(major>1 && t->type=='x')return -1;
    t->end=(uint32_t)*at;t->next=(uint16_t)d->count;return (int)index;
}
static int parse(struct wn_doc *d,const void *data,size_t size,size_t maximum,
    struct wn_token *tokens,unsigned capacity,const char *view)
{
    if(!d || !data || !size || size>maximum || maximum>(view ? 4U*1024*1024:65536) ||
       !tokens || !capacity || capacity>256)return -1;
    memset(d,0,sizeof *d);d->text=data;d->size=size;d->storage=tokens;d->capacity=capacity;
    size_t at=0;return value(d,&at,0,view,false)<0 || at!=size ? -1:0;
}
int wn_doc_parse_into(struct wn_doc *d,const void *data,size_t size,size_t maximum,
    struct wn_token *tokens,unsigned capacity)
{return parse(d,data,size,maximum,tokens,capacity,NULL);}
int wn_doc_parse_bounded(struct wn_doc *d,const void *data,size_t size,size_t maximum)
{return d ? parse(d,data,size,maximum,d->tokens,WN_TOKENS,NULL):-1;}
int wn_doc_parse(struct wn_doc *d,const void *data,size_t size)
{return wn_doc_parse_bounded(d,data,size,WN_CONTROL_MAX);}
int wn_doc_parse_array_view(struct wn_doc *d,const void *data,size_t size,size_t maximum,const char *field)
{return d && field && *field ? parse(d,data,size,maximum,d->tokens,WN_TOKENS,field):-1;}
const struct wn_token *wn_doc_token(const struct wn_doc *d,int index)
{return d && index>=0 && (unsigned)index<d->count ? d->storage+index:NULL;}
int wn_doc_array_next(const struct wn_doc *d,int array,size_t *cursor,struct wn_doc *child)
{
    const struct wn_token *t=wn_doc_token(d,array);
    if(!t || t->type!='[' || !cursor || !child)return -1;
    size_t at=*cursor ? *cursor:t->start+t->header;
    if(at==t->end)return 0;
    if(at<t->start+t->header || at>t->end)return -1;
    memset(child,0,sizeof *child);child->text=d->text;child->size=t->end;
    child->storage=child->tokens;child->capacity=WN_TOKENS;
    if(value(child,&at,0,NULL,false)<0 || at>t->end)return -1;
    *cursor=at;return 1;
}
int wn_doc_text(const struct wn_doc *d,int token,const char **text,size_t *size)
{
    const struct wn_token *t=wn_doc_token(d,token);
    if(!t || t->type!='"' || !text || !size)return -1;
    *text=d->text+t->start+t->header;*size=t->end-t->start-t->header;return 0;
}
bool wn_doc_equal(const struct wn_doc *d,int token,const char *text)
{
    const char *p;size_t n;return text && !wn_doc_text(d,token,&p,&n) && strlen(text)==n && !memcmp(p,text,n);
}
int wn_doc_string(const struct wn_doc *d,int token,char *out,size_t capacity)
{
    const char *p;size_t n;
    if(!out || wn_doc_text(d,token,&p,&n) || n>=capacity || memchr(p,0,n))return -1;
    memcpy(out,p,n);out[n]=0;return (int)n;
}
int wn_doc_member(const struct wn_doc *d,unsigned object,const char *key)
{
    const struct wn_token *t=wn_doc_token(d,(int)object);
    if(!t || t->type!='{')return -1;
    for(unsigned i=object+1;i<t->next;i=d->storage[i+1].next)
        if(wn_doc_equal(d,(int)i,wn_key_name(key)))return (int)i+1;
    return -1;
}
bool wn_doc_fields(const struct wn_doc *d,unsigned object,const char *const *fields)
{
    const struct wn_token *t=wn_doc_token(d,(int)object);if(!t || t->type!='{')return false;
    for(unsigned i=object+1;i<t->next;i=d->storage[i+1].next){
        bool found=false;for(unsigned j=0;fields[j];j++)if(wn_doc_equal(d,(int)i,wn_key_name(fields[j])))found=true;
        if(!found)return false;
    }
    return true;
}
int wn_doc_u64(const struct wn_doc *d,int token,uint64_t *out)
{
    const struct wn_token *t=wn_doc_token(d,token);if(!t || t->type!='0' || !out)return -1;
    size_t at=t->start;uint8_t major,header;return argument((const uint8_t*)d->text,d->size,&at,&major,&header,out);
}
int wn_doc_bytes(const struct wn_doc *d,int token,const uint8_t **out,size_t *size)
{
    const struct wn_token *t=wn_doc_token(d,token);if(!t || t->type!='b' || !out || !size)return -1;
    *out=(const uint8_t*)d->text+t->start+t->header;*size=t->end-t->start-t->header;return 0;
}
int wn_doc_copy_bytes(const struct wn_doc *d,int token,void *out,size_t cap,size_t *size)
{
    const uint8_t *p;size_t n;if(!out || !size || wn_doc_bytes(d,token,&p,&n) || n>cap)return -1;
    memcpy(out,p,n);*size=n;return 0;
}

int wn_doc_hash_string(const struct wn_doc *d,int token,char out[65])
{
    const uint8_t *bytes;size_t n;if(!out || wn_doc_bytes(d,token,&bytes,&n) || n!=32)return -1;
    static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<32;i++){out[i*2]=hex[bytes[i]>>4];out[i*2+1]=hex[bytes[i]&15];}
    out[64]=0;return 0;
}
