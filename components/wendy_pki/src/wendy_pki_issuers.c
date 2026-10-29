#include "wendy_pki_issuers.h"
#include "wendy_pki_crypto.h"
#include <string.h>
static size_t u16(const uint8_t *p){return ((size_t)p[0]<<8)|p[1];}
static size_t u24(const uint8_t *p){return ((size_t)p[0]<<16)|((size_t)p[1]<<8)|p[2];}
static bool message_body(const uint8_t **p,size_t *size,unsigned type)
{
    if(!*p || *size<4 || (*p)[0]!=type || u24(*p+1)!=*size-4)return false;
    *p+=4;*size-=4;return true;
}
static bool skip(const uint8_t **p,size_t *left,size_t count)
{
    if(count>*left)return false;
    *p+=count;*left-=count;return true;
}
bool pki_client_hello_offers(const uint8_t *p,size_t left,const char *protocol)
{
    if(!protocol || !*protocol || !message_body(&p,&left,1) || !skip(&p,&left,34) || !left)return false;
    size_t count=*p;if(!skip(&p,&left,1+count) || left<2)return false;
    count=u16(p);if(!skip(&p,&left,2+count) || !left)return false;
    count=*p;if(!skip(&p,&left,1+count) || left<2)return false;
    count=u16(p);if(!skip(&p,&left,2) || count!=left)return false;
    while(left>=4){
        size_t type=u16(p),length=u16(p+2);if(!skip(&p,&left,4) || length>left)return false;
        if(type==16){
            if(length<2 || u16(p)!=length-2)return false;
            const uint8_t *entry=p+2;size_t remaining=length-2,wanted=strlen(protocol);
            while(remaining){
                size_t n=*entry++;remaining--;
                if(n>remaining)return false;
                if(n==wanted && !memcmp(entry,protocol,n))return true;
                entry+=n;remaining-=n;
            }
            return false;
        }
        if(!skip(&p,&left,length))return false;
    }
    return false;
}
unsigned pki_certificate_message_count(const uint8_t *p,size_t left)
{
    if(!message_body(&p,&left,11) || !left)return 0;
    size_t context=*p;if(!skip(&p,&left,context+1) || left<3)return 0;
    size_t length=u24(p);if(!skip(&p,&left,3) || length!=left)return 0;
    unsigned count=0;
    while(left){
        if(left<3)return 0;
        size_t n=u24(p);if(!n || !skip(&p,&left,3) || !skip(&p,&left,n) || left<2)return 0;
        n=u16(p);if(!skip(&p,&left,2+n))return 0;
        count++;
    }
    return count;
}

/* The embedded NUL terminates the ordinary service name for existing C API
 * consumers; explicit TLS lengths carry the bounded binary suffix on wire. */
static const uint8_t issuer_marker[]={0,'W','C','I',1};
static const uint8_t cached_marker[]="wendy-net-cached\0";
static bool decode_issuer_protocol(const uint8_t *name,size_t n,const char *app,
    const uint8_t **hashes,unsigned *count)
{
    size_t prefix=strlen(app);
    if(n<=prefix+sizeof issuer_marker || memcmp(name,app,prefix) ||
       memcmp(name+prefix,issuer_marker,sizeof issuer_marker))return false;
    size_t bytes=n-prefix-sizeof issuer_marker;
    if(bytes%16 || bytes>PKI_ISSUER_CHAIN_MAX*16)return false;
    *hashes=name+prefix+sizeof issuer_marker;*count=(unsigned)(bytes/16);return true;
}
typedef void (*alpn_visitor)(void *,const uint8_t *,size_t);
static void visit_client_protocols(const uint8_t *p,size_t left,alpn_visitor visit,void *context)
{
    if(!message_body(&p,&left,1) || !skip(&p,&left,34) || !left)return;
    size_t count=*p;if(!skip(&p,&left,1+count) || left<2)return;
    count=u16(p);if(!skip(&p,&left,2+count) || !left)return;
    count=*p;if(!skip(&p,&left,1+count) || left<2)return;
    count=u16(p);if(!skip(&p,&left,2) || count!=left)return;
    while(left>=4){
        size_t type=u16(p),n=u16(p+2);if(!skip(&p,&left,4) || n>left)return;
        if(type==16){
            if(n<2 || u16(p)!=n-2)return;
            const uint8_t *name=p+2;size_t remaining=n-2;
            while(remaining){
                size_t length=*name++;remaining--;
                if(!length || length>remaining)return;
                visit(context,name,length);name+=length;remaining-=length;
            }
            return;
        }
        if(!skip(&p,&left,n))return;
    }
}
int pki_issuer_protocols(struct pki_issuer_state *s,const char *app)
{
    if(!s || !app || !s->chain_count || s->chain_count>PKI_ISSUER_CHAIN_MAX)return -1;
    size_t base=strlen(app),prefix=base+sizeof issuer_marker;
    size_t full=prefix+s->chain_count*16;
    if(!base || full>255)return -1;
    s->application=app;memcpy(s->hint,app,base);
    memcpy(s->hint+base,issuer_marker,sizeof issuer_marker);
    memcpy(s->hint+prefix,s->chain,s->chain_count*16);s->hint[full]=0;
    s->hint_length=full;unsigned n=0;
    for(unsigned count=s->chain_count;count;count--){
        s->protocols[n]=s->hint;s->protocol_lengths[n++]=prefix+count*16;
    }
    s->protocols[n]=app;s->protocol_lengths[n++]=base;
    unsigned chunk=0,extra=0;
    for(unsigned i=0;i<s->available_count;i++){
        bool own=false;
        for(unsigned j=0;j<s->chain_count;j++)if(!memcmp(s->available[i],s->chain[j],16))own=true;
        if(own)continue;
        if(!extra)memcpy(s->cached_hint[chunk],cached_marker,sizeof cached_marker-1);
        memcpy(s->cached_hint[chunk]+sizeof cached_marker-1+16*extra++,s->available[i],16);
        if(extra==PKI_ISSUER_CHAIN_MAX){
            s->protocols[n]=(const char *)s->cached_hint[chunk];s->protocol_lengths[n++]=sizeof cached_marker-1+16*extra;
            chunk++;extra=0;if(chunk==3)break;
        }
    }
    if(extra){s->protocols[n]=(const char *)s->cached_hint[chunk];s->protocol_lengths[n++]=sizeof cached_marker-1+16*extra;}
    s->protocols[n]=NULL;return 0;
}
struct issuer_selection {struct pki_issuer_state *state;unsigned count;};
static void select_protocol(void *context,const uint8_t *name,size_t n)
{
    struct issuer_selection *selection=context;struct pki_issuer_state *s=selection->state;
    const uint8_t *hashes;unsigned count;
    if(!decode_issuer_protocol(name,n,s->application,&hashes,&count) || count<=selection->count)return;
    for(unsigned i=0;i<count;i++){
        bool known=false;
        for(unsigned j=0;j<s->available_count;j++)if(!memcmp(hashes+16*i,s->available[j],16))known=true;
        if(!known)return;
    }
    memcpy(s->hint,name,n);s->hint[n]=0;s->hint_length=n;selection->count=count;
}
size_t pki_issuer_select(struct pki_issuer_state *s,const uint8_t *message,size_t size)
{
    struct issuer_selection selection={.state=s};
    visit_client_protocols(message,size,select_protocol,&selection);
    return selection.count ? s->hint_length:0;
}
struct issuer_possession {const char *app;const uint8_t *hash;bool found;};
static void peer_possesses(void *context,const uint8_t *name,size_t n)
{
    struct issuer_possession *p=context;const uint8_t *hashes=NULL;unsigned count=0;
    if(n>sizeof cached_marker-1 && !memcmp(name,cached_marker,sizeof cached_marker-1)){
        size_t bytes=n-(sizeof cached_marker-1);
        if(bytes%16 || bytes>PKI_ISSUER_CHAIN_MAX*16)return;
        hashes=name+sizeof cached_marker-1;count=(unsigned)(bytes/16);
    }else if(!decode_issuer_protocol(name,n,p->app,&hashes,&count))return;
    for(unsigned i=0;i<count;i++)if(!memcmp(hashes+16*i,p->hash,16))p->found=true;
}
bool pki_issuer_peer_has(const uint8_t *message,size_t size,const char *app,const uint8_t hash[16])
{
    struct issuer_possession p={.app=app,.hash=hash};
    visit_client_protocols(message,size,peer_possesses,&p);return p.found;
}
bool pki_issuer_ack_has(const uint8_t *name,size_t size,const char *app,const uint8_t hash[16])
{
    const uint8_t *hashes;unsigned count;
    if(!name || !decode_issuer_protocol(name,size,app,&hashes,&count))return false;
    for(unsigned i=0;i<count;i++)if(!memcmp(hashes+16*i,hash,16))return true;
    return false;
}

bool pki_certificate_message_last(const uint8_t *p,size_t left,const uint8_t **last,size_t *length)
{
    if(!pki_certificate_message_count(p,left) || !message_body(&p,&left,11))return false;
    size_t context=*p;if(!skip(&p,&left,1+context) || !skip(&p,&left,3))return false;
    while(left){
        if(left<3)return false;
        size_t n=u24(p);if(!skip(&p,&left,3) || n>left)return false;
        *last=p;*length=n;
        if(!skip(&p,&left,n) || left<2)return false;
        n=u16(p);if(!skip(&p,&left,2+n))return false;
    }
    return *last!=NULL;
}

size_t pki_certificate_message_der_bytes(const uint8_t *p,size_t left)
{
    if(!pki_certificate_message_count(p,left) || !message_body(&p,&left,11))return 0;
    size_t context=*p;if(!skip(&p,&left,1+context) || !skip(&p,&left,3))return 0;
    size_t bytes=0;
    while(left){
        if(left<3)return 0;
        size_t n=u24(p);if(!skip(&p,&left,3) || !skip(&p,&left,n) || left<2)return 0;
        bytes+=n;n=u16(p);if(!skip(&p,&left,2+n))return 0;
    }
    return bytes;
}
