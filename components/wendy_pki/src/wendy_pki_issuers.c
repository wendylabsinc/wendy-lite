#include "wendy_pki_issuers.h"
#include "wendy_pki_crypto.h"
#include <string.h>
static size_t u16(const uint8_t *p){return ((size_t)p[0]<<8)|p[1];}
static size_t u24(const uint8_t *p){return ((size_t)p[0]<<16)|((size_t)p[1]<<8)|p[2];}
int pki_issuer_hint(const uint8_t hashes[][32],size_t count,char output[PKI_ISSUER_HINT_SIZE])
{
    output[0]=0;
    if(!count || count>7)return -1;
    uint8_t sorted[7][32],digest[32];
    memcpy(sorted,hashes,count*32);
    for(size_t i=1;i<count;i++)for(size_t j=i;j && memcmp(sorted[j-1],sorted[j],32)>0;j--){
        uint8_t temporary[32];memcpy(temporary,sorted[j],32);
        memcpy(sorted[j],sorted[j-1],32);memcpy(sorted[j-1],temporary,32);
    }
    if(wendy_pki_sha256(&sorted[0][0],count*32,digest))return -1;
    static const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    memcpy(output,PKI_ISSUER_HINT_PREFIX,sizeof PKI_ISSUER_HINT_PREFIX-1);
    char *p=output+sizeof PKI_ISSUER_HINT_PREFIX-1;
    /* Existing ALPN digest encoding only; certificate bytes stay binary DER. */
    for(unsigned i=0;i<15;i+=3){
        *p++=alphabet[digest[i]>>2];*p++=alphabet[((digest[i]&3)<<4)|(digest[i+1]>>4)];
        *p++=alphabet[((digest[i+1]&15)<<2)|(digest[i+2]>>6)];*p++=alphabet[digest[i+2]&63];
    }
    *p++=alphabet[digest[15]>>2];*p++=alphabet[(digest[15]&3)<<4];*p=0;
    return 0;
}
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
