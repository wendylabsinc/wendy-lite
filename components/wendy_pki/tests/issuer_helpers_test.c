/* Ordinary optional-ALPN digest and complete TLS1.3 message layouts. */
#include "wendy_pki_issuers.h"
#include "wendy_pki_crypto.h"
#include <assert.h>
#include <string.h>
static void header(uint8_t *out,unsigned type,size_t size)
{out[0]=(uint8_t)type;out[1]=(uint8_t)(size>>16);out[2]=(uint8_t)(size>>8);out[3]=(uint8_t)size;}
static void u16(uint8_t *out,size_t size){out[0]=(uint8_t)(size>>8);out[1]=(uint8_t)size;}
int main(void)
{
    uint8_t hashes[3][32];
    for(unsigned i=0;i<3;i++){uint8_t input=(uint8_t)i;assert(!wendy_pki_sha256(&input,1,hashes[i]));}
    char first[PKI_ISSUER_HINT_SIZE],second[PKI_ISSUER_HINT_SIZE];
    assert(!pki_issuer_hint(hashes,3,first));
    assert(!strcmp(first,"wendy-net-issuers/TkHqdr9wPoZGWHtuXipxqg"));
    uint8_t swap[32];memcpy(swap,hashes[0],32);memcpy(hashes[0],hashes[2],32);memcpy(hashes[2],swap,32);
    assert(!pki_issuer_hint(hashes,3,second) && !strcmp(first,second));
    /* One real service and an auxiliary issuer digest in a complete hello. */
    const char *service="wendy-local-mesh-ble/2";
    uint8_t hello[180]={0};size_t at=4+34;
    hello[at++]=0;u16(hello+at,2);at+=2;hello[at++]=0x13;hello[at++]=1;
    hello[at++]=1;hello[at++]=0;
    size_t extensions=at;at+=2;u16(hello+at,16);at+=2;
    size_t list=2+1+strlen(service)+1+strlen(first);
    u16(hello+at,list);at+=2;u16(hello+at,list-2);at+=2;
    hello[at++]=(uint8_t)strlen(service);memcpy(hello+at,service,strlen(service));at+=strlen(service);
    hello[at++]=(uint8_t)strlen(first);memcpy(hello+at,first,strlen(first));at+=strlen(first);
    u16(hello+extensions,at-extensions-2);header(hello,1,at-4);
    assert(pki_client_hello_offers(hello,at,service));assert(pki_client_hello_offers(hello,at,first));
    assert(!pki_client_hello_offers(hello,at,"another-service"));
    /* The wire count must survive later library compaction of parsed chains. */
    for(unsigned n=1;n<=4;n+=3){
        uint8_t message[80]={0};at=8;
        for(unsigned i=0;i<n;i++){message[at++]=0;message[at++]=0;message[at++]=3;
            message[at++]=0x30;message[at++]=1;message[at++]=0;message[at++]=0;message[at++]=0;}
        size_t length=at-8;message[5]=(uint8_t)(length>>16);message[6]=(uint8_t)(length>>8);message[7]=(uint8_t)length;
        header(message,11,at-4);assert(pki_certificate_message_count(message,at)==n);
    }
    return 0;
}
