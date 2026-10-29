/* Ordinary binary CA availability, partial acknowledgement and TLS1.3 framing. */
#include "wendy_pki_issuers.h"
#include "wendy_pki_crypto.h"
#include <assert.h>
#include <string.h>
static void header(uint8_t *out,unsigned type,size_t size)
{out[0]=(uint8_t)type;out[1]=(uint8_t)(size>>16);out[2]=(uint8_t)(size>>8);out[3]=(uint8_t)size;}
static void u16(uint8_t *out,size_t size){out[0]=(uint8_t)(size>>8);out[1]=(uint8_t)size;}
int main(void)
{
    const char *service="wendy-local-mesh-ble/2";
    struct pki_issuer_state client={.chain_count=3},server={0};
    for(unsigned i=0;i<3;i++){
        uint8_t input=(uint8_t)i,hash[32];assert(!wendy_pki_sha256(&input,1,hash));
        memcpy(client.chain[i],hash,16);
    }
    assert(!pki_issuer_protocols(&client,service));
    /* Full own path and decreasing prefixes are opaque, length-framed names. */
    uint8_t hello[512]={0};size_t at=4+34;
    hello[at++]=0;u16(hello+at,2);at+=2;hello[at++]=0x13;hello[at++]=1;
    hello[at++]=1;hello[at++]=0;
    size_t extensions=at;at+=2;u16(hello+at,16);at+=2;
    size_t extension_length=at;at+=2;size_t list_length=at;at+=2;
    for(unsigned i=0;client.protocols[i];i++){
        size_t n=client.protocol_lengths[i];assert(n && n<=255);
        hello[at++]=(uint8_t)n;memcpy(hello+at,client.protocols[i],n);at+=n;
    }
    u16(hello+list_length,at-list_length-2);
    u16(hello+extension_length,at-extension_length-2);
    u16(hello+extensions,at-extensions-2);header(hello,1,at-4);
    assert(pki_client_hello_offers(hello,at,service));
    for(unsigned i=0;i<3;i++)assert(pki_issuer_peer_has(hello,at,service,client.chain[i]));
    server.application=service;server.available_count=2;
    memcpy(server.available,client.chain,2*16);
    size_t selected=pki_issuer_select(&server,hello,at);
    assert(selected==strlen(service)+5+2*16);
    assert(pki_issuer_ack_has((const uint8_t *)server.hint,selected,service,client.chain[0]));
    assert(pki_issuer_ack_has((const uint8_t *)server.hint,selected,service,client.chain[1]));
    assert(!pki_issuer_ack_has((const uint8_t *)server.hint,selected,service,client.chain[2]));
    /* The wire count must survive later library compaction of parsed chains. */
    for(unsigned n=1;n<=4;n+=3){
        uint8_t message[80]={0};at=8;
        for(unsigned i=0;i<n;i++){message[at++]=0;message[at++]=0;message[at++]=3;
            message[at++]=0x30;message[at++]=1;message[at++]=0;message[at++]=0;message[at++]=0;}
        size_t length=at-8;message[5]=(uint8_t)(length>>16);message[6]=(uint8_t)(length>>8);message[7]=(uint8_t)length;
        header(message,11,at-4);assert(pki_certificate_message_count(message,at)==n);
        assert(pki_certificate_message_der_bytes(message,at)==3*n);
    }
    return 0;
}
