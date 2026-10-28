/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_pki_operator.h"
#include "wendy_pki_alloc.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_hash.h"
#include "wendy_peer_identity.h"
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <string.h>

static bool hex(unsigned char c)
{return (c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F');}
int wendy_pki_operator_principal(const char *principal,size_t size,const char *tenant)
{
    static const char prefix[]="spiffe://wendy.sh/tenant/";
    size_t tenant_at=sizeof prefix-1,subject_at=tenant_at+36+10;
    if(!principal || size<=subject_at || size>WENDY_PKI_OPERATOR_PRINCIPAL_MAX ||
       memcmp(principal,prefix,sizeof prefix-1) ||
       !wendy_identity_uuid((const unsigned char*)principal+tenant_at,36) ||
       memcmp(principal+tenant_at+36,"/operator/",10))return -1;
    /* Keep the offsets derived from the literal, rather than a device offset. */
    if(tenant && (strlen(tenant)!=36 || memcmp(principal+tenant_at,tenant,36)))return -1;
    for(size_t i=subject_at;i<size;i++){
        unsigned char c=(unsigned char)principal[i];
        if(c=='%') {if(i+2>=size || !hex(principal[i+1]) || !hex(principal[i+2]))return -1;i+=2;}
        else if(!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') ||
            (c && strchr("-._~!$&'()*+,;=:@/",c))))return -1;
    }
    return subject_at<size ? 0:-1;
}

int wendy_pki_operator_manifest_verify(const struct wendy_pki_operator_peer *peer,
    const void *body,size_t size,const uint8_t *signature,size_t signature_size)
{
    static const uint8_t domain[]="wendy-local-mesh/manifest/4";
    static const uint8_t mldsa_spki[]={0x30,0x82,0x07,0xb2,0x30,0x0b,0x06,0x09,0x60,
        0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x12,0x03,0x82,0x07,0xa1,0x00};
    static const uint8_t p256_spki[]={0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,
        0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04};
    if(!peer || !body || !size || size>WENDY_PKI_OPERATOR_BODY_MAX || !signature ||
       !peer->spki_size || peer->spki_size>sizeof peer->spki || wendy_pki_crypto_init())return -1;
    size_t principal_size=strnlen(peer->principal,sizeof peer->principal);
    if(wendy_pki_operator_principal(peer->principal,principal_size,NULL))return -1;
    bool mldsa=peer->spki_size==sizeof mldsa_spki+1952 && !memcmp(peer->spki,mldsa_spki,sizeof mldsa_spki);
    if(!mldsa && (peer->spki_size!=sizeof p256_spki+64 || memcmp(peer->spki,p256_spki,sizeof p256_spki)))return -1;
    if(mldsa ? signature_size!=WENDY_PKI_MESH_SIGNATURE_MAX : signature_size<8 || signature_size>80)return -1;
    uint8_t length[4]={(uint8_t)(principal_size>>24),(uint8_t)(principal_size>>16),
        (uint8_t)(principal_size>>8),(uint8_t)principal_size};
    mbedtls_pk_context key;mbedtls_pk_init(&key);int result=-1;uint8_t *message=NULL;
    if(mbedtls_pk_parse_public_key(&key,peer->spki,peer->spki_size))goto done;
    if(mldsa){
        size_t prefix=sizeof domain+sizeof length+principal_size;
        message=pki_owned_malloc(prefix+size);if(!message)goto done;
        memcpy(message,domain,sizeof domain);memcpy(message+sizeof domain,length,sizeof length);
        memcpy(message+sizeof domain+sizeof length,peer->principal,principal_size);
        memcpy(message+prefix,body,size);
        result=mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_MLDSA65,&key,MBEDTLS_MD_NONE,
            message,prefix+size,signature,signature_size) ? -1:0;
    }else{
        /* The primary P-256 key selects ECDSA/SHA256, exactly as WendyOS. */
        uint8_t digest[32];size_t written=0;psa_hash_operation_t operation=PSA_HASH_OPERATION_INIT;
        bool okay=psa_hash_setup(&operation,PSA_ALG_SHA_256)==PSA_SUCCESS &&
            wendy_pki_hash_update_bounded(&operation,domain,sizeof domain)==PSA_SUCCESS &&
            wendy_pki_hash_update_bounded(&operation,length,sizeof length)==PSA_SUCCESS &&
            wendy_pki_hash_update_bounded(&operation,(const uint8_t*)peer->principal,principal_size)==PSA_SUCCESS &&
            wendy_pki_hash_update_bounded(&operation,body,size)==PSA_SUCCESS &&
            psa_hash_finish(&operation,digest,sizeof digest,&written)==PSA_SUCCESS && written==sizeof digest;
        psa_hash_abort(&operation);
        if(okay)result=mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_ECDSA,&key,MBEDTLS_MD_SHA256,
            digest,sizeof digest,signature,signature_size) ? -1:0;
    }
done:
    pki_owned_free(message);mbedtls_pk_free(&key);return result;
}
