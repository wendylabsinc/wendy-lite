/* Native artifacts retain their v4 domain while the existing leaf uses v3. */
#include "artifact_crypto.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_mesh.h"
#include <assert.h>
#include <string.h>
#include <psa/crypto.h>
static void reference(const char *domain,const char *principal,const void *body,size_t size,uint8_t hash[32])
{
    psa_hash_operation_t operation=PSA_HASH_OPERATION_INIT;size_t written=0;
    assert(psa_hash_setup(&operation,PSA_ALG_SHA_256)==PSA_SUCCESS);
    assert(psa_hash_update(&operation,(const uint8_t *)domain,strlen(domain)+1)==PSA_SUCCESS);
    if(principal){
        const uint8_t length[]={0,0,0,105};
        assert(psa_hash_update(&operation,length,sizeof length)==PSA_SUCCESS);
        assert(psa_hash_update(&operation,(const uint8_t *)principal,105)==PSA_SUCCESS);
    }
    assert(psa_hash_update(&operation,body,size)==PSA_SUCCESS);
    assert(psa_hash_finish(&operation,hash,32,&written)==PSA_SUCCESS && written==32);
}
int main(void)
{
    assert(!wendy_pki_crypto_init());uint8_t der[256];int bytes=wendy_pki_generate_key_der(der,sizeof der);assert(bytes>0);
    mbedtls_pk_context key;mbedtls_pk_init(&key);
    assert(!mbedtls_pk_parse_key(&key,der+sizeof der-bytes,(size_t)bytes,NULL,0));
    const char *principal="spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/00000000-0000-4000-8000-000000000004";
    const uint8_t body[]={0xa1,0x61,'x',0x01};uint8_t hash[32],signature[80];size_t written=0;
    const char *domains[]={"wendy-local-mesh/manifest/4","wendy-mesh-service/record/1","wendy-mesh-service/inventory/1"};
    for(unsigned kind=0;kind<3;kind++){
        assert(pki_artifact_signature_capacity(&key)==80);
        assert(!pki_artifact_sign(&key,kind,principal,body,sizeof body,signature,sizeof signature,&written));
        reference(domains[kind],kind ? NULL:principal,body,sizeof body,hash);
        assert(!mbedtls_pk_verify(&key,MBEDTLS_MD_SHA256,hash,sizeof hash,signature,written));
    }
    assert(!pki_artifact_sign(&key,0,principal,body,sizeof body,signature,sizeof signature,&written));
    uint8_t public_der[128];int n=mbedtls_pk_write_pubkey_der(&key,public_der,sizeof public_der);assert(n>0);
    struct wendy_pki_mesh_key view={.spki=public_der+sizeof public_der-n,.spki_size=(size_t)n};
    strcpy(view.device,principal+69);
    assert(!wendy_pki_mesh_verify_key(&view,principal,body,sizeof body,signature,written));
    uint8_t legacy[32];assert(!wendy_pki_mesh_digest(principal,body,sizeof body,legacy));
    reference("wendy-local-mesh/manifest/3",principal,body,sizeof body,hash);assert(!memcmp(hash,legacy,32));
    mbedtls_pk_free(&key);return 0;
}
