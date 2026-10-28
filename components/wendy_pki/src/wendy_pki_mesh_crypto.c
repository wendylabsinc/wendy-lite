#include "artifact_crypto.h"
#include "wendy_pki_mesh.h"
#include "wendy_pki_alloc.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_hash.h"
#include "wendy_peer_identity.h"
#include <mbedtls/pk.h>
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include <mbedtls/private/pk_private.h>
#undef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include <psa/crypto.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* sizeof includes the domain's required NUL byte. */
static const uint8_t domain[] = "wendy-local-mesh/manifest/4";
#if CONFIG_WENDY_MESH_LEAF
/* Existing Lite leaf wire contract, removed with that component at cutover. */
static const uint8_t leaf_domain[] = "wendy-local-mesh/manifest/3";
#else
#define leaf_domain domain
#endif
/* Canonical principals have 105 UTF-8 bytes. Encode their byte length,
 * not a C string terminator, before the exact principal and CBOR body. */
static const uint8_t principal_size[] = { 0, 0, 0, 105 };
/* RFC 9881 ML-DSA-65 SubjectPublicKeyInfo: the only DER header that
 * wendy_pki_mesh_chain stores, followed by the 1952-byte public key. */
static const uint8_t mldsa65_spki[] = { 0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60,
    0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12, 0x03, 0x82, 0x07, 0xa1, 0x00 };

static bool mldsa65_key(const struct wendy_pki_mesh_key *peer)
{
    return peer->spki_size==sizeof mldsa65_spki+1952 &&
        !memcmp(peer->spki,mldsa65_spki,sizeof mldsa65_spki);
}
static int preimage_valid(const char* principal, const void* body, size_t size)
{
    return !principal || strlen(principal) != 105
            || memcmp(principal, "spiffe://wendy.sh/tenant/", 25)
            || !wendy_identity_uuid((const unsigned char*)principal + 25, 36)
            || memcmp(principal + 61, "/device/", 8)
            || !wendy_identity_uuid((const unsigned char*)principal + 69, 36) || !body || !size
            || size > 32768 || wendy_pki_crypto_init()
        ? -1
        : 0;
}
static int mesh_digest(const char* principal, const void* body, size_t size, uint8_t hash[32],
    const uint8_t *prefix,size_t prefix_size)
{
    if (!hash || preimage_valid(principal, body, size))
        return -1;
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    size_t written = 0;
    int result = psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS
            && wendy_pki_hash_update_bounded(&op, prefix, prefix_size) == PSA_SUCCESS
            && wendy_pki_hash_update_bounded(&op, principal_size, sizeof principal_size) == PSA_SUCCESS
            && wendy_pki_hash_update_bounded(&op, (const uint8_t*)principal, 105) == PSA_SUCCESS
            && wendy_pki_hash_update_bounded(&op, body, size) == PSA_SUCCESS
            && psa_hash_finish(&op, hash, 32, &written) == PSA_SUCCESS && written == 32
        ? 0
        : -1;
    psa_hash_abort(&op);
    return result;
}
int wendy_pki_mesh_digest(const char *principal,const void *body,size_t size,uint8_t hash[32])
{return mesh_digest(principal,body,size,hash,leaf_domain,sizeof leaf_domain);}
int wendy_pki_artifact_digest(unsigned kind,const char *principal,const void *body,size_t size,uint8_t hash[32])
{return kind ? -1:mesh_digest(principal,body,size,hash,domain,sizeof domain);}
/* Pure ML-DSA verifies the complete preimage, not its SHA-256. This matches
 * the Linux router's crypto.Hash(0) signature and mldsa.Verify(..., nil). */
static int verify_mldsa65(mbedtls_pk_context* key, const char* principal, const void* body,
    size_t size, const uint8_t* signature, size_t signature_size,
    const uint8_t *domain,size_t domain_size)
{
    size_t prefix = domain_size + sizeof principal_size + 105;
    uint8_t* message = pki_owned_malloc(prefix + size);
    if (!message)
        return -1;
    memcpy(message, domain, domain_size);
    memcpy(message + domain_size, principal_size, sizeof principal_size);
    memcpy(message + domain_size + sizeof principal_size, principal, 105);
    memcpy(message + prefix, body, size);
    int result = mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_MLDSA65, key, MBEDTLS_MD_NONE, message,
                     prefix + size, signature, signature_size)
        ? -1
        : 0;
    pki_owned_free(message);
    return result;
}
static int mesh_verify_key(const struct wendy_pki_mesh_key* peer, const char* principal,
    const void* body, size_t size, const uint8_t* signature, size_t signature_size,
    const uint8_t *domain,size_t domain_size)
{
    if (!peer || !peer->spki || !peer->spki_size || peer->spki_size > WENDY_PKI_MESH_SPKI_MAX || !signature)
        return -1;
    /* The certified key alone selects the scheme. Each accepts only its own
     * encoding: an ECDSA DER signature, or exactly one ML-DSA-65 signature. */
    bool mldsa=mldsa65_key(peer);
    if (mldsa ? signature_size != WENDY_PKI_MESH_SIGNATURE_MAX
              : signature_size < 8 || signature_size > 80)
        return -1;
    uint8_t hash[32];
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int result = (mldsa ? preimage_valid(principal, body, size)
                        : mesh_digest(principal, body, size, hash,domain,domain_size))
            || strcmp(principal + 69, peer->device)
            || mbedtls_pk_parse_public_key(&key, peer->spki, peer->spki_size)
            || (mldsa ? verify_mldsa65(&key, principal, body, size, signature, signature_size,domain,domain_size)
                      : mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_ECDSA, &key, MBEDTLS_MD_SHA256,
                            hash, sizeof hash, signature, signature_size))
        ? -1
        : 0;
    mbedtls_pk_free(&key);
    return result;
}

int wendy_pki_mesh_verify_key(const struct wendy_pki_mesh_key *peer,const char *principal,
    const void *body,size_t size,const uint8_t *signature,size_t signature_size)
{return mesh_verify_key(peer,principal,body,size,signature,signature_size,domain,sizeof domain);}

/* WendyOS service records have their own domain and include their owner in
 * the exact CBOR body. They never reuse a route-manifest signature. */
static const uint8_t service_domain[]="wendy-mesh-service/record/1";
static const uint8_t inventory_domain[]="wendy-mesh-service/inventory/1";
static int catalogue_digest(const uint8_t *domain,size_t domain_size,const void *body,
    size_t size,size_t maximum,uint8_t hash[32])
{
    if(!body || !size || size>maximum || !hash || wendy_pki_crypto_init())return -1;
    psa_hash_operation_t operation=PSA_HASH_OPERATION_INIT;size_t written=0;
    int result=psa_hash_setup(&operation,PSA_ALG_SHA_256)==PSA_SUCCESS &&
        wendy_pki_hash_update_bounded(&operation,domain,domain_size)==PSA_SUCCESS &&
        wendy_pki_hash_update_bounded(&operation,body,size)==PSA_SUCCESS &&
        psa_hash_finish(&operation,hash,32,&written)==PSA_SUCCESS && written==32 ? 0:-1;
    psa_hash_abort(&operation);return result;
}
int wendy_pki_service_digest(const void *body,size_t size,uint8_t hash[32])
{
    return catalogue_digest(service_domain,sizeof service_domain,body,size,8192,hash);
}
int wendy_pki_inventory_digest(const void *body,size_t size,uint8_t hash[32])
{
    return catalogue_digest(inventory_domain,sizeof inventory_domain,body,size,4*1024*1024,hash);
}
static int catalogue_verify(const struct wendy_pki_mesh_key *peer,
    const void *body,size_t size,const uint8_t *signature,size_t signature_size,
    const uint8_t *domain,size_t domain_size,size_t maximum,
    int (*digest)(const void *,size_t,uint8_t[32]))
{
    if(!peer || !peer->spki || !peer->spki_size || peer->spki_size>WENDY_PKI_MESH_SPKI_MAX ||
       !body || !size || size>maximum || !signature || wendy_pki_crypto_init())return -1;
    bool mldsa=mldsa65_key(peer);
    if(mldsa ? signature_size!=WENDY_PKI_MESH_SIGNATURE_MAX:signature_size<8 || signature_size>80)return -1;
    uint8_t hash[32];mbedtls_pk_context key;mbedtls_pk_init(&key);
    uint8_t *message=NULL;int result=-1;
    if(mbedtls_pk_parse_public_key(&key,peer->spki,peer->spki_size))goto done;
    if(mldsa){
        /* Pure ML-DSA signs domain+exact body, including the domain's NUL.
         * The serialized crypto worker owns this temporary preimage; never
         * add a maximum-sized signature or message to the task stack. */
        if(!(message=pki_owned_malloc(domain_size+size)))goto done;
        memcpy(message,domain,domain_size);memcpy(message+domain_size,body,size);
        result=mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_MLDSA65,&key,MBEDTLS_MD_NONE,
            message,domain_size+size,signature,signature_size) ? -1:0;
    }else result=digest(body,size,hash) ||
        mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_ECDSA,&key,MBEDTLS_MD_SHA256,
            hash,sizeof hash,signature,signature_size) ? -1:0;
done:
    pki_owned_free(message);mbedtls_pk_free(&key);return result;
}
int wendy_pki_service_verify_key(const struct wendy_pki_mesh_key *peer,
    const void *body,size_t size,const uint8_t *signature,size_t signature_size)
{return catalogue_verify(peer,body,size,signature,signature_size,service_domain,sizeof service_domain,8192,wendy_pki_service_digest);}
int wendy_pki_inventory_verify_key(const struct wendy_pki_mesh_key *peer,
    const void *body,size_t size,const uint8_t *signature,size_t signature_size)
{return catalogue_verify(peer,body,size,signature,signature_size,inventory_domain,sizeof inventory_domain,4*1024*1024,wendy_pki_inventory_digest);}

/* Keep the complete-peer API for certificate-verification callers and the
 * separate legacy adapter. Native directories retain actual-sized key bytes. */
static struct wendy_pki_mesh_key key_view(const struct wendy_pki_mesh_peer *peer)
{
    struct wendy_pki_mesh_key view={0};
    if(peer){
        memcpy(view.device,peer->device,sizeof view.device);
        view.expires=peer->expires;view.spki=peer->spki;view.spki_size=peer->spki_size;
    }
    return view;
}
int wendy_pki_mesh_verify(const struct wendy_pki_mesh_peer *peer,const char *principal,
    const void *body,size_t size,const uint8_t *signature,size_t signature_size)
{
    struct wendy_pki_mesh_key view=key_view(peer);
    return mesh_verify_key(&view,principal,body,size,signature,signature_size,leaf_domain,sizeof leaf_domain);
}
int wendy_pki_service_verify(const struct wendy_pki_mesh_peer *peer,
    const void *body,size_t size,const uint8_t *signature,size_t signature_size)
{
    struct wendy_pki_mesh_key view=key_view(peer);
    return wendy_pki_service_verify_key(&view,body,size,signature,signature_size);
}
int wendy_pki_inventory_verify(const struct wendy_pki_mesh_peer *peer,
    const void *body,size_t size,const uint8_t *signature,size_t signature_size)
{
    struct wendy_pki_mesh_key view=key_view(peer);
    return wendy_pki_inventory_verify_key(&view,body,size,signature,signature_size);
}

/* Own artifacts use the same scheme-dependent preimages as remote verification.
 * Only the opt-in private-key backend enables pure-message ML-DSA signing. */
size_t pki_artifact_signature_capacity(const mbedtls_pk_context *key)
{
    if(!key)return 0;
    mbedtls_pk_type_t type=mbedtls_pk_get_type(key);
#if defined(MBEDTLS_MLDSA65_PRIVATE_KEY)
    if(type==MBEDTLS_PK_MLDSA65)return WENDY_PKI_MESH_SIGNATURE_MAX;
#endif
    return type==MBEDTLS_PK_ECKEY || type==MBEDTLS_PK_ECDSA ? 80:0;
}
int pki_artifact_sign(mbedtls_pk_context *key,unsigned kind,const char *principal,
    const void *body,size_t size,uint8_t *signature,size_t capacity,size_t *written)
{
    size_t required=pki_artifact_signature_capacity(key);
    if(kind>2 || !required || !signature || capacity<required || !written ||
       !size || preimage_valid(principal,body,1) ||
       size>(kind==0 ? 32768:kind==1 ? 8192:4*1024*1024))return -1;
#if defined(MBEDTLS_MLDSA65_PRIVATE_KEY)
    if(mbedtls_pk_get_type(key)==MBEDTLS_PK_MLDSA65){
        const uint8_t *prefix=kind==1 ? service_domain:kind==2 ? inventory_domain:domain;
        size_t prefix_size=kind==1 ? sizeof service_domain:kind==2 ? sizeof inventory_domain:sizeof domain;
        size_t identity_size=kind ? 0:sizeof principal_size+105;
        uint8_t *message=pki_owned_malloc(prefix_size+identity_size+size);
        if(!message)return 1;
        memcpy(message,prefix,prefix_size);
        if(!kind){
            memcpy(message+prefix_size,principal_size,sizeof principal_size);
            memcpy(message+prefix_size+sizeof principal_size,principal,105);
        }
        memcpy(message+prefix_size+identity_size,body,size);
        int result=mbedtls_pk_sign_ext(MBEDTLS_PK_SIGALG_MLDSA65,key,MBEDTLS_MD_NONE,
            message,prefix_size+identity_size+size,signature,capacity,written) ? -1:0;
        pki_owned_free(message);return result;
    }
#endif
    uint8_t hash[32];
    int r=!kind ? mesh_digest(principal,body,size,hash,domain,sizeof domain):
        kind==1 ? wendy_pki_service_digest(body,size,hash):wendy_pki_inventory_digest(body,size,hash);
    return r || mbedtls_pk_sign(key,MBEDTLS_MD_SHA256,hash,sizeof hash,signature,capacity,written) ? -1:0;
}
