#include "wendy_pki_mesh.h"
#include "wendy_pki_crypto.h"
#include "wendy_peer_identity.h"
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <string.h>

int wendy_pki_mesh_digest(const char* principal, const void* body, size_t size, uint8_t hash[32])
{
    static const uint8_t domain[] = "wendy-local-mesh/manifest/3";
    if (!principal || strlen(principal) != 105 || memcmp(principal, "spiffe://wendy.sh/tenant/", 25)
        || !wendy_identity_uuid((const unsigned char*)principal + 25, 36)
        || memcmp(principal + 61, "/device/", 8)
        || !wendy_identity_uuid((const unsigned char*)principal + 69, 36) || !body || !size
        || size > 32768 || !hash || wendy_pki_crypto_init())
        return -1;
    /* Canonical principals have 105 UTF-8 bytes. Encode their byte length,
     * not a C string terminator, before the exact principal and JSON body. */
    static const uint8_t principal_size[] = { 0, 0, 0, 105 };
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    size_t written = 0;
    int result = psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS &&
            /* sizeof includes the domain's required NUL byte. */
            psa_hash_update(&op, domain, sizeof domain) == PSA_SUCCESS
            && psa_hash_update(&op, principal_size, sizeof principal_size) == PSA_SUCCESS
            && psa_hash_update(&op, (const uint8_t*)principal, 105) == PSA_SUCCESS
            && psa_hash_update(&op, body, size) == PSA_SUCCESS
            && psa_hash_finish(&op, hash, 32, &written) == PSA_SUCCESS && written == 32
        ? 0
        : -1;
    psa_hash_abort(&op);
    return result;
}
int wendy_pki_mesh_verify(const struct wendy_pki_mesh_peer* peer, const char* principal,
    const void* body, size_t size, const uint8_t* signature, size_t signature_size)
{
    if (!peer || !peer->spki_size || peer->spki_size > sizeof peer->spki || !signature
        || signature_size < 8 || signature_size > 80)
        return -1;
    uint8_t hash[32];
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int result = wendy_pki_mesh_digest(principal, body, size, hash)
            || strcmp(principal + 69, peer->device)
            || mbedtls_pk_parse_public_key(&key, peer->spki, peer->spki_size)
            || mbedtls_pk_verify(
                &key, MBEDTLS_MD_SHA256, hash, sizeof hash, signature, signature_size)
        ? -1
        : 0;
    mbedtls_pk_free(&key);
    return result;
}
