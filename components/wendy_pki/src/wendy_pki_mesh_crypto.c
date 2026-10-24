#include "wendy_pki_mesh.h"
#include "wendy_pki_crypto.h"
#include "wendy_peer_identity.h"
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* sizeof includes the domain's required NUL byte. */
static const uint8_t domain[] = "wendy-local-mesh/manifest/3";
/* Canonical principals have 105 UTF-8 bytes. Encode their byte length,
 * not a C string terminator, before the exact principal and JSON body. */
static const uint8_t principal_size[] = { 0, 0, 0, 105 };
/* RFC 9881 ML-DSA-65 SubjectPublicKeyInfo: the only DER header that
 * wendy_pki_mesh_chain stores, followed by the 1952-byte public key. */
static const uint8_t mldsa65_spki[] = { 0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60,
    0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12, 0x03, 0x82, 0x07, 0xa1, 0x00 };

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
int wendy_pki_mesh_digest(const char* principal, const void* body, size_t size, uint8_t hash[32])
{
    if (!hash || preimage_valid(principal, body, size))
        return -1;
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    size_t written = 0;
    int result = psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS
            && psa_hash_update(&op, domain, sizeof domain) == PSA_SUCCESS
            && psa_hash_update(&op, principal_size, sizeof principal_size) == PSA_SUCCESS
            && psa_hash_update(&op, (const uint8_t*)principal, 105) == PSA_SUCCESS
            && psa_hash_update(&op, body, size) == PSA_SUCCESS
            && psa_hash_finish(&op, hash, 32, &written) == PSA_SUCCESS && written == 32
        ? 0
        : -1;
    psa_hash_abort(&op);
    return result;
}
/* Pure ML-DSA verifies the complete preimage, not its SHA-256. This matches
 * the Linux router's crypto.Hash(0) signature and mldsa.Verify(..., nil). */
static int verify_mldsa65(mbedtls_pk_context* key, const char* principal, const void* body,
    size_t size, const uint8_t* signature, size_t signature_size)
{
    size_t prefix = sizeof domain + sizeof principal_size + 105;
    uint8_t* message = malloc(prefix + size);
    if (!message)
        return -1;
    memcpy(message, domain, sizeof domain);
    memcpy(message + sizeof domain, principal_size, sizeof principal_size);
    memcpy(message + sizeof domain + sizeof principal_size, principal, 105);
    memcpy(message + prefix, body, size);
    int result = mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_MLDSA65, key, MBEDTLS_MD_NONE, message,
                     prefix + size, signature, signature_size)
        ? -1
        : 0;
    free(message);
    return result;
}
int wendy_pki_mesh_verify(const struct wendy_pki_mesh_peer* peer, const char* principal,
    const void* body, size_t size, const uint8_t* signature, size_t signature_size)
{
    if (!peer || !peer->spki_size || peer->spki_size > sizeof peer->spki || !signature)
        return -1;
    /* The certified key alone selects the scheme. Each accepts only its own
     * encoding: an ECDSA DER signature, or exactly one ML-DSA-65 signature. */
    bool mldsa = peer->spki_size == sizeof mldsa65_spki + 1952
        && !memcmp(peer->spki, mldsa65_spki, sizeof mldsa65_spki);
    if (mldsa ? signature_size != WENDY_PKI_MESH_SIGNATURE_MAX
              : signature_size < 8 || signature_size > 80)
        return -1;
    uint8_t hash[32];
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int result = (mldsa ? preimage_valid(principal, body, size)
                        : wendy_pki_mesh_digest(principal, body, size, hash))
            || strcmp(principal + 69, peer->device)
            || mbedtls_pk_parse_public_key(&key, peer->spki, peer->spki_size)
            || (mldsa ? verify_mldsa65(&key, principal, body, size, signature, signature_size)
                      : mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_ECDSA, &key, MBEDTLS_MD_SHA256,
                            hash, sizeof hash, signature, signature_size))
        ? -1
        : 0;
    mbedtls_pk_free(&key);
    return result;
}
