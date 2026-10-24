#pragma once
#include "wendy_pki.h"
#include <time.h>

#define WENDY_PKI_MESH_ALPN "wendy-local-mesh-leaf/3"
/* A remote origin's key is P-256 (91-byte SPKI) or, for Linux routers, pure
 * ML-DSA-65: a 1974-byte SPKI and 3309-byte signatures. Keep peers off task
 * stacks. This leaf's own mesh key remains P-256. */
#define WENDY_PKI_MESH_SPKI_MAX 1974
#define WENDY_PKI_MESH_SIGNATURE_MAX 3309
struct wendy_pki_mesh_peer
{
    char device[37];
    time_t expires;
    uint8_t spki[WENDY_PKI_MESH_SPKI_MAX];
    size_t spki_size;
};
struct wendy_pki_mesh_identity
{
    char tenant[37], device[37], peer[37];
    time_t certificate_expires, verified_seconds;
    int64_t verified_monotonic_us;
    uint64_t revision_first, revision_limit;
    uint8_t trust_hash[32];
};
/* Fresh nonce-bound signed time and an already enrolled UUID identity are
 * required. Never issues a new identity or changes enrollment configuration.
 * A durable revision block is reserved before any proof may be signed. */
esp_err_t wendy_pki_mesh_connect(const char* host, unsigned port, const char* router,
    wendy_pki_connection** connection, struct wendy_pki_mesh_identity* identity);
/* Signs only while the authenticated session and fresh-time window are valid.
 * The key remains inside PKI. The v3 signature binds the full principal and body. */
int wendy_pki_mesh_sign(wendy_pki_connection* connection, const char* principal, const void* body,
    size_t size, uint8_t signature[80], size_t* signature_size);
/* Public leaf-first certificate bundle, rendered as JSON base64 DER array. */
int wendy_pki_mesh_bundle(wendy_pki_connection* connection, char* out, size_t capacity);
/* Each remote chain is independently anchored to the enrolled tenant's roots.
 * Its P-256 or ML-DSA-65 public key is copied into a bounded cache; no
 * private material. */
int wendy_pki_mesh_verify_bundle(wendy_pki_connection* connection, const uint8_t* const* der,
    const size_t* sizes, size_t count, time_t now, struct wendy_pki_mesh_peer* peer);
/* Portable verifier used by the firmware and host conformance tests. */
int wendy_pki_mesh_chain(const uint8_t* const* der, const size_t* sizes, size_t count,
    const uint8_t* roots, size_t roots_size, const char* tenant, time_t now,
    struct wendy_pki_mesh_peer* peer);
/* The v3 preimage is domain || uint32_be(105) || principal || body. P-256
 * peers sign its SHA-256 (ECDSA); ML-DSA-65 peers sign it unhashed, as pure
 * ML-DSA with an empty context. The peer's certified key selects the scheme. */
int wendy_pki_mesh_verify(const struct wendy_pki_mesh_peer* peer, const char* principal,
    const void* body, size_t size, const uint8_t* signature, size_t signature_size);
int wendy_pki_mesh_digest(const char* principal, const void* body, size_t size, uint8_t hash[32]);

/* Caller owns the carrier until after wendy_pki_close. The initiator obtains
 * nonce-bound signed time through the peer before TLS; a responder relays only
 * to its enrolled timestamp authority and needs Internet access. */
esp_err_t wendy_pki_mesh_stream(const struct wendy_pki_stream* stream, bool server,
    const char* peer, wendy_pki_connection** connection, struct wendy_pki_mesh_identity* identity);
/* BLE fallback: authenticate any other device in the enrolled tenant. The
 * authenticated UUID is returned in identity->peer. TLS client streams only;
 * TCP, ESP-NOW and gateway APIs retain their explicit peer requirements. */
esp_err_t wendy_pki_mesh_stream_same_tenant(const struct wendy_pki_stream* stream,
    wendy_pki_connection** connection, struct wendy_pki_mesh_identity* identity);
/* 1: wake/readiness hint, 0: timeout, -1: closed/error. */
int wendy_pki_wait(wendy_pki_connection* connection, bool writing, int64_t deadline_us);

/* Authenticated Internet lease control, pinned to the exact gateway UUID.
 * Uses recent signed time from mesh establishment, never unauthenticated time. */
esp_err_t wendy_pki_gateway_connect(const char* host, const char* gateway,
    wendy_pki_connection** connection, int64_t* deadline_us);
bool wendy_pki_probe_direct(const char* interface, const char* resolver);
