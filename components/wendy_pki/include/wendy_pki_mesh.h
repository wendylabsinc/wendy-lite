#pragma once
#include "wendy_pki.h"
#include <time.h>

#if CONFIG_WENDY_MESH_LEAF
#define WENDY_PKI_MESH_ALPN "wendy-local-mesh-leaf/3"
#endif
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
/* Borrowed verified public-key view. The caller owns immutable SPKI bytes for
 * the duration of verification; retaining a view does not retain trust itself. */
struct wendy_pki_mesh_key
{
    char device[37];
    time_t expires;
    const uint8_t *spki;
    size_t spki_size;
};
struct wendy_pki_mesh_identity
{
    char tenant[37], device[37], peer[37];
    time_t certificate_expires, verified_seconds;
    int64_t verified_monotonic_us;
    uint64_t revision_first, revision_limit;
    uint64_t config_generation;
    uint8_t trust_hash[32];
    uint8_t journal_trust_hash[32];
};
/* Public availability metadata, never a trust assertion. Keep one copy per
 * runtime store rather than growing every copied identity/crypto snapshot. */
struct wendy_pki_mesh_public_index
{
    unsigned count;
    uint32_t certificate_epoch;
    uint64_t config_generation;
    uint8_t hashes[8][32];
    uint32_t sizes[8];
};
/* RAM-only metadata snapshot. Caller must exclusively own the completed TLS
 * context (no outstanding worker loan). Sizes were bound to parsed own DER
 * by TLS setup on its worker; this function does no NVS, parsing or hashing. */
int wendy_pki_mesh_public_index_snapshot(wendy_pki_connection *,
    const struct wendy_pki_mesh_identity *,struct wendy_pki_mesh_public_index *);
/* RAM-only current-enrollment and own-certificate-epoch check. */
bool wendy_pki_mesh_public_index_current(const struct wendy_pki_mesh_public_index *,
    const struct wendy_pki_mesh_identity *);
/* RAM-only publication counter after carrier bootstrap has reserved this
 * boot's durable range. No NVS or identity-worker lock on the actor path.
 * TIMEOUT means the short counter lock is busy; INVALID_STATE means not yet
 * bootstrapped, reset/configuration unavailable, or the boot range exhausted.
 * Reconnect, mesh off/on and certificate renewal never reserve another range. */
esp_err_t wendy_pki_mesh_revision_next(uint64_t *out);
/* Fresh nonce-bound signed time and an already enrolled UUID identity are
 * required. Never issues a new identity or changes enrollment configuration.
 * A durable revision block is reserved before any proof may be signed. */
esp_err_t wendy_pki_mesh_connect(const char* host, unsigned port, const char* router,
    wendy_pki_connection** connection, struct wendy_pki_mesh_identity* identity);
/* Signs only while the authenticated session and fresh-time window are valid.
 * The key remains inside PKI. The v4 signature binds the full principal and body. */
/* Scheme-sized artifact output. kind0 route,1 service,2 inventory. The query
 * reads immutable own key metadata only; caller must hold the context loan.
 * Sign returns0 complete,1 temporary allocation pressure,-1 failure. */
size_t wendy_pki_artifact_signature_capacity(wendy_pki_connection *);
int wendy_pki_artifact_sign(wendy_pki_connection *,unsigned kind,const char *principal,
    const void *,size_t,uint8_t *signature,size_t capacity,size_t *written);
/* Existing leaf builds retain their v3 manifest domain under that flag.
 * Native artifact_sign and verify_key always use v4. P256/80B ABI below. */
int wendy_pki_mesh_sign(wendy_pki_connection* connection, const char* principal, const void* body,
    size_t size, uint8_t signature[80], size_t* signature_size);
/* Public leaf-first own certificates. The existing leaf build requires an
 * output buffer for its JSON/base64 DER array (including a trailing NUL).
 * Other builds expose native CBOR bytes; NULL queries their encoded size. */
int wendy_pki_mesh_bundle(wendy_pki_connection* connection, char* out, size_t capacity);
/* Bounded public certificate descriptor and1024-byte part access, avoiding a
 * contiguous base64 copy of the whole own chain on constrained full routers. */
int wendy_pki_mesh_describe(wendy_pki_connection *,char *,size_t);
int wendy_pki_mesh_part(wendy_pki_connection *,const uint8_t hash[32],size_t offset,
    uint8_t out[1024],size_t *total);
/* Read only already cached local public DER for this current enrollment.
 * Returns bytes (1 for out=NULL size query), -1 absent/stale, -2 lock busy.
 * Does not create, repair or invalidate persistent cache material. */
int wendy_pki_mesh_local_part(const struct wendy_pki_mesh_identity *,
    const uint8_t hash[32],size_t offset,uint8_t out[1024],size_t *total);
/* Worker-only read of exact-hash public DER, independent of the private
 * identity mutex (which may span TLS/network waits). Requires a previously
 * verified public index's epoch. Checks config/epoch/reset before and after
 * the existing full-DER hash validation, opens NVS read-only, never writes or
 * reads private keys. NULL output is unsupported; availability uses RAM index. */
int wendy_pki_mesh_local_part_snapshot(const struct wendy_pki_mesh_identity *,
    uint32_t certificate_epoch,const uint8_t hash[32],size_t offset,
    uint8_t out[1024],size_t *total);
/* Each remote chain is independently anchored to the enrolled tenant's roots.
 * Its P-256 or ML-DSA-65 public key is copied into a bounded cache; no
 * private material. */
int wendy_pki_mesh_verify_bundle(wendy_pki_connection* connection, const uint8_t* const* der,
    const size_t* sizes, size_t count, time_t now, struct wendy_pki_mesh_peer* peer);
/* Public chain verification on the existing TLS worker, independent of a
 * carrier's lifetime. Pins the exact current enrollment generation/trust and
 * derives time from an already verified native-peer clock snapshot. */
int wendy_pki_mesh_verify_snapshot(const struct wendy_pki_mesh_identity *,
    const uint8_t *const *der,const size_t *sizes,size_t count,
    struct wendy_pki_mesh_peer *);
/* Portable synchronous verifier. DER inputs remain caller-owned and must be
 * immutable until return. The returned peer contains only copied metadata. */
int wendy_pki_mesh_chain(const uint8_t* const* der, const size_t* sizes, size_t count,
    const uint8_t* roots, size_t roots_size, const char* tenant, time_t now,
    struct wendy_pki_mesh_peer* peer);
/* The v3 preimage is domain || uint32_be(105) || principal || body. P-256
 * peers sign its SHA-256 (ECDSA); ML-DSA-65 peers sign it unhashed, as pure
 * ML-DSA with an empty context. The peer's certified key selects the scheme. */
int wendy_pki_mesh_verify(const struct wendy_pki_mesh_peer* peer, const char* principal,
    const void* body, size_t size, const uint8_t* signature, size_t signature_size);
int wendy_pki_mesh_verify_key(const struct wendy_pki_mesh_key *, const char *,
    const void *,size_t,const uint8_t *,size_t);
int wendy_pki_service_verify_key(const struct wendy_pki_mesh_key *,const void *,size_t,
    const uint8_t *,size_t);
int wendy_pki_inventory_verify_key(const struct wendy_pki_mesh_key *,const void *,size_t,
    const uint8_t *,size_t);
int wendy_pki_mesh_digest(const char* principal, const void* body, size_t size, uint8_t hash[32]);

/* Signed service records use the WendyOS service-specific domain. The
 * catalogue must separately bind the record owner/fingerprint and lease to
 * this already verified device key before accepting a record. */
int wendy_pki_service_digest(const void *,size_t,uint8_t hash[32]);
int wendy_pki_service_verify(const struct wendy_pki_mesh_peer *,const void *,size_t,
    const uint8_t *,size_t);
/* Legacy P256/80B synchronous adapters; production uses artifact_sign. */
int wendy_pki_service_sign(wendy_pki_connection *,const char *principal,const void *,size_t,
    uint8_t signature[80],size_t *);
int wendy_pki_mesh_fingerprint(wendy_pki_connection *,uint8_t hash[32]);
int wendy_pki_inventory_digest(const void *,size_t,uint8_t hash[32]);
int wendy_pki_inventory_verify(const struct wendy_pki_mesh_peer *,const void *,size_t,
    const uint8_t *,size_t);
int wendy_pki_inventory_sign(wendy_pki_connection *,const char *principal,const void *,size_t,
    uint8_t signature[80],size_t *);

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

/* Prototype native endpoint carrier. Standard TLS, no leaf protocol preface.
 * Uses the same enrolled device key, strict tenant pin and signed time. */
esp_err_t wendy_pki_net_connect(const char* host, unsigned port, const char* peer,
    wendy_pki_connection** connection, struct wendy_pki_mesh_identity* identity);

/* Consumes an accepted TCP socket, validates a same-tenant device and returns
 * its authenticated UUID. The remote address/discovery hint grants no access. */
esp_err_t wendy_pki_net_accept(int fd,wendy_pki_connection **connection,
    struct wendy_pki_mesh_identity *identity,char peer[37]);
/* Full Babel router role over the same standard TLS carrier, with the exact
 * WendyOS StreamALPN. Unlike compact endpoints, retains certificate material
 * required to authenticate and relay independently signed origin proofs. */
esp_err_t wendy_pki_net_router_connect(const char *host,unsigned port,const char *peer,
    wendy_pki_connection **connection,struct wendy_pki_mesh_identity *identity);
esp_err_t wendy_pki_net_router_accept(int fd,wendy_pki_connection **connection,
    struct wendy_pki_mesh_identity *identity,char peer[37]);
/* Standard full-router TLS over caller-owned byte stream, with no leaf/time
 * preface. expected_peer may be NULL for short-hint discovery. Returned peer
 * is always the fully authenticated same-tenant device UUID. Uses fresh
 * generation-bound signed time; expired cached time requires TSA access. */
esp_err_t wendy_pki_net_router_stream(const struct wendy_pki_stream *,bool server,
    const char *expected_peer,wendy_pki_connection **,
    struct wendy_pki_mesh_identity *,char peer[37]);
/* Copy the exact already authenticated full-path-bounded TLS neighbor key.
 * No discovery hint or relayed origin inherits this identity. */
int wendy_pki_mesh_authenticated_peer(wendy_pki_connection *,struct wendy_pki_mesh_peer *);
/* Refresh nonce-bound signed time without replacing the authenticated carrier.
 * Identity/trust changes and original certificate expiry still revoke it. */
esp_err_t wendy_pki_net_refresh(wendy_pki_connection *connection,
    struct wendy_pki_mesh_identity *identity);
/* Two-stage renewal for continuously running packet actors. The worker owns
 * only an identity snapshot, never a TLS connection. This layer uses direct
 * HTTPS; relay_host is a reserved staging argument. Apply from the owning actor;
 * a busy identity lock returns ESP_ERR_TIMEOUT for a later bounded retry.
 * Neither failure nor a stale/retired result changes the original deadline. */
esp_err_t wendy_pki_net_refresh_time(struct wendy_pki_mesh_identity *identity,
                                    const char *relay_host);
/* Apply a fresh nonce-bound public TSA reply after its transport is closed.
 * Trust, configuration generation and persistent clock floor remain local. */
esp_err_t wendy_pki_net_time_reply(struct wendy_pki_mesh_identity *,const uint8_t nonce[32],
    const uint8_t *reply,size_t size,int64_t request_started_us);
/* Nonblocking clock readiness: 1 fresh, 0 missing/aged, -1 identity worker busy.
 * BLE cold-start HTTPS uses a caller-owned byte relay to the enrolled TSA;
 * fresh signed proof verification and the persistent clock floor stay local. */
int wendy_pki_net_time_status(void);
/* NULL uses direct HTTPS when a physical network is available. */
esp_err_t wendy_pki_net_bootstrap_time(const struct wendy_pki_stream *);
/* Forward ciphertext only to the currently enrolled HTTPS TSA on port443.
 * Caller retains the stream. No generic destination or Internet gateway. */
esp_err_t wendy_pki_net_time_tunnel(const struct wendy_pki_stream *);
/* Internal loopback backend for the authenticated app TLS time service.
 * Consumes fd; relays only to the currently enrolled timestamp authority. */
void wendy_pki_net_time_relay(int fd);
esp_err_t wendy_pki_time_query(const uint8_t *,size_t,uint8_t **reply,size_t *size);
esp_err_t wendy_pki_net_apply_time(wendy_pki_connection *connection,
                                  const struct wendy_pki_mesh_identity *identity);
/* App TLS is a separate same-tenant device session. It has no routing/signing
 * authority and does not reserve a persistent route revision per app flow. */
esp_err_t wendy_pki_app_accept(int fd,wendy_pki_connection **connection,
    struct wendy_pki_mesh_identity *identity,char peer[37]);
esp_err_t wendy_pki_app_connect(const char *host,unsigned port,const char *peer,
    wendy_pki_connection **connection,struct wendy_pki_mesh_identity *identity);

/* Signed-time bootstrap bytes from a peer; the enrolled TSA remains the
 * authority. Supports numeric IPv4 and scoped IPv6 underlay addresses. */
#if CONFIG_WENDY_NET_NAN
esp_err_t wendy_pki_net_sync_time(const char *peer_address,unsigned port);
#endif

/* Async native carrier/VIP construction. Run begin/step only on the admitted
 * crypto worker. BIO read/write MUST be nonblocking memory-buffer operations.
 * Main may pump their outer I/O only after step completion, never while lent.
 * Step: 1 ready for another CPU step, -2 needs input, -3 needs output, 0 fully
 * authenticated, -1 failure. Cancellation waits for worker acknowledgement.
 * Existing signed-time bootstrap is a separate prerequisite, never network
 * I/O hidden inside begin. Take transfers an authenticated connection only. */
struct wendy_pki_net_setup;
esp_err_t wendy_pki_net_begin(const struct wendy_pki_stream *,bool server,
    const char *expected_peer,bool application,struct wendy_pki_net_setup **);
int wendy_pki_net_step(struct wendy_pki_net_setup *);
wendy_pki_connection *wendy_pki_net_take(struct wendy_pki_net_setup *,struct wendy_pki_mesh_identity *);
void wendy_pki_net_dispose(struct wendy_pki_net_setup *);

/* Native WendyCom VIP server: same operator/device policy as LAN acceptance,
 * without app/carrier ALPN or a fabricated peer device UUID. Worker-only
 * begin/step; buffered BIO lifetime and exclusive loans match net_setup.
 * Preparation releases the private identity lock before any network wait. */
struct wendy_pki_agent_setup;
struct wendy_pki_agent_info {
    enum wendy_peer_role role;
    uint64_t config_generation;
    int64_t session_deadline_us;
};
esp_err_t wendy_pki_agent_begin(const struct wendy_pki_stream *,struct wendy_pki_agent_setup **);
int wendy_pki_agent_step(struct wendy_pki_agent_setup *);
wendy_pki_connection *wendy_pki_agent_take(struct wendy_pki_agent_setup *,struct wendy_pki_agent_info *);
void wendy_pki_agent_dispose(struct wendy_pki_agent_setup *);

/* Same authenticated own P256 signing policy, with an already computed
 * domain-specific SHA256 digest. Allows a bounded worker job without copying
 * an entire immutable origin inventory alongside its retained snapshot. */
int wendy_pki_mesh_sign_digest(wendy_pki_connection *,const char *,const uint8_t[32],uint8_t[80],size_t *);
