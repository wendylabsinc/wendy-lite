#pragma once
#include "wendy_pki.h"
#include "wendy_pki_alloc.h"
#include "wendy_net_memory.h"
#include "wendy_pki_tls_input.h"
#include "wendy_pki_issuers.h"
#include "wendy_pki_public_index.h"
#include "wendy_conf.h"
#include "wendy_pki_mesh.h"
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <stdlib.h>
#include <string.h>
#define PKI_MAX_RESPONSE 65536
struct pki_tls_owned_identity;
struct pki_presented_chain;
struct pki_public_chain
{
    unsigned count;
    uint8_t hashes[8][32];
    /* Reuse sizes in the existing owned source; setup fills them only after
     * binding parsed DER to the public hashes. */
    uint32_t *sizes;
    int (*metadata)(void *,struct wendy_pki_mesh_public_index *);
    int (*read)(void *,unsigned,uint8_t **,size_t *);
    void (*destroy)(void *);
    void *context;
    /* Optional owned enrollment-root DER snapshot: malloc size+1 bytes, with
     * a trailing NUL outside the returned size. TLS pins its SHA256 before
     * parsing and verifies the same bytes before every on-demand use. */
    int (*load_trust)(void *,uint8_t **,size_t *);
    uint8_t trust_hash[32];
};
static inline void pki_public_chain_free(struct pki_public_chain *chain)
{
    if(!chain)return;
    if(chain->destroy)chain->destroy(chain->context);
    pki_owned_free(chain);
}
extern const uint8_t wendy_pki_device_roots_start[] asm("_binary_wendy_pki_device_roots_start");
extern const uint8_t wendy_pki_device_roots_end[] asm("_binary_wendy_pki_device_roots_end");
extern const uint8_t wendy_pki_tsa_roots_start[] asm("_binary_wendy_pki_tsa_roots_start");
extern const uint8_t wendy_pki_tsa_roots_end[] asm("_binary_wendy_pki_tsa_roots_end");
extern const uint8_t wendy_pki_https_roots_start[] asm("_binary_wendy_pki_https_roots_start");
extern const uint8_t wendy_pki_https_roots_end[] asm("_binary_wendy_pki_https_roots_end");
#define ROOT_SIZE(kind) (wendy_pki_##kind##_roots_end - wendy_pki_##kind##_roots_start)
struct wendy_pki_connection
{
    mbedtls_ssl_config config;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt roots, certificate;
    mbedtls_pk_context key;
    int fd;
    wendy_net_memory_scope_t allocation_scope;
    wendy_net_memory_reservation_t raw_roots_reservation;
    bool mesh_roots_prefixed;
    struct wendy_pki_stream stream;
    enum wendy_peer_role peer_role;
    uint8_t device_hash[32], operator_hash[32], operator_spki_hash[32];
    time_t device_expires, operator_expires;
    int64_t relay_expires_us;
    /* Full local/remote certificate path lifetime, independent of wall-clock
     * corrections, carrier leases and caller I/O deadlines. */
    int64_t session_deadline_us;
    /* Nonzero only for the separate, explicitly pinned mesh leaf transport. */
    int64_t mesh_deadline_us;
    char mesh_tenant[37];
    char mesh_device[37];
    char mesh_peer[37];
    uint8_t *mesh_roots;
    size_t mesh_roots_size;
    bool compact_records;
#if ESP_PLATFORM && CONFIG_WENDY_NET_TEST_DIAGNOSTICS
    bool record_read_reported,record_idle_reported;
#endif
    /* Temporary native-DER setup guard. Cleanup owns it until ssl_setup. */
    unsigned char *setup_input_reservation;
    size_t setup_input_capacity;
    struct pki_presented_chain *presented_chain;
    struct pki_issuer_state *issuers; /* Optional verified native mesh negotiation. */
    struct pki_public_chain *public_chain;
    struct wendy_pki_mesh_peer *authenticated_peer;
    /* Optional index+1 of the EXACT independently trusted single anchor in
     * public_chain. Never accept a root merely because the chain names it. */
    uint8_t public_anchor;
    bool lazy_trust;
};
static inline int pki_limit_session(wendy_pki_connection *c,time_t now,int64_t monotonic)
{
    time_t expires=c->device_expires;
    if (!expires || (c->operator_expires && c->operator_expires<expires)) expires=c->operator_expires;
    if (!expires || expires<=now || monotonic<0) return -1;
    int64_t remaining=expires-now;
    if (remaining>(INT64_MAX-monotonic)/INT64_C(1000000)) return -1;
    int64_t deadline=monotonic+remaining*INT64_C(1000000);
    if (!c->session_deadline_us || deadline<c->session_deadline_us) c->session_deadline_us=deadline;
    return 0;
}
/* Caller separately checks the exact signed clock and current enrollment
 * generation under identity_lock. Never resurrect an expired attachment or
 * accept a worker snapshot that changes its original full-path expiry. */
static inline int pki_net_apply_time(wendy_pki_connection *c,
    const struct wendy_pki_mesh_identity *identity,int64_t now)
{
    if (!c || !identity || !c->mesh_deadline_us || now>=c->mesh_deadline_us ||
        strcmp(c->mesh_tenant,identity->tenant) || strcmp(c->mesh_device,identity->device) ||
        identity->certificate_expires!=c->device_expires ||
        identity->verified_seconds<=0 || identity->verified_monotonic_us<0 ||
        now<identity->verified_monotonic_us ||
        now-identity->verified_monotonic_us>=INT64_C(300000000)) return -1;
    int64_t lifetime=identity->certificate_expires-identity->verified_seconds;
    if (lifetime<=30) return -1;
    if (lifetime>300) lifetime=300;
    if (identity->verified_monotonic_us>INT64_MAX-lifetime*INT64_C(1000000)) return -1;
    int64_t deadline=identity->verified_monotonic_us+lifetime*INT64_C(1000000);
    if (now>=deadline) return -1;
    c->mesh_deadline_us=deadline;
    return 0;
}
int pki_tls_connect(const char *host, unsigned port, const uint8_t *key, size_t key_size,
                    struct wendy_conf_span cert, struct wendy_conf_span roots, wendy_pki_connection **out);
int pki_tls_mesh_connect(const char *host, unsigned port, const char *tenant,
    const char *device, const char *router, const uint8_t *key, size_t key_size,
    struct wendy_conf_span cert, struct wendy_conf_span roots, wendy_pki_connection **out);
int pki_http_post(const char *url, const char *type, const char *token, const void *body,
                  size_t body_size, const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                  struct wendy_conf_span roots, uint8_t **response, size_t *response_size);
/* End-to-end HTTPS over a caller-owned ciphertext stream. No client key or
 * enrollment token is sent. The caller releases its stream after return. */
int pki_http_post_stream(const char *,const char *,const void *,size_t,
    struct wendy_conf_span,const struct wendy_pki_stream *,uint8_t **,size_t *);
/* Only enrollment/renewal may consume this authenticated response header.
 * The caller owns both the response body and optional allocated header. */
int pki_http_post_enrollment(const char *url, const char *type, const char *token, const void *body,
                  size_t body_size, const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                  struct wendy_conf_span roots, uint8_t **response, size_t *response_size,
                  char **lite_authority_header);

int pki_tls_accept(int fd, const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                   struct wendy_conf_span roots, const char *tenant, wendy_pki_connection **out, int64_t deadline);
int pki_tls_accept_stream(const struct wendy_pki_stream *stream,
                          const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                          struct wendy_conf_span roots, const char *tenant,
                          wendy_pki_connection **out, int64_t deadline);
int pki_tls_accept_lan(int fd, const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                      struct wendy_conf_span roots, const char *tenant,
                      wendy_pki_connection **out, int64_t deadline);
int pki_tls_accept_lite(int fd, const uint8_t *key, size_t key_size, struct wendy_conf_span cert,
                       struct wendy_conf_span roots, const char *tenant,
                       wendy_pki_connection **out, int64_t deadline);
/* LAN management consumes NVS copies, verifies the parsed local identity and
 * releases issuer/anchor storage after full mutual authentication. */
int pki_tls_accept_owned(int *fd, struct pki_tls_owned_identity *owned,
    struct wendy_conf_span roots, const char *tenant, const char *device,
    wendy_pki_connection **out, int64_t deadline);
/* Same complete-path, streamed-DER setup over a caller-owned radio stream.
 * Management BLE remains operator-only; it gains no router/device authority. */
int pki_tls_accept_owned_stream(const struct wendy_pki_stream *,
    struct pki_tls_owned_identity *,struct wendy_conf_span roots,
    const char *tenant,const char *device,wendy_pki_connection **out,int64_t deadline);

int pki_relay_grant(wendy_pki_connection *, const struct wendy_lite_trust *, int64_t deadline);

/* A NULL peer is allowed only for client streams. The verified same-tenant
 * UUID is returned in connection->mesh_peer; self identities are rejected. */
int pki_tls_mesh_stream(const struct wendy_pki_stream*, bool server, const char* tenant,
    const char* device, const char* peer, const uint8_t* key, size_t key_size,
    struct wendy_conf_span cert, struct wendy_conf_span roots, wendy_pki_connection** out);

int pki_tls_gateway_connect(const char* host, unsigned port, const char* tenant, const char* device,
    const char* router, const uint8_t* key, size_t key_size, struct wendy_conf_span cert,
    struct wendy_conf_span roots, wendy_pki_connection** out);
int pki_tls_bound_connect(const char* host, unsigned port, const char* interface, const char* resolver,
    const uint8_t* key, size_t key_size, struct wendy_conf_span cert,
    struct wendy_conf_span roots, wendy_pki_connection** out);

/* Native connection consumes these temporary NVS copies on every return.
 * Parsed TLS identity objects remain owned by the connection. */
struct pki_tls_owned_identity {
    uint8_t *key;
    size_t key_size;
    char *certificate;
    size_t certificate_size;
    /* Exact inputs verified under identity_lock; selected full-path expiry.
     * Zero requests independent verification after TLS (host/adaptor callers). */
    time_t verified_until;
    /* Optional exact roots.data allocation with a trailing NUL, transferred
     * to the connection. Capacity includes that terminator. */
    uint8_t *trust;
    size_t trust_capacity;
    /* Nonzero requests full verification of the consumed parsed identity. */
    time_t verify_at;
    /* Allocate final-sized receive storage before small certificate objects
     * fragment the heap. Zero selects the native device-chain reservation. */
    size_t input_reserve;
    bool reserve_records_first;
    /* Physical preparation already owns the global heavy workspace. The
     * synchronous native acceptor atomically transfers this cookie to TLS. */
    void *preparation_owner;
    /* Optional calloc-owned input_reserve-byte hole pinned before copying
     * identity/trust inputs. The TLS constructor consumes it on every path. */
    uint8_t *input_reservation;
    /* Optional lazy DER chain input. The callback transfers one PKI-owned
     * exact DER buffer per index (pki_owned_free, or Mbed TLS own_buffer transfer);1=certificate,0=end,-1=failure. Its context
     * survives the complete synchronous TLS constructor; any presentation
     * callbacks are detached before it returns. Local path/key/principal
     * authorization at verify_at remains mandatory; only byte-identical,
     * previously verified paths may reuse their verified validity window.
     * This avoids a contiguous whole PEM copy. */
    int (*read_der)(void *,unsigned,uint8_t **,size_t *);
    /* Optional exact source digest/length using bounded reads. Same result
     * convention as read_der; bytes must be hashed, not trusted metadata. */
    int (*hash_der)(void *,unsigned,uint8_t[32],size_t *);
    /* Optional bounded public presentation reader, bound to the exact
     * independently verified part hash. Same synchronous lifetime as above. */
    int (*read_der_range)(void *,unsigned,size_t,uint8_t *,size_t,const uint8_t[32]);
    void *der_context;
    /* Optional owned, hash-pinned public chain source. Setup compares every
     * hash with the exact verified own source before transfer. Enables releasing
     * serialized certificates while serving descriptors/parts on demand. */
    struct pki_public_chain *public_chain;
};
int pki_tls_net_connect(const char* host, unsigned port, const char* tenant, const char* device,
    const char* peer, struct pki_tls_owned_identity* owned,
    struct wendy_conf_span roots, const char* protocol, wendy_pki_connection** out);

/* Consumes both fd and identity inputs on all returns. Peer UUID comes only
 * from the authenticated same-tenant device certificate. */
int pki_tls_net_accept(int *fd, const char *tenant, const char *device,
    struct pki_tls_owned_identity *owned, struct wendy_conf_span roots,
    const char *protocol, wendy_pki_connection **out);
/* Full-router TLS over caller-owned BLE/L2CAP bytes. A missing expected UUID
 * permits discovery by short hint; full chain, tenant, device role and ALPN
 * remain mandatory and the authenticated full UUID is available afterward. */
int pki_tls_net_stream(const struct wendy_pki_stream *,bool server,const char *tenant,
    const char *device,const char *expected_peer,struct pki_tls_owned_identity *,
    struct wendy_conf_span roots,wendy_pki_connection **);

/* CPU/storage preparation and one nonblocking handshake step. The caller's
 * buffered BIO and owned DER source remain alive until handshake completion. */
int pki_tls_net_begin(const struct wendy_pki_stream *,bool,const char *,const char *,
    struct pki_tls_owned_identity *,struct wendy_conf_span,bool,wendy_pki_connection **);
int pki_tls_net_advance(wendy_pki_connection *,bool,const char *);
/* Native WendyCom server TLS: ordinary ALPN/no-ALPN, same-tenant operator or
 * device roles. CPU worker only; BIO callbacks never wait on network I/O. */
int pki_tls_agent_begin(const struct wendy_pki_stream *,const char *,const char *,
    struct pki_tls_owned_identity *,struct wendy_conf_span,wendy_pki_connection **);
int pki_tls_agent_advance(wendy_pki_connection *);
#if CONFIG_WENDY_NET_TEST_ACTOR_READINESS
bool pki_tls_agent_snapshot(const wendy_pki_connection *,struct wendy_pki_agent_snapshot *);
#endif
