#pragma once
#include <stdbool.h>
#include "wendy_net_ble_protocol.h"
#include <stddef.h>
#include <stdint.h>
#include "wendy_net_binary.h"
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif

#define WN_MTU 1320
#define WN_DATAGRAM_MAX 1100
#define WN_CONTROL_MAX 2048
/* Signed artifacts are chunked by gossip; their envelope is independent of
 * the per-control-frame scratch buffer. P-256 or certified ML-DSA-65. */
#define WN_ORIGIN_SIGNATURE_MAX 3309
#define WN_MANIFEST_BODY_MAX 32768
#define WN_MANIFEST_WIRE_MAX (WN_MANIFEST_BODY_MAX + WN_ORIGIN_SIGNATURE_MAX + 136)
#define WN_TOKENS 128
#ifndef WN_CANDIDATES
#ifdef CONFIG_WENDY_NET_MAX_CANDIDATES
#define WN_CANDIDATES CONFIG_WENDY_NET_MAX_CANDIDATES
#else
#define WN_CANDIDATES 8
#endif
#endif

/* Portable codec: no TLS, clock, allocation, routing or SDK runtime. */
struct wn_token { uint32_t start, end; uint16_t next; char type; uint8_t header; };
struct wn_doc {
    const char *text; size_t size; unsigned count;
    struct wn_token *storage; unsigned capacity;
    struct wn_token tokens[WN_TOKENS];
};
uint16_t wn_get16(const uint8_t *p);
uint32_t wn_get32(const uint8_t *p);
void wn_put16(uint8_t *p, uint16_t v);
void wn_put32(uint8_t *p, uint32_t v);
int wn_uuid_parse(const char *text, uint8_t out[16]);
void wn_uuid_format(const uint8_t uuid[16], char out[37]);
void wn_address(const uint8_t device[16], uint8_t out[16]);
/* Native catalogue and WendyOS mDNS device names, optionally absolute/cased.
 * Returns1 for a device name,0 for ordinary DNS,-1 for a malformed device id.
 * Name resolution supplies an address hint; it does not authorize a route. */
int wn_device_hostname_parse(const char *host,uint8_t device[16]);
void wn_prefix(const uint8_t device[16], char out[48]);
int wn_principal(const char *tenant, const char *device, char out[106]);
int wn_principal_device(const char *principal, const char *tenant, uint8_t device[16]);
int wn_doc_parse(struct wn_doc *doc, const void *data, size_t size);
/* Router artifacts retain the same bounded token/depth parser with an
 * explicit byte bound. Ordinary control frames use the smaller frame limit. */
int wn_doc_parse_bounded(struct wn_doc *doc,const void *data,size_t size,size_t maximum);
/* Operation-owned token storage for larger service envelopes. The ordinary
 * wrappers still populate doc->tokens within WN_TOKENS.
 * Storage must outlive all queries on doc; no heap is reserved by the parser. */
int wn_doc_parse_into(struct wn_doc *,const void *,size_t,size_t maximum,
    struct wn_token *storage,unsigned capacity);
/* Validate every array element while retaining only the array span for this
 * named field. Iterate it afterward with a fixed-size child document. Large
 * origin inventories therefore do not require one token per receipt. */
int wn_doc_parse_array_view(struct wn_doc *,const void *,size_t,size_t maximum,const char *field);
int wn_doc_array_next(const struct wn_doc *,int array,size_t *cursor,struct wn_doc *element);
const struct wn_token *wn_doc_token(const struct wn_doc *,int token);

int wn_doc_member(const struct wn_doc *doc, unsigned object, const char *key);
bool wn_doc_fields(const struct wn_doc *doc, unsigned object, const char *const *fields);
bool wn_doc_equal(const struct wn_doc *doc, int token, const char *text);
int wn_doc_string(const struct wn_doc *doc, int token, char *out, size_t capacity);
int wn_doc_u64(const struct wn_doc *doc, int token, uint64_t *out);

/* Signed origin tuple shared by native Babel router helpers.
 * The origin serializer does not choose a path-dependent next hop or metric. */
struct wn_origin { uint64_t router_id; uint16_t seqno; };
int wn_manifest_write(const uint8_t self[16], const struct wn_origin *origin,
    uint64_t revision, int64_t issued_ms, int64_t expires_ms, uint16_t service_port,
    char *out, size_t capacity);
int wn_manifest_app_write(const uint8_t self[16],const struct wn_origin *origin,
    uint64_t revision,int64_t issued,int64_t expires,uint16_t port,uint16_t app_port,
    char *out,size_t cap);
/* Native management metadata rides the signed route proof, without a second
 * service record/signature. Unknown capability names remain extensible. */
int wn_manifest_capabilities_write(const uint8_t self[16],const struct wn_origin *origin,
    uint64_t revision,int64_t issued,int64_t expires,uint16_t port,uint16_t app_port,
    const char *display_name,bool sensors,char *out,size_t cap);
bool wn_ip_admits(const uint8_t self[16], const void *packet, size_t size, bool incoming);

enum wn_medium { WN_LAN = 1, WN_BLE = 2, WN_NAN = 3 };
struct wn_candidate {
    char address[64], device[37];
    enum wn_medium medium;
    uint16_t port, cost;
    int64_t seen_ms, retry_ms, failed_ms;
    unsigned failures; /* Bounded diagnostic/presence flag, never a retry exponent. */
    bool passive; /* Dial planning only; never identity or route authority. */
    uint8_t ble_capabilities; /* Live endpoint hint only; no authority. */
    uint16_t holds; /* Physical setup/live owners; their slot cannot be reused. */
};
struct wn_selection { struct wn_candidate candidates[WN_CANDIDATES]; int active; };
void wn_selection_init(struct wn_selection *selection);
int wn_candidate_seen(struct wn_selection *selection, const struct wn_candidate *hint, int64_t now_ms);
/* Healthy candidates are shuffled, followed by failures from the last30s,
 * oldest failure first. Passive/expired/retry-floor/active entries are omitted.
 * Seed comes from the driver; this pure function owns no random or heap state.
 * Cost, medium capacity and already-in-progress links remain driver policy. */
unsigned wn_candidate_order(const struct wn_selection *selection,int64_t now_ms,
    uint32_t random,unsigned out[WN_CANDIDATES]);
/* Portable single-link convenience: cost replacement over deterministic order.
 * Firmware uses order() with a fresh random seed even for one carrier. */
int wn_candidate_next(const struct wn_selection *selection, int64_t now_ms);
/* Time discovery is independent of native carrier availability/cooldown. */
int wn_candidate_time(const struct wn_selection *,int64_t now_ms,unsigned cursor);
void wn_candidate_failed(struct wn_selection *selection, unsigned slot, int64_t now_ms);
/* The actor reserves a slot from setup until that physical owner closes.
 * Multiple owners may hold the same endpoint. Release exactly once per hold. */
int wn_candidate_hold(struct wn_selection *selection,unsigned slot);
void wn_candidate_release(struct wn_selection *selection,unsigned slot);
/* Only a verified TLS connection can commit an attachment. Discovery cannot
 * replace a live route or supply the authenticated device identity. */
/* Cache only an identity already verified by TLS, even if carrier admission
 * later declines a redundant path. Does not activate a route or clear retries. */
int wn_candidate_authenticated(struct wn_selection *,unsigned,const char *verified_device);
int wn_candidate_commit(struct wn_selection *selection, unsigned slot, const char *verified_device);
/* After mTLS and the bidirectional hello, converge crossed connections to the
 * lower UUID's dial, as WendyOS does. Same-direction duplicates keep the incumbent. */
bool wn_link_replaces(const char *self, const char *verified_peer,
                      bool incumbent_incoming, bool replacement_incoming);

struct wn_assembler { uint8_t packet[WN_MTU]; uint32_t id; uint16_t total,received; uint8_t parts; int64_t deadline_us; };
int wn_assemble(struct wn_assembler *,const uint8_t *fragment,size_t size,int64_t now_us);
size_t wn_fragment(uint8_t out[WN_DATAGRAM_MAX],const uint8_t *packet,size_t size,uint32_t id,size_t offset);

/* CBOR byte strings are borrowed views. Text strings have no JSON escaping. */
int wn_doc_bytes(const struct wn_doc *,int,const uint8_t **,size_t *);
int wn_doc_copy_bytes(const struct wn_doc *,int,void *,size_t,size_t *);
int wn_doc_text(const struct wn_doc *,int,const char **,size_t *);


int wn_manifest_wire_write(const char *,const void *,size_t,const uint8_t *,size_t,char *,size_t);
int wn_identity_request_write(const char *,char *,size_t);
int wn_manifest_request_write(const char *,char *,size_t);
int wn_directory_missing_write(const char *,bool,char *,size_t);
int wn_doc_hash_string(const struct wn_doc *,int,char[65]);

int wn_manifest_services_write(const uint8_t self[16],const struct wn_origin *,
    uint64_t,int64_t,int64_t,uint16_t,uint16_t,const char *,bool,
    const void *,size_t,char *,size_t);
