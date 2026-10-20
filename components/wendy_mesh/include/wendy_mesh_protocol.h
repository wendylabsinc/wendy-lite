#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WENDY_MESH_ALPN "wendy-local-mesh-leaf/3"
#define WENDY_MESH_PORT 43024
#define WENDY_MESH_MTU 1320
#define WENDY_MESH_DATAGRAM 1100
#define WENDY_MESH_CONTROL_MAX 65536
#define WENDY_MESH_ORIGINS_MAX 32
#define WENDY_MESH_MANIFEST_MAX 32768
#define WENDY_MESH_LEASE_SECONDS 60
#define WENDY_MESH_RENEW_SECONDS 20
#define WENDY_MESH_TIME_MAX_AGE_US INT64_C(300000000)
#define WENDY_MESH_SIGNATURE_DOMAIN "wendy-local-mesh/manifest/3"

/* JSON numbers are parsed directly as decimal integers. Never pass revisions
 * or router IDs through a double: both use the complete uint64 wire range. */
struct wm_token
{
    uint32_t start, end;
    uint16_t next;
    char type;
};
#define WM_TOKENS 160
struct wm_json
{
    const char* text;
    size_t size;
    unsigned count;
    struct wm_token tokens[WM_TOKENS];
};
int wm_json_parse(struct wm_json* doc, const void* data, size_t size);
int wm_json_member(const struct wm_json* doc, unsigned object, const char* key);
bool wm_json_fields(const struct wm_json* doc, unsigned object, const char* const* fields);
bool wm_json_equal(const struct wm_json* doc, int token, const char* text);
int wm_json_string(const struct wm_json* doc, int token, char* out, size_t capacity);
int wm_json_u64(const struct wm_json* doc, int token, uint64_t* out);

int wm_uuid_parse(const char* text, uint8_t out[16]);
void wm_uuid_format(const uint8_t uuid[16], char out[37]);
void wm_address(const uint8_t uuid[16], uint8_t out[16]);
void wm_prefix(const uint8_t uuid[16], char out[48]);
int wm_principal(const char* tenant, const char* device, char out[106]);
int wm_principal_device(const char* principal, const char* tenant, uint8_t device[16]);
uint16_t wm_get16(const uint8_t* p);
uint32_t wm_get32(const uint8_t* p);
void wm_put16(uint8_t* p, uint16_t v);
void wm_put32(uint8_t* p, uint32_t v);

struct wm_manifest
{
    uint8_t device[16];
    uint64_t revision, router_id;
    int64_t issued, expires;
    uint16_t seqno, agent_port;
    bool withdraw;
};
/* Uses the existing Go v3 field spellings, including Issued and Expires. */
int wm_manifest_write(const struct wm_manifest* manifest, char* out, size_t capacity);
int wm_manifest_parse(const struct wm_json* doc, unsigned body, struct wm_manifest* out);
int wm_hello_write(const char* device, const char* peer, char* out, size_t capacity);
int wm_hello_check(const void* data, size_t size, const char* device, const char* peer);

/* A leaf emits only its own /128, with the same router ID and sequence number
 * as its current signed proof. IHU AE 0 acknowledges the sole unicast link. */
size_t wm_babel_announce(uint8_t out[64], const uint8_t device[16], uint64_t router_id,
    uint16_t seqno, uint16_t hello_seq);
bool wm_ip_valid(const uint8_t* packet, size_t size);

/* Two fragments at most. One incomplete packet per stream; a replacement or
 * timeout discards it. Duplicate/overlapping/inconsistent fragments fail. */
struct wm_assembler
{
    uint8_t packet[WENDY_MESH_MTU];
    uint32_t id;
    uint16_t total, received;
    uint8_t parts;
    int64_t deadline_us;
};
int wm_assemble(struct wm_assembler* state, const uint8_t* fragment, size_t size, int64_t now_us);
size_t wm_fragment(uint8_t out[WENDY_MESH_DATAGRAM], const uint8_t* packet, size_t size,
    uint32_t id, size_t offset);
