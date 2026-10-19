#pragma once
#include "wendy_mesh_protocol.h"
#include "wendy_pki_mesh.h"

struct wm_origin
{
    struct wendy_pki_mesh_peer peer;
    uint8_t device[16], body_hash[32];
    uint64_t revision, router_id;
    uint16_t seqno;
    int64_t expires_us;
    int64_t expires_unix_ms;
};
struct wm_directory
{
    struct wm_origin origins[WENDY_MESH_ORIGINS_MAX];
    unsigned count;
};
/* Retry bookkeeping is separate from trusted identities and replay receipts. */
struct wm_identity_requests
{
    struct
    {
        uint8_t device[16];
        int64_t retry_after_us;
    } slots[WENDY_MESH_ORIGINS_MAX];
};
bool wm_identity_request_due(struct wm_identity_requests* requests,
    const uint8_t device[16], int64_t now_us);
/* Remote receipts stay in RAM. On each boot or trust change, fail closed for
 * the maximum accepted lease plus future skew. All previously issued proofs
 * have expired before IP can be admitted, including superseded withdrawals. */
struct wm_epoch
{
    char tenant[37], device[37];
    uint8_t trust_hash[32];
    int64_t ready_after_us;
    int64_t clock_unix_ms, clock_monotonic_us;
    bool bound;
};
int wm_directory_bind(struct wm_directory* directory, struct wm_epoch* epoch,
    const struct wendy_pki_mesh_identity* identity);
bool wm_epoch_ready(const struct wm_epoch* epoch, int64_t now_us);
int64_t wm_epoch_time(const struct wm_epoch* epoch, int64_t now_us);
/* A verified renewal keeps the identity's revision high water. The bounded
 * directory never evicts entries, including expired entries, within a trust
 * epoch. Returns 1 when full without evicting any existing receipt. */
int wm_directory_add(struct wm_directory* directory, const struct wendy_pki_mesh_peer* peer);
enum { WM_DIRECTORY_IDENTITY_NEEDED = 2 };
/* Returns WM_DIRECTORY_IDENTITY_NEEDED for a missing identity, 1 for an
 * expired/older proof, 0 for accepted/idempotent, and -1 for invalid identity,
 * signature, structure or same-revision equivocation. */
int wm_directory_apply(struct wm_directory* directory, const char* tenant,
    const struct wm_json* doc, unsigned envelope, int64_t now, int64_t now_us);
bool wm_directory_address(
    const struct wm_directory* directory, const uint8_t address[16], int64_t now_us);
