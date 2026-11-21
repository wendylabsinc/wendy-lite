#pragma once
#include "wendy_net_direct_reconcile.h"
#define WN_DIRECT_RECOVERY_RECORD_BYTES 113
struct wn_direct_recovery_record {
    uint32_t id;
    uint8_t open_digest[32];
    uint16_t result, reset_code;
    bool open_complete, local_closed, remote_closed, reset;
    struct wn_direct_snapshot flow;
};
struct wn_direct_namespace_checkpoint {
    uint32_t high_water;
    uint64_t admitted, grant;
};
/* Logical-role order: namespace 0 is coordinator (even IDs), 1 participant.
 * Caller bounds record storage by negotiated slots before decoding records. */
struct wn_direct_recovery_view {
    struct wn_direct_namespace_checkpoint namespaces[2];
    const struct wn_direct_recovery_record *records;
    size_t count;
};
bool wn_direct_recovery_view_valid(const struct wn_direct_recovery_view *);
int wn_direct_recovery_encode(const struct wn_direct_recovery_record *, uint8_t *, size_t);
int wn_direct_recovery_decode(const uint8_t *, size_t, struct wn_direct_recovery_record *);
/* Computes from validated local/remote records, never a peer-supplied digest.
 * Fixed stack crypto context; no transcript-sized or per-record allocation. */
int wn_direct_recovery_digest(const struct wn_direct_recovery_view *coordinator,
                              const struct wn_direct_recovery_view *participant, uint8_t out[32]);
