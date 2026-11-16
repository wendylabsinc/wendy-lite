#pragma once
#include "wendy_net_direct_generation.h"
#include "wendy_net_direct_recovery_wire.h"
#define WN_DIRECT_RECOVERY_BATCH 4
enum wn_direct_control_kind {
    WN_DIRECT_OFFER = 16,
    WN_DIRECT_VIEW,
    WN_DIRECT_RECORDS,
    WN_DIRECT_READY_PROOF,
    WN_DIRECT_COMMIT_PROOF,
    WN_DIRECT_COMMIT_ACK
};
/* Ordered, mutually negotiated and authenticated direct lane only. OFFER and
 * VIEW announce bounded snapshot counts, followed by contiguous RECORDS from
 * index zero. Actor must reserve slots before accepting counts; validate the
 * complete view and compute its digest locally before proof/commit.
 * Initial OFFER alone carries the random session capability. Recovery never
 * transmits it. READY and COMMIT proofs bind the complete TLS export context.
 * Empty session: OFFER -> VIEW+READY -> COMMIT -> ACK, four flights. */
struct wn_direct_control {
    uint8_t kind;
    uint32_t attachment_id;
    uint64_t generation;
    enum wn_direct_mode mode;
    bool create;
    uint8_t session_id[32], capability[32], nonce[16];
    struct wn_direct_namespace_checkpoint namespaces[2];
    uint16_t count, start;
    uint8_t record_count;
    struct wn_direct_recovery_record records[WN_DIRECT_RECOVERY_BATCH];
    uint8_t context[32], proof[32];
};
/* Fixed bounded storage, no allocation. Invalid/short encode writes nothing;
 * decode clears output on failure. Wire format matches Go ControlRecord. */
int wn_direct_control_size(const struct wn_direct_control *, size_t *);
int wn_direct_control_encode(const struct wn_direct_control *, uint8_t *, size_t, size_t *);
int wn_direct_control_decode(const uint8_t *, size_t, struct wn_direct_control *);
