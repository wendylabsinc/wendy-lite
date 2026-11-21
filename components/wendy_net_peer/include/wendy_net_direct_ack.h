#pragma once
#include <stdbool.h>
#include <stdint.h>
/* Batch common 512-byte BLE records; window reopening and FIN stay immediate. */
#define WN_DIRECT_ACK_BYTES 1024
#define WN_DIRECT_CREDIT_BYTES 1024
#define WN_DIRECT_ACK_DELAY_US INT64_C(250000)
struct wn_direct_receipt {
    uint64_t received, limit;
    bool fin_seen;
};
/* Actor-owned; callers fence callbacks from previous attachments. No queued
 * payload pointers. All times are nonnegative monotonic microseconds. */
struct wn_direct_ack {
    struct wn_direct_receipt current, sent;
    int64_t since;
    bool pending, initial;
};
int wn_direct_ack_init(struct wn_direct_ack *, struct wn_direct_receipt, int64_t now);
int wn_direct_ack_update(struct wn_direct_ack *, struct wn_direct_receipt, int64_t now);
/* Polling/failed enqueue does not consume an ACK. Always returns latest state. */
bool wn_direct_ack_due(const struct wn_direct_ack *, int64_t now, struct wn_direct_receipt *);
/* Call only when the writer owns this exact snapshot; updates observed after
 * the snapshot remain pending, without postponing the original deadline. */
int wn_direct_ack_written(struct wn_direct_ack *, struct wn_direct_receipt);
