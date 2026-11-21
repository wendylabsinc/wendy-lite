#pragma once
#include "wendy_net_direct_ack.h"
#include "wendy_net_direct_reconcile.h"
#include "wendy_net_direct_wire.h"
/* Single session actor owns this object and the referenced buffers/socket.
 * Caller authenticates OPEN and fences attachment tokens before dispatch.
 * Reserve writer capacity before prepare; scratch belongs to the writer and
 * must survive until accepted. Ambiguous submission requires reattachment. */
struct wn_direct_lane {
    uint32_t id;
    struct wn_direct_sender *sender;
    struct wn_direct_receiver *receiver;
    struct wn_direct_ack ack;
    uint64_t cursor;
    bool fin_sent, fin_ack;
    uint8_t pending_kind;
    size_t pending_bytes;
    struct wn_direct_receipt pending_state;
};
int wn_direct_lane_init(struct wn_direct_lane *, uint32_t, struct wn_direct_sender *,
                        struct wn_direct_receiver *, int64_t);
/* prepare: 1=record, 0=idle, -1=error; others: 0=success, -1=error. */
int wn_direct_lane_prepare(struct wn_direct_lane *, uint32_t alias, int64_t now, uint8_t *scratch,
                           size_t capacity, struct wn_direct_frame *);
int wn_direct_lane_accepted(struct wn_direct_lane *);
int wn_direct_lane_receive(struct wn_direct_lane *, const struct wn_direct_frame *, int64_t now);
int wn_direct_lane_state(struct wn_direct_lane *, struct wn_direct_state_entry);
int wn_direct_lane_grant(struct wn_direct_lane *, uint64_t limit, int64_t now);
/* Call only after workers joined and all session flow plans validated. */
int wn_direct_lane_reattach(struct wn_direct_lane *, const struct wn_direct_snapshot *,
                            int64_t now);
