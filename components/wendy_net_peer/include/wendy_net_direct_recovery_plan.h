#pragma once
#include "wendy_net_direct_recovery_wire.h"
enum wn_direct_recovery_action {
    WN_DIRECT_RESUME,
    WN_DIRECT_RESET_FLOW,
    WN_DIRECT_REPLAY_OPEN,
    WN_DIRECT_RECEIVE_OPEN,
    WN_DIRECT_RETIRE,
    WN_DIRECT_CONFIRM_RETIRED
};
struct wn_direct_recovery_step {
    uint32_t id;
    enum wn_direct_recovery_action action;
    bool open_complete, reset;
    uint16_t result, reset_code;
    struct wn_direct_reconciliation flow;
};
/* Pure full-union validation. Role 0=coordinator/even, 1=participant/odd.
 * Caller owns stable immutable views. No output entries change on failure.
 * A replay/receive OPEN with reset=true must be admitted as cancelled WITHOUT
 * dialing a destination socket. Apply only after authenticated session commit. */
int wn_direct_recovery_plan(const struct wn_direct_recovery_view *local,
                            const struct wn_direct_recovery_view *remote, uint8_t role,
                            struct wn_direct_recovery_step *out, size_t capacity, size_t *count);

/* Validate the immutable transcript without retaining a mutation plan. */
int wn_direct_recovery_validate(const struct wn_direct_recovery_view *,
                                const struct wn_direct_recovery_view *, uint8_t role);
