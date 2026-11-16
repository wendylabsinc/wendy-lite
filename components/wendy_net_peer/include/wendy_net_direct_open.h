#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "wendy_net_direct_buffer.h"
#define WN_DIRECT_RETIRED (-3)
/* Embedded in the flow record; lifetime and retirement have one owner. */
struct wn_direct_open_entry {
    uint8_t digest[32];
    uint16_t result;
    bool complete, local_closed, remote_closed;
};
/* Per-direction cumulative OPEN credit, independent of the byte window.
 * Actual records are owned exclusively by wn_direct_flows. */
struct wn_direct_opens {
    uint32_t high_water;
    uint16_t count, free;
    uint8_t parity;
    uint64_t admitted, grant;
};
int wn_direct_opens_init(struct wn_direct_opens *, uint16_t count, bool coordinator);
int wn_direct_opens_grant(struct wn_direct_opens *, uint64_t through);
int wn_direct_opens_peer_grant(struct wn_direct_opens *, uint64_t through);
/* Only after the flow owner has excluded a duplicate and reserved a record. */
int wn_direct_opens_admit(struct wn_direct_opens *, uint32_t id);
