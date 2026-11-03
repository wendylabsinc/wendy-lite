/* Optional local console diagnostics. Never encoded on the mesh or WendyCom. */
#pragma once
#include "wendy_net_profile.h"
#if CONFIG_WENDY_NET_CARRIER_OBSERVATION && !WENDY_NET_NON_TRANSIT
#define WN_CARRIER_OBSERVATION_ENABLED 1
#include <stdbool.h>
#include <stdint.h>
#define WN_CARRIER_OBSERVATION_ROWS 8
struct wn_carrier_observation {
    uint64_t attachment, link, selected_link, origin;
    int64_t sampled_us, candidate_expires_us, proof_expires_us;
    uint16_t sequence, metric, advertised;
    uint8_t medium;
    bool current_identity, candidate, authorized, feasible, twoway, retiring, usable;
};
struct wn_carrier_observations {
    unsigned count;
    struct wn_carrier_observation rows[WN_CARRIER_OBSERVATION_ROWS];
};
#else
#define WN_CARRIER_OBSERVATION_ENABLED 0
#endif
