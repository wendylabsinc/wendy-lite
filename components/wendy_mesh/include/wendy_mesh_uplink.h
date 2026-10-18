#pragma once
#include "wendy_mesh_protocol.h"

/* IPv4 borrower for the existing wendy-mesh-internet/1 gateway protocol.
 * Lease addresses never enter Babel and this endpoint never forwards transit. */
bool wm_uplink_lease(const uint8_t response[3], uint8_t address[4]);
bool wm_uplink_ip4(const uint8_t* packet, size_t size);
size_t wm_uplink_wrap(uint8_t out[WENDY_MESH_MTU], const uint8_t source[16],
    const uint8_t gateway[16], const uint8_t lease[4], const uint8_t* packet, size_t size);
bool wm_uplink_unwrap(const uint8_t source[16], const uint8_t gateway[16],
    const uint8_t lease[4], const uint8_t* packet, size_t size);
