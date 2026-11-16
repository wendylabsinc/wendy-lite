#pragma once
#include "wendy_net_direct_flows.h"
/* Root actor only, after peer/service authorization. Successful construction
 * transfers a ledger-owned endpoint to caller; bind or close it exactly once.
 * Incoming association is created on first message, never recreated after close.
 * Outgoing construction completes the already-existing guest connect handle. */
uint16_t wn_direct_guest_packet_incoming(uint16_t port, uint16_t maximum,
                                         struct wn_direct_packet_io *);
uint16_t wn_direct_guest_packet_outgoing(int handle, uint16_t maximum,
                                         struct wn_direct_packet_io *);
