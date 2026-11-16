/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_net_gossip.h"
#include "wendy_net_peer_protocol.h"

#define WN_OPERATOR_HELLO_MAX 128
int wn_operator_hello_read(const void *, size_t, uint8_t instance[16]);
int wn_operator_ready_write(void *, size_t);
int wn_operator_hello_read_direct(const void *, size_t, uint8_t instance[16], uint32_t local,
                                  uint32_t *selected);
int wn_operator_ready_write_direct(void *, size_t, uint32_t selected);

#include "wendy_net_direct_wire.h"
bool wn_direct_capability_valid(uint32_t);
uint32_t wn_direct_capability_negotiate(uint32_t local, uint32_t remote);
/* Advertise only after the session owner can handle attachment and promotion.
 * Caller must independently enforce physical BLE eligibility. */
int wn_router_hello_write_direct(const char *self, const char *peer, char *, size_t,
                                 uint32_t local);
int wn_router_hello_check_direct(const void *, size_t, const char *self, const char *peer,
                                 uint32_t local, uint32_t *selected);
int wn_router_hello_write(const char *self, const char *peer, char *, size_t);
int wn_router_hello_check(const void *, size_t, const char *self, const char *peer);
/* Exact WendyOS ControlMessage/netgossip.Message JSON envelope. DATA borrows
 * the caller's 1024-byte buffer; no parser or payload allocations.
 * Read returns 1 for an unsupported future operation/type/version, 0 for a
 * decoded supported message, and -1 for a malformed supported format. */
int wn_gossip_write(const struct wg_message *, char *, size_t);
int wn_gossip_read(const void *, size_t, struct wg_message *, uint8_t data[WG_CHUNK]);
/* Sans-I/O borrowed DATA view; input must outlive the synchronous receive. */
int wn_gossip_read_view(const void *, size_t, struct wg_message *);
/* Platform SHA256 implementation for wg_config.identify. Streaming avoids a
 * second full announcement allocation while a download is being verified. */
int wn_gossip_identify(void *, uint8_t type, const void *, size_t, uint8_t hash[32]);

/* Busy new peers advertise a deferred lane; old peers keep ordinary routing. */
uint32_t wn_direct_carrier_negotiate(uint32_t local, uint32_t local_deferred, uint32_t remote,
                                     uint32_t remote_deferred, bool *deferred);

int wn_operator_hello_read_deferred(const void *, size_t, uint8_t instance[16], uint32_t local,
                                    uint32_t deferred, uint32_t *selected, bool *parked);
int wn_operator_ready_write_deferred(void *, size_t, uint32_t selected, bool parked);
int wn_router_hello_write_deferred(const char *self, const char *peer, char *, size_t,
                                   uint32_t local, uint32_t deferred);
int wn_router_hello_check_deferred(const void *, size_t, const char *self, const char *peer,
                                   uint32_t local, uint32_t deferred, uint32_t *selected,
                                   bool *parked);
