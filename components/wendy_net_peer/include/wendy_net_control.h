/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_net_gossip.h"
#include "wendy_net_peer_protocol.h"

int wn_router_hello_write(const char *self, const char *peer, char *, size_t);
int wn_router_hello_check(const void *, size_t, const char *self,
                          const char *peer);
/* Exact WendyOS ControlMessage/netgossip.Message JSON envelope. DATA borrows
 * the caller's 1024-byte buffer; no parser or payload allocations.
 * Read returns 1 for an unsupported future operation/type/version, 0 for a
 * decoded supported message, and -1 for a malformed supported format. */
int wn_gossip_write(const struct wg_message *, char *, size_t);
int wn_gossip_read(const void *, size_t, struct wg_message *,
                   uint8_t data[WG_CHUNK]);
/* Sans-I/O borrowed DATA view; input must outlive the synchronous receive. */
int wn_gossip_read_view(const void *,size_t,struct wg_message *);
/* Platform SHA256 implementation for wg_config.identify. Streaming avoids a
 * second full announcement allocation while a download is being verified. */
int wn_gossip_identify(void *, uint8_t type, const void *, size_t,
                       uint8_t hash[32]);
