/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_net_router.h"
#include "catalog_node.h"
struct wnrs;
struct wnrs_node;
typedef int (*wnrs_send)(void *, const void *, size_t, bool control);
/* owner must outlive its carrier sessions; last close releases node state. */
int wnrs_open(struct wnrs **, struct wnrs_node **owner, wendy_pki_connection *,
              const struct wendy_pki_mesh_identity *, const char *peer, uint16_t cost,
              wnrs_send, void *);
/* The outer owner must keep its TLS connection alive while
 * wncrypto_borrowed(connection) is true, including after protocol cancellation.
 * Close removes node/session state; independent verification loans self-drain. */
void wnrs_close(struct wnrs *);
int wnrs_tick(struct wnrs *);
void wnrs_refresh(struct wnrs *, const struct wendy_pki_mesh_identity *);
void wnrs_time_handler(struct wnrs *,int (*)(void *,const struct wn_doc *,unsigned));
int wnrs_control(struct wnrs *, const void *, size_t);
int wnrs_routing(struct wnrs *, const void *, size_t);
int wnrs_packet(struct wnrs *, void *, size_t, bool incoming);
bool wnrs_app_endpoint(struct wnrs *, const uint8_t device[16], uint16_t *port);
bool wnrs_agent_endpoint(struct wnrs *, const uint8_t device[16], uint16_t *port);

uint64_t wnrs_link_id(const struct wnrs *);
int wnrs_packet_route(struct wnrs *,void *,size_t,bool incoming,uint64_t *outgoing);
int wnrs_service_action(struct wnrs *,struct wnsc_registry **,unsigned,const void *,size_t,
    char *,size_t,wnsc_listener_owner,void *);
void wnrs_service_maintain(struct wnrs *,struct wnsc_registry **,wnsc_listener_owner,void *);
void wnrs_service_clear(struct wnsc_registry **);

/* Routing actor only; metadata and active upload pins remain intact. */
size_t wnrs_reclaim_payloads(struct wnrs_node *,size_t wanted);

int64_t wnrs_next_deadline(const struct wnrs *);

bool wnrs_receive_paused(const struct wnrs *);

bool wnrs_node_busy(const struct wnrs_node *);
/* Outer actor driver: collect/read effects on the existing PKI worker. */
int wnrs_poll_effects(struct wnrs_node *);

struct _WendyComNetTopologyPage;
/* Actor-only metadata projection; no crypto or I/O. Scans borrow state.
 * Only a selected operator row may own one bounded principal copy, released
 * through wnt_page_release after encoding or cancellation. */
int wnrs_topology(struct wnrs_node *,uint32_t cursor,uint64_t generation,
    struct _WendyComNetTopologyPage *);

struct wendy_pki_net_issuers;
void wnrs_issuer_snapshot(struct wnrs_node *,struct wendy_pki_net_issuers *);
