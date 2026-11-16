#pragma once
#include "wendy_net_direct_registry.h"
#include "wendy_pki_mesh.h"
/* Root-actor only. 0 transfers one registry pin to the app control owner,
 * 1 asks it to retry after a carrier crypto loan, negative rejects. No new
 * epoch/backend is created. The completed app TLS identity is locally derived. */
int wn_app_direct_control_begin(wendy_pki_connection *, const struct wendy_pki_mesh_identity *,
                                const uint8_t instance[16], bool initiator,
                                uint64_t expected_serial, struct wn_direct_peer **,
                                uint64_t *token);
void wn_app_direct_control_close(struct wn_direct_peer *, uint64_t token);
int wn_app_direct_open(struct wn_direct_peer *, uint32_t id);
/* WDP1 carries session/generation/flow, never an unauthenticated peer identity.
 * Match that existing epoch, then derive identity from this actual upper TLS. */
int wn_app_direct_flow_pin(wendy_pki_connection *, const struct wendy_pki_mesh_identity *,
                           const uint8_t hello[64], struct wn_direct_peer **);
void wn_app_direct_flow_release(struct wn_direct_peer *);
unsigned wn_app_direct_incoming_capacity(void);

/* Root actor only: start one outgoing upper control for this exact retained
 * epoch. The root-supplied predicate is rechecked throughout setup.
 * No service OPEN or guest completion is performed. */
int wn_app_direct_promote(uint64_t serial, const char peer[37], const uint8_t address[16],
                          uint16_t port,
                          bool (*eligible)(uint64_t serial, const uint8_t address[16],
                                           uint16_t port));
