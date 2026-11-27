#pragma once
#include <stdbool.h>
#include <stddef.h>
struct wendy_pki_mesh_peer;
struct wendy_pki_connection;
/* Carrier device-role TLS only. VIP and operator protocols retain independent
 * domains; a cached PSK is never a logical app-stream recovery capability. */
void pki_resumption_prepare(struct wendy_pki_connection *, const char *protocol);
/* Shared with the server certificate callback to predict the exact ALPN for tickets. */
size_t pki_tls_server_issuer_alias(struct wendy_pki_connection *, bool *leaf);
void pki_resumption_before_step(struct wendy_pki_connection *);
int pki_resumption_finish(struct wendy_pki_connection *, const char *expected_peer,
                           const char *protocol);
void pki_resumption_close(struct wendy_pki_connection *);
void pki_resumption_clear(void);

void pki_resumption_client_start(struct wendy_pki_connection *, const char *expected_peer);
void pki_resumption_received_ticket(struct wendy_pki_connection *);

/* Share the connection-lifetime carrier snapshot with its resumption owner.
 * Caller must have authenticated this peer; this does not admit a ticket. */
bool pki_resumption_share_authenticated_peer(struct wendy_pki_connection *,
                                             const struct wendy_pki_mesh_peer *);
