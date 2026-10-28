#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "wendy_pki.h"
/* Native endpoint integration baseline; never enables synthetic Babel routes. */
esp_err_t wendy_net_peer_start(void);
/* Read persisted single-radio policy before core initializes either radio. */
esp_err_t wendy_net_peer_boot_radios(bool *ble,bool *wifi);
/* Run at most one pending time-maintenance job on the existing server/TLS
 * worker. Never call from the packet actor. Retains no connection pointer. */
void wendy_net_peer_maintain(void);
esp_err_t wendy_net_app_start(void);
bool wendy_net_app_ready(void);
int wendy_net_app_listener(void);
/* Leave new management connections in their TCP backlog while active app
 * flows occupy the configured handshake headroom. Existing sessions continue. */
bool wendy_net_app_management_ready(void);
void wendy_net_app_accept(int fd);
/* Resolve through the routing actor; call from another task. Bounded5second
 * wait, one outstanding query, no caller-owned pointer retained on timeout.
 * Only an authenticated signed TLS endpoint with a live route is returned. */
esp_err_t wendy_net_peer_app_endpoint(const char *peer, uint8_t address[16], uint16_t *port);
esp_err_t wendy_net_peer_agent_endpoint(const char *peer, uint8_t address[16], uint16_t *port);
int wendy_net_app_time_listener(void);
int wendy_net_peer_service_catalog(unsigned operation,const void *,size_t,char *,size_t);

/* Experimental optional-payload pressure relief before TLS. Runs eviction
 * on the routing actor with a bounded wait; never retains a caller pointer. */
void wendy_net_peer_prepare_handshake(void);

#include <sys/select.h>
/* Only the mesh actor calls these nonblocking drivers. */
int wendy_net_app_poll(void);
bool wendy_net_app_stop(void);
void wendy_net_app_watch(fd_set *,fd_set *,int *,int64_t *deadline);
esp_err_t wendy_net_peer_app_endpoint_now(const char *,uint8_t[16],uint16_t *);
esp_err_t wendy_net_peer_agent_endpoint_now(const char *,uint8_t[16],uint16_t *);
