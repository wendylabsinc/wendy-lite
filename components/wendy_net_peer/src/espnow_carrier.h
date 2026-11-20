#pragma once

#include "esp_err.h"
#include "wendy_net_peer_protocol.h"

#define WN_ESPNOW_PORT 43025
#define WN_ESPNOW_COST 1024

bool wn_espnow_supported(void);
bool wn_espnow_worker_active(void);
unsigned wn_espnow_rate_limit(unsigned configured);
void wn_espnow_set_link_rate(const void *link, const char *address, unsigned rate);
void wn_espnow_clear_link_rate(const void *link);
esp_err_t wn_espnow_start(unsigned channel);
void wn_espnow_stop(void);
bool wn_espnow_channel_live(unsigned channel);
int wn_espnow_listener(void);
int wn_espnow_accept(struct wn_candidate *);
int wn_espnow_connect(const struct wn_candidate *, bool *connecting);
void wn_espnow_poll(const char *tenant, const char *device, bool accepting,
                   struct wn_selection *, int64_t now);
