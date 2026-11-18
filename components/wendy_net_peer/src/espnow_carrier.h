#pragma once

#include "esp_err.h"
#include "wendy_net_peer_protocol.h"

#define WN_ESPNOW_PORT 43025
#define WN_ESPNOW_COST 1024

bool wn_espnow_supported(void);
esp_err_t wn_espnow_start(unsigned channel);
void wn_espnow_stop(void);
bool wn_espnow_channel_live(unsigned channel);
int wn_espnow_listener(void);
int wn_espnow_accept(struct wn_candidate *);
int wn_espnow_connect(const struct wn_candidate *, bool *connecting);
void wn_espnow_poll(const char *tenant, const char *device, bool accepting,
                   struct wn_selection *, int64_t now);
