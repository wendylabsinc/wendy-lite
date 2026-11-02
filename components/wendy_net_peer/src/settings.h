#pragma once
#include "wendy_com_msg.pb.h"
#include "esp_err.h"

esp_err_t wn_settings_init(void);
WendyComNetConfig wn_settings_get(void);
bool wn_settings_restarting(void);
bool wn_settings_restart_due(void);
bool wn_settings_pending(void);
void wn_settings_poll(bool network_drained);
/* Driver hooks: settings owns persistence, actor owns application/teardown. */
void wn_peer_configuration_changed(void);
void wn_peer_runtime_status(WendyComNetStatus *);
