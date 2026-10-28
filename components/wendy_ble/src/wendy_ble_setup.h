#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WBLE_SETUP_PSM 131
#define WBLE_SETUP_MAX_CONFIG 60000
#define WBLE_SETUP_MAX_RESPONSE 4096
/* Owns L2CAP for the session. Never hands anonymous traffic to WendyCom. */
void wble_setup_session(void);
/* Run only on the WendyCom task, serial with USB challenge/config/reset.
 * Input/output buffers are disjoint. Accepted configuration requires reboot,
 * even if writing its response fails. */
bool wble_setup_dispatch(const uint8_t *, size_t, uint8_t *, size_t, size_t *, bool *reboot);
