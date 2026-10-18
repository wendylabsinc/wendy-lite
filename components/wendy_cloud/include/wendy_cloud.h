#pragma once

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WENDY_CLOUD_STATE_IDLE         = 0,
    WENDY_CLOUD_STATE_CONNECTING   = 1,
    WENDY_CLOUD_STATE_CONNECTED    = 2,
    WENDY_CLOUD_STATE_DISCONNECTED = 3,
    WENDY_CLOUD_STATE_ERROR        = 4,
} wendy_cloud_state_t;

/**
 * Start the cloud connection task.
 * Call after nvs_flash_init() and network stack initialization.
 * Wi-Fi or mesh may supply connectivity.
 * Returns ESP_ERR_INVALID_STATE if the device has no enrollment configuration.
 */
esp_err_t wendy_cloud_start(void);

/**
 * Stop the cloud connection task and tear down the TLS session.
 */
void wendy_cloud_stop(void);

/**
 * Return the current connection state.
 */
wendy_cloud_state_t wendy_cloud_get_state(void);

/**
 * Convenience: true when state == WENDY_CLOUD_STATE_CONNECTED.
 */
bool wendy_cloud_is_connected(void);

unsigned wendy_cloud_connect_failures(void);
void wendy_cloud_reset_failures(void);

/* Wake the connector after a route change. Call outside the lwIP core thread. */
void wendy_cloud_network_changed(void);

#ifdef __cplusplus
}
#endif
