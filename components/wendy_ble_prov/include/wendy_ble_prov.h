#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Status values for the BLE status characteristic ───────────────── */

typedef enum {
    WENDY_BLE_PROV_STATUS_NO_CREDS   = 0,
    WENDY_BLE_PROV_STATUS_CONNECTING = 1,
    WENDY_BLE_PROV_STATUS_CONNECTED  = 2,
    WENDY_BLE_PROV_STATUS_FAILED     = 3,
} wendy_ble_prov_status_t;

/* ── Callbacks from BLE to main ────────────────────────────────────── */

typedef struct {
    /**
     * Called (from BLE task context) when a client has written SSID +
     * password + command=0x01.  The main thread should call
     * wendy_wifi_try_connect() — NOT the BLE task.
     */
    void (*on_wifi_creds)(const char *ssid, const char *password);

    /**
     * Called when command=0x02 is written (clear saved credentials).
     */
    void (*on_clear_creds)(void);
} wendy_ble_prov_callbacks_t;

/* ── Public API ─────────────────────────────────────────────────────── */

/**
 * Initialize BLE provisioning: starts NimBLE, registers GATT services,
 * and begins advertising as "Wendy-XXXX".
 */
esp_err_t wendy_ble_prov_init(const wendy_ble_prov_callbacks_t *callbacks);

/**
 * Update the status characteristic and optionally the IP address.
 * Sends a notification to any subscribed client.
 *
 * @param status  One of wendy_ble_prov_status_t values.
 * @param ip_addr IP address string (only used when status == CONNECTED), or NULL.
 */
void wendy_ble_prov_set_status(wendy_ble_prov_status_t status, const char *ip_addr);

/**
 * Returns true if wendy_ble_prov already initialized the NimBLE stack.
 * Used by wendy_ble to avoid double-init of nimble_port_init().
 */
bool wendy_ble_prov_nimble_ready(void);

#ifdef __cplusplus
}
#endif
