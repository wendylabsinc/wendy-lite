#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returned when no WiFi credentials are available (NVS or compile-time) */
#define WENDY_WIFI_ERR_NO_CREDS  ((esp_err_t)0x7001)

/* ── Public API ─────────────────────────────────────────────────────── */

/**
 * Initialize WiFi station and connect using stored or compile-time credentials.
 *
 * Credential resolution: NVS ("wendy_prov" namespace) first, then compile-time
 * CONFIG_WENDY_WIFI_SSID/PASSWORD, then returns WENDY_WIFI_ERR_NO_CREDS.
 *
 * On success, registers mDNS service and starts UDP listener.
 */
esp_err_t wendy_wifi_init(void);

/**
 * Connect to WiFi with given credentials. Persists to NVS on success,
 * then registers mDNS and starts UDP listener.
 *
 * Can be called multiple times (disconnects previous network first).
 */
esp_err_t wendy_wifi_try_connect(const char *ssid, const char *password);

/**
 * Check whether WiFi is currently connected.
 */
bool wendy_wifi_is_connected(void);

/**
 * Deinitialize WiFi transport, stop listener tasks.
 */
void wendy_wifi_deinit(void);

#ifdef __cplusplus
}
#endif
