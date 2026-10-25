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
 * After receiving an IP address, starts mDNS and device/cloud services in a
 * worker, including when DHCP finishes after this call times out. The names
 * come from wendy_conf, so wendy_conf_init() must have run first.
 *
 * A failed result does not stop the station. After five immediate retries it
 * keeps trying the last configured network every 10 seconds, including after a
 * later loss of the access point.
 */
esp_err_t wendy_wifi_init(void);

/**
 * Connect to WiFi with given credentials. Persists to NVS on success,
 * with service startup scheduled by the IP-address event.
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

/* Start a station radio without AP association, or verify the current AP is
 * on the requested channel. Never retunes a connected infrastructure link. */
esp_err_t wendy_wifi_mesh_radio_start(uint8_t channel);
