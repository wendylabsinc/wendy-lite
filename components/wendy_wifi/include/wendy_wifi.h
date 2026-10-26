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
 * Credential resolution: NVS ("wendy_prov" namespace) first, then wendy-conf,
 * then compile-time CONFIG_WENDY_WIFI_SSID/PASSWORD.
 *
 * After receiving an IP address, starts mDNS and device/cloud services in a
 * worker, including when DHCP finishes after this call times out. The names
 * come from wendy_conf, so wendy_conf_init() must have run first.
 * A failed connection result does not stop background reconnection: after
 * five immediate retries, the station tries again every ten seconds until
 * an IP address arrives or wendy_wifi_deinit() stops the transport.
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
