#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_wifi.h"
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif

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
 * Failed handoffs also retry in the worker, retaining the latest credentials
 * until they connect, a newer request replaces them, or deinit cancels them.
 * Native Wendy Net starts its local certificate worker and mDNS registration
 * before station connection, allowing BLE operation without an AP. Cloud
 * services still wait for a physical IP address.
 */
esp_err_t wendy_wifi_init(void);
/* Boot policy only: call before any WiFi/shared-listener initialization. */
esp_err_t wendy_wifi_set_boot_radio_enabled(bool enabled);

/* Actual boot policy, independently of compiled radio support. */
bool wendy_wifi_radio_available(void);

/**
 * Connect to WiFi with given credentials. Persists to NVS on success,
 * with service startup scheduled by the IP-address event.
 *
 * Can be called multiple times (disconnects previous network first).
 * A failed handoff returns its error while background retries continue.
 * A newer request or deinitialization cancels those retries.
 */
esp_err_t wendy_wifi_try_connect(const char *ssid, const char *password);

/**
 * Check whether WiFi is currently connected.
 */
bool wendy_wifi_is_connected(void);

/* Pause/resume the configured station without changing saved credentials or
 * tearing down the radio, native mesh interface or management listeners. */
esp_err_t wendy_wifi_set_station_enabled(bool enabled);

/**
 * Deinitialize WiFi transport, stop listener tasks.
 */
void wendy_wifi_deinit(void);

/* Bounded scan, also on a blank board. Caller supplies *count slots. */
esp_err_t wendy_wifi_scan(wifi_ap_record_t *records, uint16_t *count);

#ifdef __cplusplus
}
#endif
