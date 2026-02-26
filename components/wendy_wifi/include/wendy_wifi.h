#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returned when no WiFi credentials are available (NVS or compile-time) */
#define WENDY_WIFI_ERR_NO_CREDS  ((esp_err_t)0x7001)

/* ── Callbacks for WiFi protocol events ────────────────────────────── */

typedef struct {
    /** Called when a WASM binary has been downloaded over HTTP. */
    void (*on_upload_complete)(const uint8_t *data, uint32_t len, uint8_t slot);

    /** Called when a RUN command is received (unused for WiFi, reserved). */
    void (*on_run)(void);

    /** Called when a STOP command is received (unused for WiFi, reserved). */
    void (*on_stop)(void);

    /** Called when a RESET command is received (unused for WiFi, reserved). */
    void (*on_reset)(void);
} wendy_wifi_callbacks_t;

/* ── Public API ─────────────────────────────────────────────────────── */

/**
 * Initialize WiFi station and connect using stored or compile-time credentials.
 *
 * Credential resolution: NVS ("wendy_prov" namespace) first, then compile-time
 * CONFIG_WENDY_WIFI_SSID/PASSWORD, then returns WENDY_WIFI_ERR_NO_CREDS.
 *
 * On success, registers mDNS service and starts UDP listener.
 */
esp_err_t wendy_wifi_init(const wendy_wifi_callbacks_t *callbacks);

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
