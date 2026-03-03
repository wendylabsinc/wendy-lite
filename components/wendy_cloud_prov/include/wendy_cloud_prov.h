#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status values reported via BLE notify */
typedef enum {
    WENDY_CLOUD_PROV_NOT_PROVISIONED = 0,
    WENDY_CLOUD_PROV_RECEIVING       = 1,
    WENDY_CLOUD_PROV_COMMITTED       = 2,
    WENDY_CLOUD_PROV_FAILED          = 3,
    WENDY_CLOUD_PROV_ALREADY_LOCKED  = 4,
} wendy_cloud_prov_status_t;

/**
 * Read NVS locked flag. Must be called before BLE GATT callbacks run.
 */
esp_err_t wendy_cloud_prov_init(void);

/**
 * Register the cloud provisioning GATT service with NimBLE.
 * Called from wendy_ble_prov after GAP/GATT init but before nimble_port_freertos_init.
 */
esp_err_t wendy_cloud_prov_register_gatt(void);

/**
 * Check whether the device has been cloud-provisioned.
 */
bool wendy_cloud_is_provisioned(void);

/**
 * Retrieve the cloud endpoint URL from NVS.
 */
esp_err_t wendy_cloud_get_url(char *buf, size_t buf_len);

/**
 * Retrieve the client certificate PEM from NVS.
 */
esp_err_t wendy_cloud_get_cert(char *buf, size_t buf_len, size_t *out_len);

/**
 * Retrieve the private key PEM from NVS.
 */
esp_err_t wendy_cloud_get_key(char *buf, size_t buf_len, size_t *out_len);

#ifdef __cplusplus
}
#endif
