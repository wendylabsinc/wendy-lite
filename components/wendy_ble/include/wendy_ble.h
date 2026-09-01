#ifndef WENDY_BLE_H
#define WENDY_BLE_H

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Bring up the NimBLE stack: controller, host, and the host task.
///
/// Idempotent, and the only place in the firmware that may call
/// nimble_port_init(). wendy_ble_start() calls it; wendy_ble_export calls it
/// too, so a WASM guest asking for BLE gets the same already-running stack.
esp_err_t wendy_ble_host_init(void);

/// Start the WendyCom BLE transport: advertise, publish the GATT info
/// service, and (once implemented) serve WendyCom over mTLS on an L2CAP
/// connection-oriented channel.
///
/// The advertised identity is read from wendy_conf, the same source
/// com_get_device_identity() serves to WendyCom, so a scan and an `identity`
/// command can never disagree.
///
/// Returns ESP_ERR_INVALID_STATE when CONFIG_WENDY_BLE_REQUIRE_MTLS is set and
/// the device is not provisioned; nothing is advertised in that case.
esp_err_t wendy_ble_start(void);

#ifdef __cplusplus
}
#endif

#endif
