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
/// service, and serve WendyCom over TLS on an L2CAP connection-oriented
/// channel. One session at a time; a second connection attempt is rejected
/// while one is open.
///
/// The advertised identity is read from wendy_conf, the same source
/// com_get_device_identity() serves to WendyCom, so a scan and an `identity`
/// command can never disagree.
///
/// Enrolled devices advertise with mTLS enabled and use their enrolled
/// identity to authenticate same-tenant operators over TLS 1.3. They never
/// fall back to anonymous TLS. Unenrolled devices serve the embedded
/// self-signed certificate without client verification when
/// CONFIG_WENDY_BLE_REQUIRE_MTLS is disabled.
///
/// Returns ESP_ERR_INVALID_STATE during identity reset, with PKI enrollment
/// in a build without PKI support, or when an unenrolled device requires
/// mTLS. Nothing is advertised on initial startup in those cases.
esp_err_t wendy_ble_start(void);

#ifdef __cplusplus
}
#endif

#endif
