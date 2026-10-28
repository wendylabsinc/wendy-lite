#pragma once

#include "esp_err.h"
#include "wendy_com.h"
#include "wendy_core_sensor.h"

#ifdef __cplusplus
extern "C" {
#endif

/// This is the heart of Wendy Lite. It brings up all main peripherals and the
/// Wendy communication channel. Register a sensor-link delegate via
/// wendy_core_register_sensor_link_source() first if the board has sensor
/// sources to expose. Called once from app_main(). */
esp_err_t wendy_core_init(void);
/* Before core_init only. Shared IP/native listeners remain with WiFi disabled. */
esp_err_t wendy_core_set_boot_radios(bool ble, bool wifi);

#ifdef __cplusplus
}
#endif
