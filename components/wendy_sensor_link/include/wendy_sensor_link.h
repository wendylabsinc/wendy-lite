#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initializes the XIAO ESP32S3 Sense sensors and registers the SensorLink
 * delegate. Call once before wendy_core_init() to reserve DMA memory before
 * networking starts. Available when CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
 * is enabled.
 *
 * A missing camera or microphone does not prevent the other from working.
 * Returns ESP_OK when at least one sensor can stream, ESP_ERR_NOT_FOUND if
 * neither is available, or an error if the sender could not be initialized.
 * Device management may start normally after any error. */
esp_err_t wendy_sensor_link_init(void);

#ifdef __cplusplus
}
#endif
