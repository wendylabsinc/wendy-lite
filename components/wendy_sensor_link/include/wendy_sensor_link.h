#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initializes the selected board's sensors and registers the SensorLink
 * delegate. Call once before wendy_core_init() to reserve DMA memory before
 * networking starts. Available for CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3 or
 * CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1. Both boards stream the camera
 * and microphone concurrently.
 *
 * A missing camera or microphone does not prevent the other from working.
 * Returns ESP_OK when at least one sensor can stream, ESP_ERR_NOT_FOUND if
 * neither is available, or an error if the sender could not be initialized.
 * Device management may start normally after any error. */
esp_err_t wendy_sensor_link_init(void);

struct wendy_sensor_link_stats {
    uint64_t frames_submitted;
    uint64_t frames_completed;
    uint64_t bytes_submitted;
    uint64_t capture_errors;
    uint64_t capture_time_us;
    uint64_t capture_time_max_us;
    uint64_t completion_time_us;
    uint64_t completion_time_max_us;
    uint64_t queue_rejected;
};

/* Lifetime counters for channel 0 (camera) or 1 (microphone), copied under a
 * lock. Available before initialization, initially all zero. Capture time
 * includes failed attempts and timeouts. A completion returns ownership of an
 * accepted buffer; it can mean transmission, cancellation, or a later refusal,
 * and is not a successful-delivery count. Queue rejections count immediate
 * core-queue refusals and do not increment submitted/completed counters. */
esp_err_t wendy_sensor_link_get_stats(uint32_t channel_id, struct wendy_sensor_link_stats *stats);

#ifdef __cplusplus
}
#endif
