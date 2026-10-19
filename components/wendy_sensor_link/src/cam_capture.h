#pragma once

/* Owns the board's camera driver for SensorLink streaming. */

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif

#if CONFIG_WENDY_SENSOR_LINK_MOSAICO
#define CAM_FRAME_WIDTH 1280
#define CAM_FRAME_HEIGHT 720
#elif CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
#define CAM_FRAME_WIDTH 640
#define CAM_FRAME_HEIGHT 480
#else
#define CAM_FRAME_WIDTH 800
#define CAM_FRAME_HEIGHT 600
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Initializes the board's camera driver and JPEG output. Returns ESP_OK if
 * the driver is already up, so every consumer module can call it. */
esp_err_t cam_capture_init(void);

/* Releases the driver after startup fails. Only call before streaming. */
void cam_capture_deinit(void);

/* S31 boards reserve buffers at startup and only capture while subscribed. */
#if CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1 || CONFIG_WENDY_SENSOR_LINK_MOSAICO
esp_err_t cam_capture_start(void);
void cam_capture_stop(void);
#endif

/* Grabs a frame. The JPEG is NOT copied: *jpeg borrows the driver's
 * frame buffer and stays valid until cam_capture_release_frame(). Every
 * successful call must be paired with exactly one release, and frames should
 * be held briefly -- the driver only owns fb_count of them. width/height are
 * the frame dimensions in pixels. Safe to call from multiple tasks. */
esp_err_t cam_capture_retrieve_jpeg_frame(const uint8_t **jpeg, size_t *jpeg_len, int *width, int *height);

/* Hands a frame from cam_capture_retrieve_jpeg_frame() back to the driver. */
void cam_capture_release_frame(const uint8_t *jpeg);

#ifdef __cplusplus
}
#endif
