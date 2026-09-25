#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "wendy_com.h"

/// Registers a sensor source with the Wendy core.
/// Must be called before wendy_core_init().
void wendy_core_register_sensor_link_source(const struct wcom_sensor_link_delegate *delegate);

/// This is the heart of Wendy Lite. It brings up all main peripherals and the
/// Wendy communication channel. Register a sensor-link delegate via
/// wendy_core_register_sensor_link_source() first if the board has sensor
/// sources to expose. Called once from app_main(). */
esp_err_t wendy_core_init(void);

/// Sensor-link streaming. Unlike their wcom_sensor_* counterparts these are
/// callable from any task: each hands its work to the com task and returns
/// straight away, so nothing here reports what the device made of it.
/// None of them is reentrant.

/// Opens a stream towards client_id on channel_id.
void wendy_core_sensor_stream_begin(int client_id, uint32_t channel_id);

/// Used to send sensor-link related data to the client.
/// The provider buffer must stay valid until the done callback is invoked.
/// done runs on the com task and always runs exactly once, whether the frame
/// reached the host, was refused, or was cut short because the link died or
/// the client went away mid-frame. Wait for it before sending the next frame.
void wendy_core_send_jpeg_frame(int client_id, uint32_t channel_id, const void *data, size_t size, uint64_t ts_us, void (* done)(uint32_t channel_id));

/// Closes the stream. A frame already queued still completes.
void wendy_core_sensor_stream_end(int client_id, uint32_t channel_id);

#ifdef __cplusplus
}
#endif
