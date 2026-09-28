#pragma once

#include <stddef.h>
#include <stdint.h>
#include "wendy_com.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Registers a sensor source with the Wendy core.
/// Must be called before wendy_core_init().
void wendy_core_register_sensor_link_source(const struct wcom_sensor_link_delegate *delegate);

/// Sensor-link streaming. Unlike their wcom_sensor_* counterparts these are
/// callable from any task: each hands its work to the com task and returns
/// straight away, so nothing here reports what the device made of it.
/// None of them is reentrant: a call made while the previous one of the same
/// kind is still queued is dropped. The done callbacks say when the next call
/// is safe, so a stream goes begin, push (wait for done) ..., end (wait for
/// done), and only then begin again.

/// Opens a stream towards client_id on channel_id.
void wendy_core_sensor_stream_begin(int client_id, uint32_t channel_id);

/// Pushes one frame of sensor-link data to the client: a video frame, a
/// buffer of audio samples or a batch of sensor readings.
/// The provider buffer must stay valid until the done callback is invoked.
/// done runs on the com task and always runs exactly once, whether the frame
/// reached the host, was refused, or was cut short because the link died or
/// the client went away mid-frame. Wait for it before sending the next frame.
void wendy_core_sensor_stream_push(int client_id, uint32_t channel_id, const void *data, size_t size, uint64_t ts_us, void (* done)(uint32_t channel_id));

/// Closes the stream. Call it only once the last frame's done has run.
/// done runs once the stream is closed; from then on begin can be called
/// again. It always runs exactly once, normally on the com task, or straight
/// away on the calling task if a previous end is still queued.
void wendy_core_sensor_stream_end(int client_id, uint32_t channel_id, void (* done)(uint32_t channel_id));

#ifdef __cplusplus
}
#endif
