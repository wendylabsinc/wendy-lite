#pragma once

#include <stddef.h>
#include <stdint.h>
#include "wendy_com.h"
#include "wendy_com_sensor.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Registers a sensor source with the Wendy core.
/// Must be called before wendy_core_init().
void wendy_core_register_sensor_link_source(const struct wcom_sensor_link_delegate *delegate);

/// Sensor-link streaming. Unlike their wcom_sensor_* counterparts these are
/// callable from any task: each hands its work to the com task and returns
/// straight away, so nothing here reports what the device made of it.
/// Independent bounded pools hold up to WCOM_SENSOR_MAX_STREAMS queued calls
/// of each kind, so different channels may submit concurrently. Calls on a
/// single stream must remain ordered. Open it before pushing and wait for each
/// frame's done before reusing that buffer or submitting its next frame.

/// Opens a stream towards client_id on channel_id.
void wendy_core_sensor_stream_begin(int client_id, uint32_t channel_id);

/// Pushes one frame of sensor-link data to the client: a video frame, a
/// buffer of audio samples or a batch of sensor readings.
/// The provider buffer must stay valid until the done callback is invoked.
/// done always runs exactly once, whether the frame
/// reached the host, was refused, or was cut short because the link died or
/// the client went away mid-frame. It normally runs on the com task, or on
/// the calling task if the operation queue is full or the arguments invalid.
/// Wait for it before sending the next frame.
void wendy_core_sensor_stream_push(int client_id, uint32_t channel_id, const void *data, size_t size, uint64_t ts_us, void (* done)(uint32_t channel_id));

/// Like push(), but returns BUSY when the operation pool is full and BAD_STATE
/// for an empty buffer. On refusal, done is not called and the buffer remains
/// the caller's. OK means the operation was queued, not that the frame reached
/// the transport; done then runs exactly once even if the com task rejects it.
WendyComResult wendy_core_sensor_stream_try_push(int client_id, uint32_t channel_id,
                                                const void *data, size_t size, uint64_t ts_us,
                                                void (*done)(uint32_t channel_id));

/// Closes the stream. Call it only once the last frame's done has run.
/// done runs once the stream is closed; from then on begin can be called
/// again. It always runs exactly once, normally on the com task, or straight
/// away on the calling task if the end-operation pool is full. In that case
/// the close was not queued; callers needing confirmed cancellation should
/// serialize wcom_sensor_stream_end() through their own com operation.
void wendy_core_sensor_stream_end(int client_id, uint32_t channel_id, void (* done)(uint32_t channel_id));

#ifdef __cplusplus
}
#endif
