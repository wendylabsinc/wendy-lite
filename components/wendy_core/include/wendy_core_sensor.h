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
/// straight away.
///
/// begin() gives the stream (one client_id/channel_id pair) a slot of its own,
/// one of WCOM_SENSOR_MAX_STREAMS. The stream keeps that slot until end() has
/// run and its last frame is done, so its calls never compete with other
/// streams for queue space. Different streams may submit from different tasks
/// at the same time. Calls on a single stream must remain ordered: begin, then
/// push, each after the previous frame's done, then end.

enum wendy_core_sensor_result {
    WENDY_CORE_SENSOR_OK = 0,
    WENDY_CORE_SENSOR_BUSY,
    WENDY_CORE_SENSOR_BAD_ARG,
};

/// Reports the outcome of push() or end() for the stream client_id/channel_id.
typedef void (*wendy_core_sensor_done_t)(int client_id, uint32_t channel_id,
                                         enum wendy_core_sensor_result result);

/// Opens a stream towards client_id on channel_id and takes its slot.
/// Returns BUSY if this stream still holds a slot (open, or its end or last
/// frame not done yet) or if every slot is in use, and BAD_ARG if client_id is
/// negative. OK means the open was queued: if the com task then refuses it
/// (client gone, stream still draining), it logs a warning and every push gets
/// a non-OK done until end().
enum wendy_core_sensor_result wendy_core_sensor_stream_begin(int client_id, uint32_t channel_id);

/// Pushes one frame of sensor-link data to the client: a video frame, a
/// buffer of audio samples or a batch of sensor readings.
/// The provider buffer must stay valid until done runs. done always runs
/// exactly once, and the caller can then reuse or free the buffer:
/// - OK, on the com task: the frame was sent, or cut short because end() was
///   called, the link died or the client went away mid-frame.
/// - BUSY: this stream's previous push has not reached the com task yet (done
///   runs on the calling task, before push returns), or the com task still
///   holds the previous frame.
/// - BAD_ARG: data is NULL, size is 0 or the stream is not open (done runs on
///   the calling task, before push returns), or the com task refused the
///   frame because the stream is closed or the client is gone.
/// Wait for done before sending the next frame.
void wendy_core_sensor_stream_push(int client_id, uint32_t channel_id, const void *data,
                                   size_t size, uint64_t ts_us, wendy_core_sensor_done_t done);

/// Deprecated: use wendy_core_sensor_stream_push().
/// Like push(), but returns BUSY when this stream's previous push has not
/// reached the com task yet, and BAD_STATE for an empty buffer or a stream
/// that is not open. On refusal, done is not called and the buffer remains
/// the caller's. OK means the operation was queued, not that the frame reached
/// the transport; done then runs exactly once even if the com task rejects it.
WendyComResult wendy_core_sensor_stream_try_push(int client_id, uint32_t channel_id,
                                                const void *data, size_t size, uint64_t ts_us,
                                                void (*done)(uint32_t channel_id));

/// Closes the stream. Call it only once the last frame's done has run, unless
/// the frame should be cut short. done runs exactly once: with OK on the com
/// task once the stream is closed, or with BAD_ARG on the calling task, before
/// end returns, if the stream is not open. A frame still on the transport
/// completes later, and the slot is released after its done.
void wendy_core_sensor_stream_end(int client_id, uint32_t channel_id, wendy_core_sensor_done_t done);

#ifdef __cplusplus
}
#endif
