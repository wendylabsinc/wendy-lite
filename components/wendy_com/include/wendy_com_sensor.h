#ifndef WENDY_COM_SENSOR_H
#define WENDY_COM_SENSOR_H

#include <stddef.h>
#include <stdint.h>
#include "wendy_com_msg.pb.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WCOM_SENSOR_MAX_STREAMS 4

// Streams sensor data to a client as sensor_data messages. Each frame is cut
// into chunks of about 10 KiB, queued one at a time as the previous one goes
// out: frames have no size limit, and other traffic on the link never waits
// for more than one sensor chunk per link. Up to WCOM_SENSOR_MAX_STREAMS
// client/channel streams each retain one frame; ready streams take turns. All
// functions must be called from the com task; wendy_core offers the same
// three, callable from any task.

/// Open a stream on channel_id towards client_id, resetting the frame
/// sequence counter. Nothing goes on the wire: the stream is device-side
/// state, telling the frame calls below where to send. Returns BUSY if this
/// client/channel is already open or still draining, or all slots are in use.
/// Returns BAD_STATE if client_id is not connected.
WendyComResult wcom_sensor_stream_begin(int client_id, uint32_t channel_id);

/// Send one frame on an open stream: a video frame, a buffer of audio samples
/// or a batch of sensor readings, in the format the channel's descriptor
/// announces. On WENDY_COM_RESULT_OK the frame is queued and data must stay
/// valid until done runs; on any other result the frame was not taken and
/// done is not called.
///
/// done runs on the com task once the frame's last chunk has been sent, or
/// the frame was cut short: the link died under it, or the client went away
/// between two chunks. Either way the buffer is free again. It must not call
/// back into wcom_sensor_*: the tx queue may be tearing down around it, and a
/// frame queued from there would be orphaned. Go through
/// wendy_core_sensor_stream_push() instead, which defers to the com task.
WendyComResult wcom_sensor_stream_push(int client_id, uint32_t channel_id,
                                       const void *data, size_t size,
                                       uint64_t ts_us,
                                       void (*done)(uint32_t channel_id));

/// Close the stream. A waiting frame is released immediately. A chunk already
/// queued to the transport finishes before its buffer is released, and no
/// further chunks of that frame are sent. The frame's done still runs exactly
/// once. This client/channel cannot reopen until that callback has run; other
/// streams continue independently. For complete frames, wait for done first.
WendyComResult wcom_sensor_stream_end(int client_id, uint32_t channel_id);

/// Close every stream held by client_id. Buffers still referenced by the
/// transport remain valid until their done callbacks, just as with end().
void wcom_sensor_client_disconnected(int client_id);

#ifdef __cplusplus
}
#endif

#endif
