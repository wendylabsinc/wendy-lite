#ifndef WENDY_COM_SENSOR_H
#define WENDY_COM_SENSOR_H

#include <stddef.h>
#include <stdint.h>
#include "wendy_com_msg.pb.h"

// Streams sensor data to a client as sensor_data messages. Each frame is cut
// into chunks of about 10 KiB, queued one at a time as the previous one goes
// out: frames have no size limit, and other traffic on the link never waits
// for more than one chunk. One stream and one in-flight frame at a time. All
// functions must be called from the com task; wendy_core offers the same
// three, callable from any task.

/// Open a stream on channel_id towards client_id, resetting the frame
/// sequence counter. Nothing goes on the wire: the stream is device-side
/// state, telling the frame calls below where to send. Fails if a stream is
/// already open or client_id is not connected.
WendyComResult wcom_sensor_stream_begin(int client_id, uint32_t channel_id);

/// Send one JPEG frame on an open stream. On WENDY_COM_RESULT_OK the frame is
/// queued and data must stay valid until done runs; on any other result the
/// frame was not taken and done is not called.
///
/// done runs on the com task once the frame's last chunk has been sent, or
/// the frame was cut short: the link died under it, or the client went away
/// between two chunks. Either way the buffer is free again. It must not call
/// back into wcom_sensor_*: the tx queue may be tearing down around it, and a
/// frame queued from there would be orphaned. Go through
/// wendy_core_send_jpeg_frame() instead, which defers to the com task.
WendyComResult wcom_sensor_stream_jpeg_frame(int client_id, uint32_t channel_id,
                                             const void *data, size_t size,
                                             uint64_t ts_us,
                                             void (*done)(uint32_t channel_id));

/// Close the stream. A frame already queued still completes, its remaining
/// chunks going out as usual, and its done callback still runs.
WendyComResult wcom_sensor_stream_end(int client_id, uint32_t channel_id);

/// Drop the stream held by client_id, if any.
void wcom_sensor_client_disconnected(int client_id);

#endif
