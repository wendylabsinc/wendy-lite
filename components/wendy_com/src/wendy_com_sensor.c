#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "wendy_com_sensor.h"
#include "wendy_com_agent.h"
#include "wendy_com_link.h"
#include "wendy_com_msg.pb.h"
#include "sensorlink.pb.h"
#include "esp_log.h"
#include <pb_encode.h>


// SensorData.flags. A push cannot say that a frame depends on an earlier one,
// so every frame is taken to stand on its own and every chunk is marked
// keyframe; the chunk that ends a frame is marked last.
#define _FLAG_KEYFRAME   (1u << 0)
#define _FLAG_LAST_CHUNK (1u << 1)

// A frame goes out as a run of SensorData messages, each at most this big on
// the wire, frame header included.
#define _IDEAL_MSG_SIZE (10 * 1024)

// A SensorData with the payload reduced to its tag and length: the five
// scalars (6 + 6 + 6 + 11 + 6) + payload tag and length (4) = 39 bytes at worst.
#define _INNER_SIZE 40

// The above, wrapped: sensor_data tag (1) + its length as a varint (5) = 45.
#define _PREFIX_SIZE 48

// Payload bytes per chunk: what a message of _IDEAL_MSG_SIZE has left once the
// frame header and the largest prefix are taken out. Every chunk but the last
// of a frame carries exactly this much.
#define _CHUNK_PAYLOAD_SIZE (_IDEAL_MSG_SIZE - sizeof(struct wcom_agent_msg_header) - _PREFIX_SIZE)

_Static_assert(_IDEAL_MSG_SIZE - sizeof(struct wcom_agent_msg_header) <= UINT16_MAX,
               "body_size in the frame header is 16 bits");

static const char *TAG = "wcom_sensor";

struct sensor_frame {
    bool busy;
    bool queued;
    bool cancelled;
    int link_id;
    struct wcom_agent_msg_header header;
    struct wcom_tx_chunk tx_chunks[3];
    uint8_t prefix[_PREFIX_SIZE];
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
    uint8_t *wire;
#endif
    int client_id;
    uint32_t channel_id;
    uint32_t frame_seq;
    uint32_t chunk_seq;
    uint64_t ts_us;
    const uint8_t *data;
    size_t size;
    size_t offset;
    void (*done)(uint32_t channel_id);
};

// A closed stream keeps its slot until the transport releases its frame.
// Payload bytes remain in the producer's buffer; XIAO additionally owns a
// staging buffer for the currently queued message.
static struct sensor_stream {
    bool active;
    int client_id;
    uint32_t channel_id;
    uint32_t frame_seq;
    uint64_t last_scheduled;
    struct sensor_frame frame;
} _streams[WCOM_SENSOR_MAX_STREAMS];

// At most one sensor chunk is queued per link. Completed chunks rotate among
// ready streams and append behind control traffic already in the tx queue.
static uint64_t _schedule_clock;

static void _done_sending_chunk(int link_id, const struct wcom_tx_chunk *chunk, bool success);

// Writes the payload tag and length but not the bytes: those go out as their
// own tx chunk, straight from the producer's buffer. Every length that has to
// cover them is worked out arithmetically in _send_chunk() instead.
static bool _encode_payload_hole(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
    size_t size = *(const size_t *)*arg;
    return pb_encode_tag_for_field(stream, field) &&
           pb_encode_varint(stream, size);
}

// Queues the next chunk of this frame. Anything but OK
// means nothing was queued: BAD_STATE if the client is gone, UNKNOWN_ERROR if
// the chunk failed to encode.
static WendyComResult _send_chunk(struct sensor_frame *frame)
{
    // Looked up afresh for every chunk: client IDs are never reused, so one
    // that went away since the previous chunk no longer resolves.
    int channel = wcom_get_channel(frame->client_id);
    int link_id = wcom_get_link_id(frame->client_id);
    if (channel < 0 || link_id < 0 || link_id != frame->link_id)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;

    size_t size = frame->size - frame->offset;
    uint32_t flags = _FLAG_KEYFRAME;
    if (size > _CHUNK_PAYLOAD_SIZE)
        size = _CHUNK_PAYLOAD_SIZE;
    else
        flags |= _FLAG_LAST_CHUNK;

    // SensorData is encoded on its own and wrapped by hand, rather than as
    // WendyComMessage.sensor_data, because pb_encode_submessage() caps its
    // substream at the length it just measured and then rejects a re-encode
    // that comes out shorter ("submsg size changed"). A payload left out of
    // the bytes on purpose trips both. Encoded standalone there is no such
    // check, and the one length that has to cover the payload — the wrapper's
    // — is computed below.
    wendy_lite_sensorlink_SensorData sensor_data = wendy_lite_sensorlink_SensorData_init_zero;
    sensor_data.channel_id = frame->channel_id;
    sensor_data.frame_seq = frame->frame_seq;
    sensor_data.chunk_seq = frame->chunk_seq;
    sensor_data.ts_us = frame->ts_us;
    sensor_data.flags = flags;
    // size is a stack local, consumed synchronously by the encode below.
    sensor_data.payload.funcs.encode = _encode_payload_hole;
    sensor_data.payload.arg = &size;

    uint8_t inner[_INNER_SIZE];
    pb_ostream_t inner_stream = pb_ostream_from_buffer(inner, sizeof(inner));
    if (!pb_encode(&inner_stream, wendy_lite_sensorlink_SensorData_fields, &sensor_data)) {
        ESP_LOGE(TAG, "pb_encode chunk: %s", PB_GET_ERROR(&inner_stream));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }

    size_t submsg_size = inner_stream.bytes_written + size;
    pb_ostream_t out_stream = pb_ostream_from_buffer(frame->prefix, sizeof(frame->prefix));
    if (!pb_encode_tag(&out_stream, PB_WT_STRING, WendyComMessage_sensor_data_tag) ||
        !pb_encode_varint(&out_stream, submsg_size) ||
        !pb_write(&out_stream, inner, inner_stream.bytes_written)) {
        ESP_LOGE(TAG, "pb_encode wrapper: %s", PB_GET_ERROR(&out_stream));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }

    frame->header = (struct wcom_agent_msg_header){
        .magic = WCOM_AGENT_MSG_MAGIC,
        .version = WCOM_AGENT_MSG_VERSION,
        .channel = channel,
        .body_size = htons(out_stream.bytes_written + size),
    };
    frame->tx_chunks[0].data = &frame->header;
    frame->tx_chunks[0].size = sizeof(frame->header);
    frame->tx_chunks[0].done_handler = NULL;
    frame->tx_chunks[0].next = &frame->tx_chunks[1];
    frame->tx_chunks[1].data = frame->prefix;
    frame->tx_chunks[1].size = out_stream.bytes_written;
    frame->tx_chunks[1].done_handler = NULL;
    frame->tx_chunks[1].next = &frame->tx_chunks[2];
    frame->tx_chunks[2].data = frame->data + frame->offset;
    frame->tx_chunks[2].size = size;
    frame->tx_chunks[2].done_handler = _done_sending_chunk;
    frame->tx_chunks[2].next = NULL;

    frame->offset += size;
    frame->chunk_seq++;

    frame->queued = true;
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
    // Submit the complete message in one TLS write instead of emitting two
    // tiny writes for framing before the payload. The staging buffer
    // remains owned until transport completion, including WANT_WRITE retries.
    size_t wire_size = sizeof(frame->header) + out_stream.bytes_written + size;
    memcpy(frame->wire, &frame->header, sizeof(frame->header));
    memcpy(frame->wire + sizeof(frame->header), frame->prefix, out_stream.bytes_written);
    memcpy(frame->wire + sizeof(frame->header) + out_stream.bytes_written,
           frame->tx_chunks[2].data, size);
    frame->tx_chunks[2].data = frame->wire;
    frame->tx_chunks[2].size = wire_size;
    wcom_send(link_id, &frame->tx_chunks[2]);
#else
    wcom_send(link_id, &frame->tx_chunks[0]);
#endif
    return WendyComResult_WENDY_COM_RESULT_OK;
}

// Release the buffer before notifying its producer. The stream itself stays
// active until end/disconnect, so a completed frame does not reset sequencing.
static void _finish_frame(struct sensor_frame *frame)
{
    void (*done)(uint32_t channel_id) = frame->done;
    uint32_t channel_id = frame->channel_id;
    frame->busy = false;
    frame->queued = false;
    frame->done = NULL;
    frame->data = NULL;
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
    free(frame->wire);
    frame->wire = NULL;
#endif
    if (done)
        done(channel_id);
}

static void _schedule_link(int link_id)
{
    for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
        struct sensor_frame *frame = &_streams[i].frame;
        if (frame->busy && frame->queued && frame->link_id == link_id)
            return;
    }
    for (size_t examined = 0; examined < WCOM_SENSOR_MAX_STREAMS; examined++) {
        struct sensor_stream *next = NULL;
        for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
            struct sensor_stream *stream = &_streams[i];
            if (stream->frame.busy && stream->frame.link_id == link_id &&
                (!next || stream->last_scheduled < next->last_scheduled))
                next = stream;
        }
        if (!next)
            return;
        // Keep this age across frames, so a producer submitting many short
        // frames cannot jump ahead of another stream's waiting long frame.
        next->last_scheduled = ++_schedule_clock;
        struct sensor_frame *frame = &next->frame;
        if (!frame->cancelled && _send_chunk(frame) == WendyComResult_WENDY_COM_RESULT_OK)
            return;
        _finish_frame(frame);
    }
}

static bool _schedule_pending;
static struct wcom_operation _schedule_op;

static void _schedule_exec(struct wcom_operation *op)
{
    _schedule_pending = false;
    for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
        struct sensor_frame *frame = &_streams[i].frame;
        if (frame->busy && !frame->queued)
            _schedule_link(frame->link_id);
    }
}

static void _request_schedule(void)
{
    if (_schedule_pending)
        return;
    for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
        if (_streams[i].frame.busy && !_streams[i].frame.queued) {
            // Yield to the com loop between sensor chunks. Besides limiting
            // queued wire data, this lets RX commands and operations run even
            // when the transport accepts an entire frame without blocking.
            _schedule_pending = true;
            _schedule_op.func = _schedule_exec;
            wcom_core_exec(&_schedule_op);
            return;
        }
    }
}

static void _done_sending_chunk(int link_id, const struct wcom_tx_chunk *chunk, bool success)
{
    struct sensor_frame *frame = NULL;
    for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
        if (&_streams[i].frame.tx_chunks[2] == chunk) {
            frame = &_streams[i].frame;
            break;
        }
    }
    if (!frame || !frame->busy || !frame->queued)
        return;
    frame->queued = false;
    if (!success || frame->cancelled || frame->offset == frame->size)
        _finish_frame(frame);

    if (!success) {
        // Link teardown only visits chunks already on its tx queue. Return
        // the other streams' waiting buffers here too, without queuing any
        // more traffic while the transport is clearing that queue.
        for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
            struct sensor_frame *pending = &_streams[i].frame;
            if (pending->busy && pending->link_id == link_id)
                _finish_frame(pending);
        }
        return;
    }
    _request_schedule();
}

static struct sensor_stream *_find_stream(int client_id, uint32_t channel_id)
{
    for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
        struct sensor_stream *stream = &_streams[i];
        if ((stream->active || stream->frame.busy) &&
            stream->client_id == client_id && stream->channel_id == channel_id)
            return stream;
    }
    return NULL;
}

WendyComResult wcom_sensor_stream_begin(int client_id, uint32_t channel_id)
{
    if (wcom_get_link_id(client_id) < 0)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    if (_find_stream(client_id, channel_id))
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
        struct sensor_stream *stream = &_streams[i];
        if (!stream->active && !stream->frame.busy) {
            stream->active = true;
            stream->client_id = client_id;
            stream->channel_id = channel_id;
            stream->frame_seq = 0;
            stream->last_scheduled = _schedule_clock;
            return WendyComResult_WENDY_COM_RESULT_OK;
        }
    }
    return WendyComResult_WENDY_COM_RESULT_BUSY;
}

WendyComResult wcom_sensor_stream_push(int client_id, uint32_t channel_id,
                                       const void *data, size_t size,
                                       uint64_t ts_us,
                                       void (*done)(uint32_t channel_id))
{
    struct sensor_stream *stream = _find_stream(client_id, channel_id);
    if (!stream || !stream->active || !data || size == 0)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    if (stream->frame.busy)
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    int link_id = wcom_get_link_id(client_id);
    if (link_id < 0 || wcom_get_channel(client_id) < 0)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;

#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
    uint8_t *wire = malloc(_IDEAL_MSG_SIZE);
    if (!wire) return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
#endif
    stream->frame = (struct sensor_frame){
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
        .wire = wire,
#endif
        .busy = true,
        .link_id = link_id,
        .client_id = client_id,
        .channel_id = channel_id,
        .frame_seq = stream->frame_seq++,
        .ts_us = ts_us,
        .data = data,
        .size = size,
        .done = done,
    };
    _schedule_link(link_id);
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_sensor_stream_end(int client_id, uint32_t channel_id)
{
    struct sensor_stream *stream = _find_stream(client_id, channel_id);
    if (!stream || !stream->active)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    stream->active = false;
    if (stream->frame.busy) {
        // A queued chunk may already be partially on the wire; its storage
        // cannot be reused until its completion callback. Stop at that chunk.
        stream->frame.cancelled = true;
        if (!stream->frame.queued)
            _finish_frame(&stream->frame);
    }
    return WendyComResult_WENDY_COM_RESULT_OK;
}

void wcom_sensor_client_disconnected(int client_id)
{
    for (size_t i = 0; i < WCOM_SENSOR_MAX_STREAMS; i++) {
        struct sensor_stream *stream = &_streams[i];
        if (stream->client_id != client_id)
            continue;
        stream->active = false;
        if (stream->frame.busy) {
            stream->frame.cancelled = true;
            if (!stream->frame.queued)
                _finish_frame(&stream->frame);
        }
    }
}
