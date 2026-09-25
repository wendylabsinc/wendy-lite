#include <arpa/inet.h>
#include <inttypes.h>
#include "wendy_com_sensor.h"
#include "wendy_com_agent.h"
#include "wendy_com_link.h"
#include "wendy_com_msg.pb.h"
#include "sensorlink.pb.h"
#include "esp_log.h"
#include <pb_encode.h>


// SensorData.flags. Every JPEG frame stands on its own, so every chunk is
// marked keyframe; the chunk that ends a frame is marked last.
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

static struct {
    bool active;
    int client_id;
    uint32_t channel_id;
    uint32_t frame_seq;
} _stream;

// Frames share the link tx queue with responses but need their own tx state:
// a link's header/tx_chunks may be busy with an in-flight response. One
// stream exists globally, so one static slot suffices. The slot outlives the
// stream: a frame may still be going out when it ends.
//
// A frame goes out one chunk at a time, each queued from the done handler of
// the one before. The slot thus holds a single message whatever the frame
// size, and whatever else gets queued on the link meanwhile — a response, a
// console event — goes out between two chunks rather than after the whole
// frame. The frame's routing is copied in, not read from _stream, which may be
// ended or reopened before the last chunk is out.
static struct {
    bool busy;
    struct wcom_agent_msg_header header;
    struct wcom_tx_chunk tx_chunks[3];
    uint8_t prefix[_PREFIX_SIZE];
    int client_id;
    uint32_t channel_id;
    uint32_t frame_seq;
    uint32_t chunk_seq; // of the next chunk to queue
    uint64_t ts_us;
    const uint8_t *data;
    size_t size;
    size_t offset;      // payload bytes queued so far
    void (*done)(uint32_t channel_id);
} _frame_slot;


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

// Queues the next chunk of the frame held in _frame_slot. Anything but OK
// means nothing was queued: BAD_STATE if the client is gone, UNKNOWN_ERROR if
// the chunk failed to encode.
static WendyComResult _send_chunk(void)
{
    // Looked up afresh for every chunk: client IDs are never reused, so one
    // that went away since the previous chunk no longer resolves.
    int channel = wcom_get_channel(_frame_slot.client_id);
    int link_id = wcom_get_link_id(_frame_slot.client_id);
    if (channel < 0 || link_id < 0)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;

    size_t size = _frame_slot.size - _frame_slot.offset;
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
    sensor_data.channel_id = _frame_slot.channel_id;
    sensor_data.frame_seq = _frame_slot.frame_seq;
    sensor_data.chunk_seq = _frame_slot.chunk_seq;
    sensor_data.ts_us = _frame_slot.ts_us;
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
    pb_ostream_t out_stream = pb_ostream_from_buffer(_frame_slot.prefix, sizeof(_frame_slot.prefix));
    if (!pb_encode_tag(&out_stream, PB_WT_STRING, WendyComMessage_sensor_data_tag) ||
        !pb_encode_varint(&out_stream, submsg_size) ||
        !pb_write(&out_stream, inner, inner_stream.bytes_written)) {
        ESP_LOGE(TAG, "pb_encode wrapper: %s", PB_GET_ERROR(&out_stream));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }

    _frame_slot.header = (struct wcom_agent_msg_header){
        .magic = WCOM_AGENT_MSG_MAGIC,
        .version = WCOM_AGENT_MSG_VERSION,
        .channel = channel,
        .body_size = htons(out_stream.bytes_written + size),
    };
    _frame_slot.tx_chunks[0].data = &_frame_slot.header;
    _frame_slot.tx_chunks[0].size = sizeof(_frame_slot.header);
    _frame_slot.tx_chunks[0].done_handler = NULL;
    _frame_slot.tx_chunks[0].next = &_frame_slot.tx_chunks[1];
    _frame_slot.tx_chunks[1].data = _frame_slot.prefix;
    _frame_slot.tx_chunks[1].size = out_stream.bytes_written;
    _frame_slot.tx_chunks[1].done_handler = NULL;
    _frame_slot.tx_chunks[1].next = &_frame_slot.tx_chunks[2];
    _frame_slot.tx_chunks[2].data = _frame_slot.data + _frame_slot.offset;
    _frame_slot.tx_chunks[2].size = size;
    _frame_slot.tx_chunks[2].done_handler = _done_sending_chunk;
    _frame_slot.tx_chunks[2].next = NULL;

    _frame_slot.offset += size;
    _frame_slot.chunk_seq++;

    wcom_send(link_id, &_frame_slot.tx_chunks[0]);
    return WendyComResult_WENDY_COM_RESULT_OK;
}

// Frees the slot and hands the producer's buffer back.
static void _finish_frame(void)
{
    void (*done)(uint32_t channel_id) = _frame_slot.done;
    uint32_t channel_id = _frame_slot.channel_id;

    _frame_slot.busy = false;
    _frame_slot.done = NULL;

    if (done)
        done(channel_id);
}

// Called on the com task once a chunk is fully sent (true) or the link's tx
// queue was torn down (false). The frame is over once its last chunk is out,
// or as soon as one cannot go: either way the producer's buffer is free again.
static void _done_sending_chunk(int link_id, const struct wcom_tx_chunk *chunk, bool success)
{
    if (success && _frame_slot.offset < _frame_slot.size) {
        // The link dequeued this chunk before calling us, so the next one can
        // be queued right here. Never on failure: the link is tearing its
        // queue down around us, and a chunk queued now would be orphaned.
        if (_send_chunk() == WendyComResult_WENDY_COM_RESULT_OK)
            return;
        ESP_LOGW(TAG, "frame %" PRIu32 " on channel %" PRIu32 " cut short after %" PRIu32 " chunks",
                 _frame_slot.frame_seq, _frame_slot.channel_id, _frame_slot.chunk_seq);
    }
    _finish_frame();
}

WendyComResult wcom_sensor_stream_begin(int client_id, uint32_t channel_id)
{
    ESP_LOGI(TAG, "STREAM_BEGIN client=%d channel=%" PRIu32, client_id, channel_id);
    if (_stream.active) {
        ESP_LOGW(TAG, "stream already open for client=%d channel=%" PRIu32,
                 _stream.client_id, _stream.channel_id);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    if (wcom_get_link_id(client_id) < 0) {
        ESP_LOGW(TAG, "client %d has no link", client_id);
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    }
    _stream.active = true;
    _stream.client_id = client_id;
    _stream.channel_id = channel_id;
    _stream.frame_seq = 0;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_sensor_stream_jpeg_frame(int client_id, uint32_t channel_id,
                                             const void *data, size_t size,
                                             uint64_t ts_us,
                                             void (*done)(uint32_t channel_id))
{
    if (!_stream.active || client_id != _stream.client_id || channel_id != _stream.channel_id) {
        ESP_LOGW(TAG, "no stream open for client=%d channel=%" PRIu32, client_id, channel_id);
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    }
    if (!data || size == 0) {
        ESP_LOGW(TAG, "empty frame on channel %" PRIu32, channel_id);
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    }
    if (_frame_slot.busy)
        return WendyComResult_WENDY_COM_RESULT_BUSY;

    _frame_slot.busy = true;
    _frame_slot.client_id = client_id;
    _frame_slot.channel_id = channel_id;
    _frame_slot.frame_seq = _stream.frame_seq;
    _frame_slot.chunk_seq = 0;
    _frame_slot.ts_us = ts_us;
    _frame_slot.data = data;
    _frame_slot.size = size;
    _frame_slot.offset = 0;
    _frame_slot.done = done;

    WendyComResult result = _send_chunk();
    if (result != WendyComResult_WENDY_COM_RESULT_OK) {
        if (result == WendyComResult_WENDY_COM_RESULT_BAD_STATE)
            ESP_LOGE(TAG, "client %d has no link for a frame", client_id);
        // Nothing was queued, so the frame was never taken: done stays the
        // caller's business.
        _frame_slot.busy = false;
        _frame_slot.done = NULL;
        return result;
    }

    _stream.frame_seq++;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_sensor_stream_end(int client_id, uint32_t channel_id)
{
    ESP_LOGI(TAG, "STREAM_END client=%d channel=%" PRIu32, client_id, channel_id);
    if (!_stream.active || client_id != _stream.client_id || channel_id != _stream.channel_id)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    _stream.active = false;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

void wcom_sensor_client_disconnected(int client_id)
{
    if (_stream.active && _stream.client_id == client_id) {
        ESP_LOGI(TAG, "client %d disconnected, dropping its stream", client_id);
        _stream.active = false;
    }
}
