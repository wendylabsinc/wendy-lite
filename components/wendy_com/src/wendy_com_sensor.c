#include <arpa/inet.h>
#include <inttypes.h>
#include "wendy_com_sensor.h"
#include "wendy_com_agent.h"
#include "wendy_com_link.h"
#include "wendy_com_msg.pb.h"
#include "sensorlink.pb.h"
#include "esp_log.h"
#include <pb_encode.h>


// bit0 of SensorFrame.flags. Every JPEG frame stands on its own.
#define _FLAG_KEYFRAME 1u

// A SensorFrame with the payload reduced to its tag and length: the four
// scalars (6 + 6 + 11 + 6) + payload tag and length (4) = 33 bytes at worst.
#define _INNER_SIZE 40

// The above, wrapped: sensor_frame tag (1) + its length as a varint (5) = 39.
#define _PREFIX_SIZE 48

static const char *TAG = "wcom_sensor";

static struct {
    bool active;
    int client_id;
    uint32_t channel_id;
    uint32_t seq;
} _stream;

// Frames share the link tx queue with responses but need their own tx state:
// a link's header/tx_chunks may be busy with an in-flight response. One
// stream exists globally, so one static slot suffices. The slot outlives the
// stream: a frame may still be queued when it ends.
static struct {
    bool busy;
    struct wcom_agent_msg_header header;
    struct wcom_tx_chunk tx_chunks[3];
    uint8_t prefix[_PREFIX_SIZE];
    uint32_t channel_id;
    void (*done)(uint32_t channel_id);
} _frame_slot;


// Writes the payload tag and length but not the bytes: those go out as their
// own tx chunk, straight from the producer's buffer. Every length that has to
// cover them is worked out arithmetically in _send_frame() instead.
static bool _encode_payload_hole(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
    size_t size = *(const size_t *)*arg;
    return pb_encode_tag_for_field(stream, field) &&
           pb_encode_varint(stream, size);
}

// Called on the com task once the frame is fully sent (true) or the link's tx
// queue was torn down (false). Either way the producer's buffer is free again.
static void _done_sending_frame(int link_id, const struct wcom_tx_chunk *chunk, bool success)
{
    void (*done)(uint32_t channel_id) = _frame_slot.done;
    uint32_t channel_id = _frame_slot.channel_id;

    _frame_slot.busy = false;
    _frame_slot.done = NULL;

    if (done)
        done(channel_id);
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
    _stream.seq = 0;
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

    int channel = wcom_get_channel(client_id);
    int link_id = wcom_get_link_id(client_id);
    if (channel < 0 || link_id < 0) {
        ESP_LOGE(TAG, "client %d has no link for a frame", client_id);
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    }

    // SensorFrame is encoded on its own and wrapped by hand, rather than as
    // WendyComMessage.sensor_frame, because pb_encode_submessage() caps its
    // substream at the length it just measured and then rejects a re-encode
    // that comes out shorter ("submsg size changed"). A payload left out of
    // the bytes on purpose trips both. Encoded standalone there is no such
    // check, and the one length that has to cover the payload — the wrapper's
    // — is computed below.
    wendy_lite_sensorlink_SensorFrame frame = wendy_lite_sensorlink_SensorFrame_init_zero;
    frame.channel_id = channel_id;
    frame.seq = _stream.seq;
    frame.ts_us = ts_us;
    frame.flags = _FLAG_KEYFRAME;
    // size is a stack local, consumed synchronously by the encode below.
    frame.payload.funcs.encode = _encode_payload_hole;
    frame.payload.arg = &size;

    uint8_t inner[_INNER_SIZE];
    pb_ostream_t inner_stream = pb_ostream_from_buffer(inner, sizeof(inner));
    if (!pb_encode(&inner_stream, wendy_lite_sensorlink_SensorFrame_fields, &frame)) {
        ESP_LOGE(TAG, "pb_encode frame: %s", PB_GET_ERROR(&inner_stream));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }

    size_t submsg_size = inner_stream.bytes_written + size;
    pb_ostream_t out_stream = pb_ostream_from_buffer(_frame_slot.prefix, sizeof(_frame_slot.prefix));
    if (!pb_encode_tag(&out_stream, PB_WT_STRING, WendyComMessage_sensor_frame_tag) ||
        !pb_encode_varint(&out_stream, submsg_size) ||
        !pb_write(&out_stream, inner, inner_stream.bytes_written)) {
        ESP_LOGE(TAG, "pb_encode wrapper: %s", PB_GET_ERROR(&out_stream));
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }

    size_t total = out_stream.bytes_written + size;
    if (total > UINT16_MAX) {
        // body_size in the frame header is 16 bits, so this one cannot go out
        // whole and there is no fragmentation at this layer.
        ESP_LOGE(TAG, "frame of %zu bytes exceeds the %u byte message limit",
                 size, (unsigned)UINT16_MAX);
        return WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
    }

    _stream.seq++;

    _frame_slot.busy = true;
    _frame_slot.channel_id = channel_id;
    _frame_slot.done = done;
    _frame_slot.header = (struct wcom_agent_msg_header){
        .magic = WCOM_AGENT_MSG_MAGIC,
        .version = WCOM_AGENT_MSG_VERSION,
        .channel = channel,
        .body_size = htons(total),
    };
    _frame_slot.tx_chunks[0].data = &_frame_slot.header;
    _frame_slot.tx_chunks[0].size = sizeof(_frame_slot.header);
    _frame_slot.tx_chunks[0].done_handler = NULL;
    _frame_slot.tx_chunks[0].next = &_frame_slot.tx_chunks[1];
    _frame_slot.tx_chunks[1].data = _frame_slot.prefix;
    _frame_slot.tx_chunks[1].size = out_stream.bytes_written;
    _frame_slot.tx_chunks[1].done_handler = NULL;
    _frame_slot.tx_chunks[1].next = &_frame_slot.tx_chunks[2];
    _frame_slot.tx_chunks[2].data = data;
    _frame_slot.tx_chunks[2].size = size;
    _frame_slot.tx_chunks[2].done_handler = _done_sending_frame;
    _frame_slot.tx_chunks[2].next = NULL;

    wcom_send(link_id, &_frame_slot.tx_chunks[0]);
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
