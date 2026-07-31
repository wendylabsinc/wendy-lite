#include <stdlib.h>
#include <arpa/inet.h>
#include "wendy_com_stdio_pump.h"
#include "wendy_com_stdio.h"
#include "wendy_com_agent.h"
#include "wendy_com_link.h"
#include "wendy_com_msg.pb.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <pb_encode.h>


#define _CHUNK_SIZE 512

static const char *TAG = "wcom_stdio_pump";

static struct {
    bool attached;
    int client_id;
    uint32_t event_id;
    int64_t deadline_us;
} _state;

static bool _kick_queued;

// Events share the link tx queue with responses but need their own tx state:
// a link's header/tx_chunks may be busy with an in-flight response. A single
// attachment exists globally, so one static slot suffices. The slot outlives
// an attachment: a frame may still be queued across detach/re-attach.
static struct {
    struct wcom_agent_msg_header header;
    struct wcom_tx_chunk tx_chunks[2];
    void *body_data;    // grown on demand; freed once detached and idle
    size_t body_size;
    bool busy;
} _event_slot;

struct _span {
    const uint8_t *data;
    size_t size;
};

static void _pump(void);
static void _schedule_pump(void);

// The body buffer may be freed only when no queued frame references it and
// no attachment will reuse it.
static void _free_body_if_unused(void)
{
    if (_event_slot.busy || _state.attached)
        return;
    free(_event_slot.body_data);
    _event_slot.body_data = NULL;
    _event_slot.body_size = 0;
}

// Called on the com task once the frame is fully sent (true) or the link's
// tx queue was torn down (false).
static void _done_sending_event(int link_id, const struct wcom_tx_chunk *chunk, bool success)
{
    _event_slot.busy = false;
    _free_body_if_unused();
    if (success) {
        _pump();
    } else {
        // The link is tearing down its tx queue and invokes done handlers
        // while iterating it — a chunk enqueued inline here would be
        // orphaned, so defer.
        _schedule_pump();
    }
}

static bool _encode_bytes(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
    const struct _span *span = *arg;
    return pb_encode_tag_for_field(stream, field) &&
           pb_encode_string(stream, span->data, span->size);
}

static void _detach(void)
{
    wcom_stdio_set_data_handler(NULL, NULL);
    wcom_stdio_set_blocking(false); // writers must never stay blocked with nobody draining
    _state.attached = false;
    _free_body_if_unused();
}

static void _kick_func(struct wcom_operation *op)
{
    _kick_queued = false;
    _pump();
}

static struct wcom_operation _kick_op = {
    .func = _kick_func,
};

static void _schedule_pump(void)
{
    if (!_kick_queued) {
        _kick_queued = true;
        wcom_core_exec(&_kick_op);
    }
}

static void _data_handler(void *ctx)
{
    _pump();
}

// Single funnel for streaming stdio data: called when new data arrives,
// when the previous event was sent, and once after attach. The auto-detach
// deadline is checked lazily exactly here.
static void _pump(void)
{
    if (!_state.attached || _event_slot.busy)
        return; // busy: the queued frame's done callback re-pumps
    if (esp_timer_get_time() >= _state.deadline_us) {
        _detach();
        return;
    }

    bool gap;
    uint8_t buf[_CHUNK_SIZE];
    size_t n = wcom_stdio_read(buf, sizeof(buf), &gap);
    if (n == 0)
        return; // ring empty and re-armed: the data handler fires on next data

    struct _span span = { buf, n };
    WendyComMessage out = WendyComMessage_init_zero;
    out.which_msg = WendyComMessage_event_tag;
    WendyComEvent *evt = &out.msg.event;
    evt->event_id = _state.event_id;
    evt->which_data = WendyComEvent_console_data_tag;
    evt->data.console_data.io = WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_OUTPUT;
    evt->data.console_data.gap = gap;
    evt->data.console_data.data.funcs.encode = _encode_bytes;
    evt->data.console_data.data.arg = &span;

    // span is a stack local: the sizing pass and pb_encode consume it
    // synchronously here
    size_t needed;
    if (!pb_get_encoded_size(&needed, WendyComMessage_fields, &out)) {
        ESP_LOGE(TAG, "client %d pb_get_encoded_size failed", _state.client_id);
        return;
    }
    if (needed > _event_slot.body_size) {
        void *body = realloc(_event_slot.body_data, needed);
        if (!body) {
            ESP_LOGE(TAG, "client %d realloc failed for event body of size %zu", _state.client_id, needed);
            return;
        }
        _event_slot.body_data = body;
        _event_slot.body_size = needed;
    }
    pb_ostream_t out_stream = pb_ostream_from_buffer(_event_slot.body_data, _event_slot.body_size);
    if (!pb_encode(&out_stream, WendyComMessage_fields, &out)) {
        ESP_LOGE(TAG, "client %d pb_encode event: %s", _state.client_id, PB_GET_ERROR(&out_stream));
        return;
    }

    int channel = wcom_get_channel(_state.client_id);
    if (channel < 0) {
        ESP_LOGE(TAG, "client %d has no channel for event", _state.client_id);
        return;
    }

    int link_id = wcom_get_link_id(_state.client_id);
    if (link_id < 0) {
        ESP_LOGE(TAG, "client %d has no link for event", _state.client_id);
        return;
    }
    
    _event_slot.busy = true;
    _event_slot.header = (struct wcom_agent_msg_header){
        .magic = WCOM_AGENT_MSG_MAGIC,
        .version = WCOM_AGENT_MSG_VERSION,
        .channel = channel,
        .body_size = htons(out_stream.bytes_written),
    };
    _event_slot.tx_chunks[0].data = &_event_slot.header;
    _event_slot.tx_chunks[0].size = sizeof(_event_slot.header);
    _event_slot.tx_chunks[0].done_handler = NULL;
    _event_slot.tx_chunks[0].next = &_event_slot.tx_chunks[1];
    _event_slot.tx_chunks[1].data = _event_slot.body_data;
    _event_slot.tx_chunks[1].size = out_stream.bytes_written;
    _event_slot.tx_chunks[1].done_handler = _done_sending_event;
    _event_slot.tx_chunks[1].next = NULL;
    
    wcom_send(link_id, &_event_slot.tx_chunks[0]);
}

WendyComResult wcom_stdio_pump_attach(int client_id, uint32_t event_id, uint32_t duration_ms, bool blocking_mode)
{
    int64_t deadline_us = duration_ms > 0 ?
        esp_timer_get_time() + (int64_t)duration_ms * 1000 : INT64_MAX; // 0 = forever
    if (_state.attached && _state.client_id == client_id && _state.event_id == event_id) {
        _state.deadline_us = deadline_us;
        wcom_stdio_set_blocking(blocking_mode);
        _schedule_pump();
        return WendyComResult_WENDY_COM_RESULT_OK;
    }
    if (_state.attached)
        _detach();
    _state.attached = true;
    _state.client_id = client_id;
    _state.event_id = event_id;
    _state.deadline_us = deadline_us;
    wcom_stdio_set_blocking(blocking_mode);
    wcom_stdio_set_data_handler(_data_handler, NULL);
    // Deferred first drain: the kick op runs after the attach response is
    // queued (so the response frame precedes the first event frame) and
    // covers data buffered before any handler was registered, for which the
    // stdio module's internal notify does not fire.
    _schedule_pump();
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_stdio_pump_detach(int client_id, uint32_t event_id)
{
    if (!_state.attached || _state.client_id != client_id || _state.event_id != event_id)
        return WendyComResult_WENDY_COM_RESULT_BAD_STATE;
    _detach();
    return WendyComResult_WENDY_COM_RESULT_OK;
}

void wcom_stdio_pump_client_disconnected(int client_id)
{
    if (_state.attached && client_id == _state.client_id)
        _detach();
}
