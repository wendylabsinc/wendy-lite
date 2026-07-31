#include <stdbool.h>
#include <assert.h>
#include <limits.h>
#include <arpa/inet.h>
#include "wendy_com_agent.h"
#include "wendy_com_link.h"
#include "wendy_com_cmd.h"
#include "wendy_com_msg.pb.h"
#include "esp_log.h"
#include <pb_decode.h>
#include <pb_encode.h>


//--- literals ---//

#define _PROTOCOL_VERSION_MAJOR 2
#define _PROTOCOL_VERSION_MINOR 0

#define _CHANNELS_PER_LINK_COUNT 4


//--- types ---//

struct _agent_channel {
    uint32_t channel; // channel number as present in the message header
    int client_id; // identify a specific link and channel
    uint32_t id_gen;
};

struct _agent_link {
    int link_id;
    bool handshake_done;
    uint32_t rx_channel; // channel of the inbound message currently being handled
    struct wcom_agent_msg_header header;
    struct wcom_rx_chunk rx_chunk;
    struct wcom_tx_chunk tx_chunks[2];
    char static_buf[256];
    char *dynamic_buf;
    size_t dynamic_buf_size;
    struct _agent_channel channels[_CHANNELS_PER_LINK_COUNT];
};

struct _span {
    uint8_t *data;
    size_t size;
};

struct _client_ref {
    struct _agent_link *link;
    struct _agent_channel *channel;
};


//--- globals ---//

static const char *TAG = "wcom_agent";

static struct _agent_link _links[WCOM_LINK_COUNT];


//--- private functions ---//

static void _start_recv_header(struct _agent_link *link);

/// A client_id is an opaque ID, which is always positive and non-zero.
/// Internally, the agent is able to extract the link and channel from the client_id.
/// Even if a channel is closed and reopened, it does not get the same client_id.
static int _generate_client_id(int link_index, int channel_index)
{
    uint32_t id;
    do {
        uint32_t n = ++_links[link_index].channels[channel_index].id_gen;
        id = (n * WCOM_LINK_COUNT + link_index) * _CHANNELS_PER_LINK_COUNT + channel_index;
        id &= 0x7FFFFFFF;
    } while (id == 0);
    assert(id <= INT_MAX);
    return (int)id;
}

static struct _client_ref _get_client_ref(int client_id)
{
    struct _client_ref ref = {0};
    if (client_id <= 0)
        return ref;
    int link_index = (client_id / _CHANNELS_PER_LINK_COUNT) % WCOM_LINK_COUNT;
    int channel_index = client_id % _CHANNELS_PER_LINK_COUNT;
    if (link_index < 0 || link_index >= WCOM_LINK_COUNT || channel_index < 0 || channel_index >= _CHANNELS_PER_LINK_COUNT)
        return ref;
    struct _agent_link *link = &_links[link_index];
    if (link->link_id == 0 || link->channels[channel_index].client_id != client_id)
        return ref;
    ref.link = link;
    ref.channel = &link->channels[channel_index];
    return ref;
}

static struct _agent_link *_get_rx_chunk_link(const struct wcom_rx_chunk *chunk)
{
    for (int i = 0; i < WCOM_LINK_COUNT; i++) {
        struct _agent_link *ch = &_links[i];
        if (&ch->rx_chunk == chunk)
            return ch;
    }
    return NULL;
}

static struct _agent_link *_get_tx_chunk_link(const struct wcom_tx_chunk *chunk)
{
    for (int i = 0; i < WCOM_LINK_COUNT; i++) {
        struct _agent_link *ch = &_links[i];
        if (&ch->tx_chunks[0] == chunk || &ch->tx_chunks[1] == chunk)
            return ch;
    }
    return NULL;
}

static void *_get_buffer(struct _agent_link *link, size_t size)
{
    if (size > sizeof(link->static_buf)) {
        if (size > link->dynamic_buf_size) {
            free(link->dynamic_buf);
            link->dynamic_buf = malloc(size);
            if (!link->dynamic_buf) {
                ESP_LOGE(TAG, "malloc failed for dynamic rx buffer of size %zu", size);
                return NULL;
            }
            link->dynamic_buf_size = size;
        }
        return link->dynamic_buf;
    } else {
        return link->static_buf;
    }
}

static bool _capture_span(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    // For a pb_istream_from_buffer stream, state is the current read pointer,
    // so at callback entry it points to the first byte of the field content.
    struct _span *out = *arg;
    out->data = stream->state;
    out->size = stream->bytes_left;
    return pb_read(stream, NULL, stream->bytes_left);
}

static void _done_sending_msg(int link_id, const struct wcom_tx_chunk *chunk, bool success)
{
    if (!success)
        return;
    struct _agent_link *link = _get_tx_chunk_link(chunk);
    assert(link);
    if (link_id != link->link_id)
        return;
    _start_recv_header(link);
}

static void _start_sending_msg(struct _agent_link *link, void *body, size_t size)
{
    link->header.magic = WCOM_AGENT_MSG_MAGIC;
    link->header.version = WCOM_AGENT_MSG_VERSION;
    link->header.category = 0;
    // Replies go out on the channel of the message they answer. The agent
    // handles one message at a time per link, so rx_channel is still the
    // triggering message's channel here.
    link->header.channel = link->rx_channel;
    link->header.reserved = 0;
    link->header.body_size = htons(size);
    link->tx_chunks[0].data = &link->header;
    link->tx_chunks[0].size = sizeof(link->header);
    if (size > 0) {
        link->tx_chunks[0].done_handler = NULL;
        link->tx_chunks[0].next = &link->tx_chunks[1];
        link->tx_chunks[1].data = body;
        link->tx_chunks[1].size = size;
        link->tx_chunks[1].done_handler = _done_sending_msg;
        link->tx_chunks[1].next = NULL;
    } else {
        link->tx_chunks[0].done_handler = _done_sending_msg;
        link->tx_chunks[0].next = NULL;
    }
    wcom_send(link->link_id, &link->tx_chunks[0]);
}

static void _send_message(struct _agent_link *link, const WendyComMessage *out)
{
    pb_ostream_t sizing = PB_OSTREAM_SIZING;
    if (!pb_encode(&sizing, WendyComMessage_fields, out)) {
        ESP_LOGE(TAG, "link %d pb_encode sizing: %s", link->link_id, PB_GET_ERROR(&sizing));
        wcom_close(link->link_id);
        return;
    }

    void *buf = _get_buffer(link, sizing.bytes_written);
    pb_ostream_t out_stream = pb_ostream_from_buffer(buf, sizing.bytes_written);
    if (!pb_encode(&out_stream, WendyComMessage_fields, out)) {
        ESP_LOGE(TAG, "link %d pb_encode message: %s", link->link_id, PB_GET_ERROR(&out_stream));
        wcom_close(link->link_id);
        return;
    }

    _start_sending_msg(link, buf, out_stream.bytes_written);
}

static void _process_handshake(struct _agent_link *link, const WendyComHandshake *hs)
{
    ESP_LOGI(TAG, "link %d handshake (client %u.%u)", link->link_id,
             hs->has_version ? hs->version.major : 0,
             hs->has_version ? hs->version.minor : 0);
    if (!hs->has_version || hs->version.major != _PROTOCOL_VERSION_MAJOR) {
        ESP_LOGE(TAG, "link %d unsupported client protocol version", link->link_id);
        wcom_close(link->link_id);
        return;
    }
    link->handshake_done = true;

    WendyComMessage out = WendyComMessage_init_zero;
    out.which_msg = WendyComMessage_handshake_tag;
    out.msg.handshake.handshake_id = hs->handshake_id;
    out.msg.handshake.has_version = true;
    out.msg.handshake.version.major = _PROTOCOL_VERSION_MAJOR;
    out.msg.handshake.version.minor = _PROTOCOL_VERSION_MINOR;
    _send_message(link, &out);
}

static struct _agent_channel *_find_channel(struct _agent_link *link, uint32_t channel)
{
    for (int i = 0; i < _CHANNELS_PER_LINK_COUNT; i++) {
        if (link->channels[i].client_id != 0 && link->channels[i].channel == channel)
            return &link->channels[i];
    }
    return NULL;
}

// Reply to the message just received with a ChannelState report. The reply
// goes out on link->rx_channel — the channel the message arrived on, which is
// the channel the report is about.
static void _send_channel_state(struct _agent_link *link, pb_size_t which_state,
                                WendyComChannelErrorReason reason)
{
    WendyComMessage out = WendyComMessage_init_zero;
    out.which_msg = WendyComMessage_service_tag;
    out.msg.service.which_cmd = WendyComService_channel_state_tag;
    out.msg.service.cmd.channel_state.which_state = which_state;
    if (which_state == WendyComChannelState_error_tag)
        out.msg.service.cmd.channel_state.state.error.reason = reason;
    _send_message(link, &out);
}

static void _open_channel(struct _agent_link *link, uint8_t channel)
{
    if (_find_channel(link, channel)) {
        // includes channel 0, which is pre-opened at link connect
        ESP_LOGW(TAG, "link %d channel %u already open", link->link_id, channel);
        _send_channel_state(link, WendyComChannelState_error_tag,
                            WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_REJECTED);
        return;
    }
    int link_index = link - _links;
    for (int i = 0; i < _CHANNELS_PER_LINK_COUNT; i++) {
        if (link->channels[i].client_id == 0) {
            link->channels[i].channel = channel;
            link->channels[i].client_id = _generate_client_id(link_index, i);
            ESP_LOGI(TAG, "link %d channel %u open (client %d)",
                     link->link_id, channel, link->channels[i].client_id);
            _send_channel_state(link, WendyComChannelState_open_tag, 0);
            return;
        }
    }
    ESP_LOGE(TAG, "link %d cannot open channel %u: all %d channels in use",
             link->link_id, channel, _CHANNELS_PER_LINK_COUNT);
    _send_channel_state(link, WendyComChannelState_error_tag,
                        WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_REJECTED);
}

static void _close_channel(struct _agent_link *link, uint8_t channel)
{
    if (channel == 0) {
        ESP_LOGW(TAG, "link %d close channel 0 rejected (never closed)", link->link_id);
        _send_channel_state(link, WendyComChannelState_error_tag,
                            WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_REJECTED);
        return;
    }
    struct _agent_channel *entry = _find_channel(link, channel);
    if (!entry) {
        ESP_LOGW(TAG, "link %d close of unopened channel %u rejected", link->link_id, channel);
        _send_channel_state(link, WendyComChannelState_error_tag,
                            WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_REJECTED);
        return;
    }
    ESP_LOGI(TAG, "link %d channel %u closed (client %d)",
             link->link_id, channel, entry->client_id);
    wcom_cmd_client_disconnected(entry->client_id);
    entry->client_id = 0;
    entry->channel = -1;
    _send_channel_state(link, WendyComChannelState_close_tag, 0);
}

// Channel management is link-level, not session-level: the cloud broker
// opens the first tunnel channel before that tunnel's handshake reaches us,
// so service messages are accepted even before the handshake. Every service
// message is answered with a ChannelState report, whose completion re-arms
// the header read.
static void _process_service_message(struct _agent_link *link, const WendyComService *svc)
{
    switch (svc->which_cmd) {
    case WendyComService_open_channel_tag:
        _open_channel(link, link->rx_channel);
        break;
    case WendyComService_close_channel_tag:
        _close_channel(link, link->rx_channel);
        break;
    default:
        ESP_LOGW(TAG, "link %d disallowed service msg rejected (which_cmd=%d)",
                 link->link_id, svc->which_cmd);
        _send_channel_state(link, WendyComChannelState_error_tag,
                            WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_REJECTED);
        break;
    }
}

static void _process_command(struct _agent_link *link, const WendyComCommand *cmd, const struct _span *data_span)
{
    struct _agent_channel *channel = _find_channel(link, link->rx_channel);
    if (!channel) {
        ESP_LOGW(TAG, "link %d cmd id %d on unopened channel %u",
                 link->link_id, cmd->request_id, link->rx_channel);
        _send_channel_state(link, WendyComChannelState_error_tag,
                            WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_NOT_OPEN);
        return;
    }
    int client_id = channel->client_id;

    WendyComMessage out = WendyComMessage_init_zero;
    out.which_msg = WendyComMessage_response_tag;
    WendyComResponse *resp = &out.msg.response;
    resp->request_id = cmd->request_id;
    resp->result = WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;

    ESP_LOGI(TAG, "link %d received cmd id %d", link->link_id, cmd->request_id);

    switch (cmd->which_params) {
    case WendyComCommand_ping_tag:
        resp->result = wcom_cmd_ping();
        break;
    case WendyComCommand_reboot_tag:
        resp->result = wcom_cmd_reboot(
            cmd->params.reboot.has_app_auto_start ? cmd->params.reboot.app_auto_start : true,
            cmd->params.reboot.app_auto_start_delay);
        break;
    case WendyComCommand_app_push_begin_tag:
        resp->result = wcom_cmd_app_push_begin(client_id, cmd->params.app_push_begin.size,
                                               cmd->params.app_push_begin.app_type);
        break;
    case WendyComCommand_app_push_data_tag:
        if (data_span->data)
            resp->result = wcom_cmd_app_push_data(client_id, cmd->params.app_push_data.offset,
                                                  data_span->data, data_span->size);
        else
            resp->result = WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
        break;
    case WendyComCommand_app_push_end_tag:
        resp->result = wcom_cmd_app_push_end(client_id);
        break;
    case WendyComCommand_conf_push_begin_tag:
        resp->result = wcom_cmd_conf_push_begin(client_id, cmd->params.conf_push_begin.size,
                                                cmd->params.conf_push_begin.mode);
        break;
    case WendyComCommand_conf_push_data_tag:
        if (data_span->data)
            resp->result = wcom_cmd_conf_push_data(client_id, cmd->params.conf_push_data.offset,
                                                   data_span->data, data_span->size);
        else
            resp->result = WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
        break;
    case WendyComCommand_conf_push_end_tag:
        resp->result = wcom_cmd_conf_push_end(client_id);
        break;
    case WendyComCommand_app_start_tag:
        resp->result = wcom_cmd_app_start(client_id);
        break;
    case WendyComCommand_app_stop_tag:
        resp->result = wcom_cmd_app_stop(client_id);
        break;
    case WendyComCommand_get_device_identity_tag:
        resp->which_data = WendyComResponse_device_identity_tag;
        resp->result = wcom_cmd_get_device_identity(&resp->data.device_identity);
        break;
    case WendyComCommand_get_device_info_tag:
        resp->which_data = WendyComResponse_device_info_tag;
        resp->result = wcom_cmd_get_device_info(&resp->data.device_info);
        break;
    case WendyComCommand_console_attach_tag:
        resp->result = wcom_cmd_console_attach(client_id,
                                               cmd->params.console_attach.event_id,
                                               cmd->params.console_attach.duration,
                                               cmd->params.console_attach.blocking);
        break;
    case WendyComCommand_console_detach_tag:
        resp->result = wcom_cmd_console_detach(client_id,
                                               cmd->params.console_detach.event_id);
        break;
    default:
        ESP_LOGW(TAG, "link %d unknown cmd (which_params=%d)", link->link_id, cmd->which_params);
        resp->result = WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
        break;
    }

    _send_message(link, &out);
}

// Host -> device events carry no response, so every non-reply path must
// re-arm the header read itself: the other message kinds get it from
// _done_sending_msg when their reply finishes sending.
static void _process_event(struct _agent_link *link, const WendyComEvent *evt, const struct _span *data_span)
{
    struct _agent_channel *channel = _find_channel(link, link->rx_channel);
    if (!channel) {
        ESP_LOGW(TAG, "link %d event on unopened channel %u", link->link_id, link->rx_channel);
        _send_channel_state(link, WendyComChannelState_error_tag,
                            WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_NOT_OPEN);
        return;
    }

    if (evt->which_data == WendyComEvent_console_data_tag &&
        evt->data.console_data.io == WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_INPUT) {
        if (data_span->data)
            wcom_cmd_console_stdin_data(channel->client_id, data_span->data, data_span->size);
    } else {
        ESP_LOGW(TAG, "link %d unexpected event ignored (which_data=%d)",
                 link->link_id, evt->which_data);
    }
    _start_recv_header(link);
}

static void _process_message(struct _agent_link *link, const uint8_t *body, size_t size)
{
    struct _span data_span = {NULL, 0};
    WendyComMessage req = WendyComMessage_init_zero;
    // Pre-set the oneof discriminators along the app_push_data path so nanopb
    // preserves our callback when it encounters those fields: it only resets
    // a oneof member whose which_ value doesn't already match the wire tag.
    req.which_msg = WendyComMessage_command_tag;
    req.msg.command.which_params = WendyComCommand_app_push_data_tag;
    req.msg.command.params.app_push_data.data.funcs.decode = _capture_span;
    req.msg.command.params.app_push_data.data.arg = &data_span;
    pb_istream_t stream = pb_istream_from_buffer(body, size);

    if (!pb_decode_noinit(&stream, WendyComMessage_fields, &req)) {
        ESP_LOGE(TAG, "link %d pb_decode: %s", link->link_id, PB_GET_ERROR(&stream));
        wcom_close(link->link_id);
        return;
    }

    // Only one oneof member can be pre-set per decode, so a conf_push_data
    // command came out with its data callback reset and the bytes skipped.
    // Decode again with the conf_push_data path pre-set instead.
    if (req.which_msg == WendyComMessage_command_tag &&
        req.msg.command.which_params == WendyComCommand_conf_push_data_tag) {
        data_span = (struct _span){NULL, 0};
        req = (WendyComMessage)WendyComMessage_init_zero;
        req.which_msg = WendyComMessage_command_tag;
        req.msg.command.which_params = WendyComCommand_conf_push_data_tag;
        req.msg.command.params.conf_push_data.data.funcs.decode = _capture_span;
        req.msg.command.params.conf_push_data.data.arg = &data_span;
        stream = pb_istream_from_buffer(body, size);
        if (!pb_decode_noinit(&stream, WendyComMessage_fields, &req)) {
            ESP_LOGE(TAG, "link %d pb_decode: %s", link->link_id, PB_GET_ERROR(&stream));
            wcom_close(link->link_id);
            return;
        }
    }

    // Same limitation for an inbound console_data event (host -> device
    // stdin): decode again with the event path pre-set.
    if (req.which_msg == WendyComMessage_event_tag &&
        req.msg.event.which_data == WendyComEvent_console_data_tag) {
        data_span = (struct _span){NULL, 0};
        req = (WendyComMessage)WendyComMessage_init_zero;
        req.which_msg = WendyComMessage_event_tag;
        req.msg.event.which_data = WendyComEvent_console_data_tag;
        req.msg.event.data.console_data.data.funcs.decode = _capture_span;
        req.msg.event.data.console_data.data.arg = &data_span;
        stream = pb_istream_from_buffer(body, size);
        if (!pb_decode_noinit(&stream, WendyComMessage_fields, &req)) {
            ESP_LOGE(TAG, "link %d pb_decode: %s", link->link_id, PB_GET_ERROR(&stream));
            wcom_close(link->link_id);
            return;
        }
    }

    switch (req.which_msg) {
    case WendyComMessage_handshake_tag:
        _process_handshake(link, &req.msg.handshake);
        break;
    case WendyComMessage_command_tag:
        if (!link->handshake_done) {
            ESP_LOGE(TAG, "link %d command received before handshake", link->link_id);
            wcom_close(link->link_id);
            return;
        }
        _process_command(link, &req.msg.command, &data_span);
        break;
    case WendyComMessage_service_tag:
        _process_service_message(link, &req.msg.service);
        break;
    case WendyComMessage_event_tag:
        if (!link->handshake_done) {
            ESP_LOGE(TAG, "link %d event received before handshake", link->link_id);
            wcom_close(link->link_id);
            return;
        }
        _process_event(link, &req.msg.event, &data_span);
        break;
    default:
        ESP_LOGE(TAG, "link %d unexpected message (which_msg=%d)", link->link_id, req.which_msg);
        wcom_close(link->link_id);
        break;
    }
}

static void _done_recv_body(int link_id, const struct wcom_rx_chunk *chunk, bool success)
{
    if (!success)
        return;
    struct _agent_link *link = _get_rx_chunk_link(chunk);
    assert(link);
    if (link_id != link->link_id)
        return;

    _process_message(link, chunk->data, chunk->size);
}

static void _start_recv_body(struct _agent_link *link)
{
    size_t body_size = ntohs(link->header.body_size);
    if (body_size == 0) {
        // an empty body is not a valid WendyComMessage
        ESP_LOGE(TAG, "link %d empty message body", link->link_id);
        wcom_close(link->link_id);
        return;
    }
    link->rx_chunk.data = _get_buffer(link, body_size);
    link->rx_chunk.size = body_size;
    link->rx_chunk.done_handler = _done_recv_body;
    link->rx_chunk.next = NULL;
    wcom_recv(link->link_id, &link->rx_chunk);
}

static void _done_recv_header(int link_id, const struct wcom_rx_chunk *chunk, bool success)
{
    if (!success)
        return;
    struct _agent_link *link = _get_rx_chunk_link(chunk);
    assert(link);
    if (link_id != link->link_id)
        return;

    if (link->header.magic != WCOM_AGENT_MSG_MAGIC ||
        link->header.version != WCOM_AGENT_MSG_VERSION ||
        link->header.category != 0) {
        ESP_LOGE(TAG, "invalid message header received on link %d", link->link_id);
        wcom_close(link_id);
        return;
    }

    link->rx_channel = link->header.channel;

    _start_recv_body(link);
}

static void _start_recv_header(struct _agent_link *link)
{
    link->rx_chunk.data = &link->header;
    link->rx_chunk.size = sizeof(link->header);
    link->rx_chunk.done_handler = _done_recv_header;
    link->rx_chunk.next = NULL;
    wcom_recv(link->link_id, &link->rx_chunk);
}

static void _on_link_state_changed(
    struct wcom_state_change_handler *handler,
    int link_id,
    enum wcom_link_state state)
{
    if (state == WCOM_LINK_STATE_CONNECTED) {
        for (int i = 0; i < WCOM_LINK_COUNT; i++) {
            struct _agent_link *ch = &_links[i];
            if (ch->link_id == 0) {
                ch->link_id = link_id;
                ch->handshake_done = false;
                ch->rx_channel = 0;
                for (int i = 0; i < _CHANNELS_PER_LINK_COUNT; i++) {
                    ch->channels[i].client_id = 0;
                    ch->channels[i].channel = -1;
                }
                ch->channels[0].client_id = _generate_client_id(i, 0);
                ch->channels[0].channel = 0;
                _start_recv_header(ch);
                return;
            }
        }
    } else {
        for (int i = 0; i < WCOM_LINK_COUNT; i++) {
            struct _agent_link *link = &_links[i];
            if (link->link_id == link_id) {
                for (int j = 0; j < _CHANNELS_PER_LINK_COUNT; j++) {
                    if (link->channels[j].client_id != 0) {
                        wcom_cmd_client_disconnected(link->channels[j].client_id);
                    }
                    link->channels[j].client_id = 0;
                    link->channels[j].channel = -1;
                }
                link->handshake_done = false;
                link->link_id = 0;
                free(link->dynamic_buf);
                link->dynamic_buf = NULL;
                link->dynamic_buf_size = 0;
                return;
            }
        }
    }
}

static void _add_state_handler(struct wcom_operation *op)
{
    static struct wcom_state_change_handler state_handler = {
        .func = _on_link_state_changed,
    };
    wcom_add_state_change_handler(&state_handler);
}


//--- public functions ---//

void wcom_agent_init(void)
{
    static struct wcom_operation add_handler_op = {
        .func = _add_state_handler,
    };
    wcom_core_exec(&add_handler_op);
}

int wcom_get_link_id(int client_id)
{
    struct _client_ref ref = _get_client_ref(client_id);
    if (!ref.link)
        return -1;
    return ref.link->link_id;
}

int wcom_get_channel(int client_id)
{
    struct _client_ref ref = _get_client_ref(client_id);
    if (!ref.channel)
        return -1;
    return (int)ref.channel->channel;
}
