#include <stdbool.h>
#include <arpa/inet.h>
#include "wendy_com_agent.h"
#include "wendy_com_link.h"
#include "wendy_com_cmd.h"
#include "wendy_com_msg.pb.h"
#include "esp_log.h"
#include <pb_decode.h>
#include <pb_encode.h>


#define _AGENT_MSG_MAGIC 0xA5
#define _AGENT_MSG_VERSION 2

#define _PROTOCOL_VERSION_MAJOR 2
#define _PROTOCOL_VERSION_MINOR 0


struct _agent_msg_header {
    uint8_t magic;
    uint8_t version;
    uint8_t category;
    uint8_t channel;
    uint16_t reserved;
    uint16_t body_size;
};

struct _agent_link {
    int link_id;
    bool handshake_done;
    struct _agent_msg_header header;
    struct wcom_rx_chunk rx_chunk;
    struct wcom_tx_chunk tx_chunks[2];
    char static_buf[256];
    char *dynamic_buf;
    size_t dynamic_buf_size;
};

struct _span {
    uint8_t *data;
    size_t size;
};


static const char *TAG = "wcom_agent";

static struct _agent_link _links[WCOM_LINK_COUNT];


static void _start_recv_header(struct _agent_link *link);

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
    /* For a pb_istream_from_buffer stream, state is the current read pointer,
       so at callback entry it points to the first byte of the field content. */
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
    link->header.magic = _AGENT_MSG_MAGIC;
    link->header.version = _AGENT_MSG_VERSION;
    link->header.category = 0;
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
        ESP_LOGE(TAG, "ch%d pb_encode sizing: %s", link->link_id, PB_GET_ERROR(&sizing));
        wcom_close(link->link_id);
        return;
    }

    void *buf = _get_buffer(link, sizing.bytes_written);
    pb_ostream_t out_stream = pb_ostream_from_buffer(buf, sizing.bytes_written);
    if (!pb_encode(&out_stream, WendyComMessage_fields, out)) {
        ESP_LOGE(TAG, "ch%d pb_encode message: %s", link->link_id, PB_GET_ERROR(&out_stream));
        wcom_close(link->link_id);
        return;
    }

    _start_sending_msg(link, buf, out_stream.bytes_written);
}

static void _process_handshake(struct _agent_link *link, const WendyComHandshake *hs)
{
    ESP_LOGI(TAG, "ch%d handshake (client %u.%u)", link->link_id,
             hs->has_version ? hs->version.major : 0,
             hs->has_version ? hs->version.minor : 0);
    if (!hs->has_version || hs->version.major != _PROTOCOL_VERSION_MAJOR) {
        ESP_LOGE(TAG, "ch%d unsupported client protocol version", link->link_id);
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

static void _process_command(struct _agent_link *link, const WendyComCommand *cmd, const struct _span *data_span)
{
    WendyComMessage out = WendyComMessage_init_zero;
    out.which_msg = WendyComMessage_response_tag;
    WendyComResponse *resp = &out.msg.response;
    resp->request_id = cmd->request_id;
    resp->result = WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;

    ESP_LOGI(TAG, "ch%d received cmd id %d", link->link_id, cmd->request_id);
    switch (cmd->which_params) {
    case WendyComCommand_ping_tag:
        resp->result = wcom_cmd_ping();
        break;
    case WendyComCommand_reboot_tag:
        resp->result = wcom_cmd_reboot();
        break;
    case WendyComCommand_app_push_begin_tag:
        resp->result = wcom_cmd_app_push_begin(link->link_id, cmd->params.app_push_begin.size,
                                               cmd->params.app_push_begin.app_type);
        break;
    case WendyComCommand_app_push_data_tag:
        if (data_span->data)
            resp->result = wcom_cmd_app_push_data(link->link_id, cmd->params.app_push_data.offset,
                                                  data_span->data, data_span->size);
        else
            resp->result = WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
        break;
    case WendyComCommand_app_push_end_tag:
        resp->result = wcom_cmd_app_push_end(link->link_id);
        break;
    case WendyComCommand_app_start_tag:
        resp->result = wcom_cmd_app_start(link->link_id);
        break;
    case WendyComCommand_app_stop_tag:
        resp->result = wcom_cmd_app_stop(link->link_id);
        break;
    case WendyComCommand_get_device_identity_tag:
        resp->which_data = WendyComResponse_device_identity_tag;
        resp->result = wcom_cmd_get_device_identity(&resp->data.device_identity);
        break;
    case WendyComCommand_get_device_info_tag:
        resp->which_data = WendyComResponse_device_info_tag;
        resp->result = wcom_cmd_get_device_info(&resp->data.device_info);
        break;
    default:
        ESP_LOGW(TAG, "ch%d unknown cmd (which_params=%d)", link->link_id, cmd->which_params);
        resp->result = WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR;
        break;
    }

    _send_message(link, &out);
}

static void _process_message(struct _agent_link *link, const uint8_t *body, size_t size)
{
    struct _span data_span = {NULL, 0};
    WendyComMessage req = WendyComMessage_init_zero;
    /* Pre-set the oneof discriminators along the app_push_data path so nanopb
       preserves our callback when it encounters those fields: it only resets
       a oneof member whose which_ value doesn't already match the wire tag. */
    req.which_msg = WendyComMessage_command_tag;
    req.msg.command.which_params = WendyComCommand_app_push_data_tag;
    req.msg.command.params.app_push_data.data.funcs.decode = _capture_span;
    req.msg.command.params.app_push_data.data.arg = &data_span;
    pb_istream_t stream = pb_istream_from_buffer(body, size);

    if (!pb_decode_noinit(&stream, WendyComMessage_fields, &req)) {
        ESP_LOGE(TAG, "ch%d pb_decode: %s", link->link_id, PB_GET_ERROR(&stream));
        wcom_close(link->link_id);
        return;
    }

    switch (req.which_msg) {
    case WendyComMessage_handshake_tag:
        _process_handshake(link, &req.msg.handshake);
        break;
    case WendyComMessage_command_tag:
        if (!link->handshake_done) {
            ESP_LOGE(TAG, "ch%d command received before handshake", link->link_id);
            wcom_close(link->link_id);
            return;
        }
        _process_command(link, &req.msg.command, &data_span);
        break;
    default:
        ESP_LOGE(TAG, "ch%d unexpected message (which_msg=%d)", link->link_id, req.which_msg);
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
        ESP_LOGE(TAG, "ch%d empty message body", link->link_id);
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

    if (link->header.magic != _AGENT_MSG_MAGIC ||
        link->header.version != _AGENT_MSG_VERSION ||
        link->header.category != 0) {
        ESP_LOGE(TAG, "invalid message header received on link %d", link->link_id);
        wcom_close(link_id);
        return;
    }

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
                _start_recv_header(ch);
                return;
            }
        }
    } else {
        wcom_cmd_client_disconnected(link_id);
        for (int i = 0; i < WCOM_LINK_COUNT; i++) {
            struct _agent_link *ch = &_links[i];
            if (ch->link_id == link_id) {
                ch->link_id = 0;
                free(ch->dynamic_buf);
                ch->dynamic_buf = NULL;
                ch->dynamic_buf_size = 0;
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

void wcom_agent_init(void)
{
    static struct wcom_operation add_handler_op = {
        .func = _add_state_handler,
    };
    wcom_core_exec(&add_handler_op);
}
