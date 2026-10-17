/* Compile the production link, protocol dispatcher, and command delegates.
 * Only transport scheduling and the application/stdio effects are replaced. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#define ESP_LOGD(tag, ...) ((void)(tag))
#define _links transport_links
#define TAG transport_tag
#include "../src/wendy_com_link.c"
#undef _links
#undef TAG
#include "../src/wendy_com_agent.c"
#define TAG command_tag
#include "../src/wendy_com_cmd.c"
#undef TAG

static unsigned management_calls, stdin_calls, sensor_calls, disconnected_calls;
static int sensor_client;
static enum wcom_sensor_link_result subscription_result = WCOM_SENSOR_LINK_OK;
static bool resetting;

int64_t esp_timer_get_time(void) { return 1000; }

ssize_t wendy_com_uart_read(wendy_com_uart_t *uart, void *data, size_t size) { return -1; }
ssize_t wendy_com_uart_write(wendy_com_uart_t *uart, const void *data, size_t size) { return -1; }
int wendy_com_uart_get_fd(wendy_com_uart_t *uart) { return uart->fd; }
int64_t wendy_com_uart_auto_close_delay(wendy_com_uart_t *uart) { return -1; }
void wcom_stdio_pump_client_disconnected(int id) {}
void wcom_sensor_client_disconnected(int id) {}
WendyComResult wcom_stdio_pump_attach(int id, uint32_t event, uint32_t duration, bool blocking)
{ management_calls++; return WendyComResult_WENDY_COM_RESULT_OK; }
WendyComResult wcom_stdio_pump_detach(int id, uint32_t event)
{ management_calls++; return WendyComResult_WENDY_COM_RESULT_OK; }
size_t wendy_stdio_put_stdin_data(const void *data, size_t size)
{ assert(size == 5 && !memcmp(data, "input", 5)); stdin_calls++; return size; }
bool wendy_pki_reset_in_progress(void) { return resetting; }
void wendy_pki_builtin_trust(bool *ready, bool *tsa_ready)
{ management_calls++; *ready = *tsa_ready = false; }
esp_err_t wendy_pki_challenge(bool status, char nonce[65], bool *enrolled)
{ management_calls++; *enrolled = false; return ESP_OK; }
esp_err_t wendy_pki_reset(const char *device, const char *nonce)
{ management_calls++; return ESP_OK; }
esp_err_t wendy_pki_sync_time(const char *server, const uint8_t *reply, size_t size,
                            bool *synchronized, int64_t *seconds)
{ management_calls++; return ESP_OK; }

static WendyComResult managed(void) { management_calls++; return WendyComResult_WENDY_COM_RESULT_OK; }
static WendyComResult request_reboot(bool start, uint32_t delay) { return managed(); }
static WendyComResult app_begin(size_t size, WendyComAppType type) { return managed(); }
static WendyComResult conf_begin(size_t size, WendyComConfPushMode mode) { return managed(); }
static WendyComResult push_data(size_t offset, const uint8_t *data, size_t size) { return managed(); }
static void identity(const char **id, const char **name, const char **display) { management_calls++; }
static void info(const char **os, const char **version, const char **arch, const char **target,
                 bool *wasm, bool *native) { management_calls++; }
static enum wcom_sensor_link_result manifest(struct wcom_sensor_descriptor *sensors, size_t max, size_t *count)
{ sensor_calls++; *count = 0; return WCOM_SENSOR_LINK_OK; }
static enum wcom_sensor_link_result subscribe(int id, const uint32_t *channels, size_t count)
{ sensor_calls++; sensor_client = id; return subscription_result; }
static void disconnected(int id) { disconnected_calls++; }

struct wire {
    unsigned char input[4096], output[4096];
    size_t input_size, input_offset, output_size;
};
static ssize_t read_wire(void *ctx, void *data, size_t size)
{
    struct wire *wire = ctx;
    size_t available = wire->input_size - wire->input_offset;
    if (!available) return WCOM_STREAM_ERR_WANT_READ;
    if (size > available) size = available;
    memcpy(data, wire->input + wire->input_offset, size);
    wire->input_offset += size;
    return size;
}
static ssize_t write_wire(void *ctx, const void *data, size_t size)
{
    struct wire *wire = ctx;
    assert(size <= sizeof wire->output - wire->output_size);
    memcpy(wire->output + wire->output_size, data, size);
    wire->output_size += size;
    return size;
}
static int wire_fd(void *ctx) { return -1; }
static bool ready(void *ctx) { return true; }
static const struct wcom_stream_ops ops = {
    .read = read_wire, .write = write_wire, .wakeup_fd = wire_fd,
    .can_read = ready, .can_write = ready,
};

static enum wcom_link_permission expected_permission;
static unsigned connection_callbacks;
static void connected(struct wcom_state_change_handler *handler, int id, enum wcom_link_state state)
{
    if (state == WCOM_LINK_STATE_CONNECTED) {
        /* The transport must publish permission before any observer runs. */
        assert(wcom_link_get_permission(id) == expected_permission);
        connection_callbacks++;
    }
}

static WendyComMessage exchange(struct wire *wire, int id, uint8_t channel, const WendyComMessage *message)
{
    assert(wire->input_offset == wire->input_size);
    wire->input_offset = wire->output_size = 0;
    struct wcom_agent_msg_header header = {
        .magic = WCOM_AGENT_MSG_MAGIC, .version = WCOM_AGENT_MSG_VERSION, .channel = channel,
    };
    pb_ostream_t stream = pb_ostream_from_buffer(wire->input + sizeof header, sizeof wire->input - sizeof header);
    assert(pb_encode(&stream, WendyComMessage_fields, message));
    header.body_size = htons(stream.bytes_written);
    memcpy(wire->input, &header, sizeof header);
    wire->input_size = sizeof header + stream.bytes_written;
    _link_do_rx(_get_link(id));
    _link_do_tx(_get_link(id));
    assert(wire->input_offset == wire->input_size);
    WendyComMessage response = WendyComMessage_init_zero;
    if (wire->output_size) {
        assert(wire->output_size >= sizeof header);
        memcpy(&header, wire->output, sizeof header);
        assert(header.channel == channel && ntohs(header.body_size) == wire->output_size - sizeof header);
        pb_istream_t input = pb_istream_from_buffer(wire->output + sizeof header, wire->output_size - sizeof header);
        assert(pb_decode(&input, WendyComMessage_fields, &response));
    }
    return response;
}

static void handshake(struct wire *wire, int id)
{
    WendyComMessage message = WendyComMessage_init_zero;
    message.which_msg = WendyComMessage_handshake_tag;
    message.msg.handshake.has_version = true;
    message.msg.handshake.version.major = 2;
    assert(exchange(wire, id, 0, &message).which_msg == WendyComMessage_handshake_tag);
}

static WendyComResult command(struct wire *wire, int id, uint8_t channel, pb_size_t tag)
{
    WendyComMessage message = WendyComMessage_init_zero;
    message.which_msg = WendyComMessage_command_tag;
    message.msg.command.request_id = 55;
    message.msg.command.which_params = tag;
    WendyComMessage response = exchange(wire, id, channel, &message);
    assert(response.which_msg == WendyComMessage_response_tag);
    assert(response.msg.response.request_id == 55);
    return response.msg.response.result;
}

static void channel_state(struct wire *wire, int id, uint8_t channel, bool open)
{
    WendyComMessage message = WendyComMessage_init_zero;
    message.which_msg = WendyComMessage_service_tag;
    message.msg.service.which_cmd = open ? WendyComService_open_channel_tag : WendyComService_close_channel_tag;
    WendyComMessage response = exchange(wire, id, channel, &message);
    assert(response.which_msg == WendyComMessage_service_tag);
    assert(response.msg.service.cmd.channel_state.which_state ==
           (open ? WendyComChannelState_open_tag : WendyComChannelState_close_tag));
}

static bool encode_input(pb_ostream_t *stream, const pb_field_t *field, void *const *arg)
{ return pb_encode_tag_for_field(stream, field) && pb_encode_string(stream, (const uint8_t *)"input", 5); }
static void console_input(struct wire *wire, int id, uint8_t channel)
{
    WendyComMessage message = WendyComMessage_init_zero;
    message.which_msg = WendyComMessage_event_tag;
    message.msg.event.which_data = WendyComEvent_console_data_tag;
    message.msg.event.data.console_data.io = WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_INPUT;
    message.msg.event.data.console_data.data.funcs.encode = encode_input;
    assert(exchange(wire, id, channel, &message).which_msg == 0);
}

static void check_device_commands(struct wire *wire, int id, uint8_t channel)
{
    unsigned initial_management = management_calls, initial_sensors = sensor_calls;
    for (pb_size_t tag = WendyComCommand_ping_tag; tag <= WendyComCommand_enrollment_reset_tag; tag++) {
        bool allowed = tag == WendyComCommand_sensor_link_get_manifest_tag ||
                       tag == WendyComCommand_sensor_link_subscribe_tag ||
                       tag == WendyComCommand_sensor_link_unsubscribe_tag;
        assert(command(wire, id, channel, tag) == (allowed ? WendyComResult_WENDY_COM_RESULT_OK
                                                         : WendyComResult_WENDY_COM_RESULT_BAD_STATE));
        assert(management_calls == initial_management);
    }
    assert(sensor_calls == initial_sensors + 3);
    /* Preserve a source's busy result through dispatch and wire encoding. */
    subscription_result = WCOM_SENSOR_LINK_BUSY;
    assert(command(wire, id, channel, WendyComCommand_sensor_link_subscribe_tag) == WendyComResult_WENDY_COM_RESULT_BUSY);
    subscription_result = WCOM_SENSOR_LINK_FAIL;
    assert(command(wire, id, channel, WendyComCommand_sensor_link_subscribe_tag) == WendyComResult_WENDY_COM_RESULT_UNKNOWN_ERROR);
    subscription_result = WCOM_SENSOR_LINK_OK;
    assert(command(wire, id, channel, WendyComCommand_sensor_link_subscribe_tag) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(command(wire, id, channel, 0) == WendyComResult_WENDY_COM_RESULT_BAD_STATE);
    unsigned initial_stdin = stdin_calls;
    console_input(wire, id, channel);
    assert(stdin_calls == initial_stdin);
    /* Events must re-arm reads even when rejected. */
    assert(command(wire, id, channel, WendyComCommand_sensor_link_get_manifest_tag) == WendyComResult_WENDY_COM_RESULT_OK);
}

int main(void)
{
    static struct wcom_state_change_handler observer = {.func = connected};
    static struct wcom_state_change_handler agent = {.func = _on_link_state_changed};
    wcom_add_state_change_handler(&observer);
    wcom_add_state_change_handler(&agent);
    static const struct wcom_app_delegate application = {
        .on_reboot = request_reboot, .on_app_push_begin = app_begin, .on_app_push_data = push_data,
        .on_app_push_end = managed, .on_app_start = managed, .on_app_stop = managed,
        .on_conf_push_begin = conf_begin, .on_conf_push_data = push_data, .on_conf_push_end = managed,
        .on_get_device_identity = identity, .on_get_device_info = info,
    };
    static const struct wcom_sensor_link_delegate sensors = {
        .on_sensor_link_get_manifest = manifest, .on_sensor_link_subscribe = subscribe,
        .on_sensor_link_unsubscribe = subscribe, .on_sensor_link_disconnected = disconnected,
    };
    wcom_cmd_set_app_delegate(&application);
    wcom_cmd_set_sensor_link_delegate(&sensors);
    struct wire wire = {0};
    assert(wcom_link_get_permission(-1) == WCOM_LINK_PERMISSION_NONE);
    assert(wcom_link_get_permission(0) == WCOM_LINK_PERMISSION_NONE);
    assert(wcom_add_socket_link_with_permission(&ops, &wire, NULL, WCOM_LINK_PERMISSION_NONE) == -1);
    assert(wcom_add_socket_link_with_permission(&ops, &wire, NULL, (enum wcom_link_permission)99) == -1);
    assert(wcom_add_tls_link_with_permission(NULL, NULL, (enum wcom_link_permission)99) == -1);
    assert(connection_callbacks == 0);

    expected_permission = WCOM_LINK_PERMISSION_SENSOR_ONLY;
    int device = wcom_add_socket_link_with_permission(&ops, &wire, NULL, expected_permission);
    assert(device > 0 && connection_callbacks == 1);
    handshake(&wire, device);
    check_device_commands(&wire, device, 0);
    channel_state(&wire, device, 7, true);
    check_device_commands(&wire, device, 7);
    int old_client = sensor_client;
    assert(wcom_get_link_id(old_client) == device && wcom_get_channel(old_client) == 7);
    channel_state(&wire, device, 7, false);
    assert(wcom_get_link_id(old_client) == -1);
    channel_state(&wire, device, 7, true);
    check_device_commands(&wire, device, 7);
    assert(sensor_client != old_client);
    assert(wcom_get_link_id(old_client) == -1);
    resetting = true;
    assert(command(&wire, device, 7, WendyComCommand_sensor_link_subscribe_tag) == WendyComResult_WENDY_COM_RESULT_BAD_STATE);
    resetting = false;
    wcom_remove_link(device);
    assert(wcom_link_get_permission(device) == WCOM_LINK_PERMISSION_NONE);

    /* Reusing the transport slot must replace its old authorization snapshot. */
    expected_permission = WCOM_LINK_PERMISSION_FULL;
    int full = wcom_add_socket_link(&ops, &wire, NULL);
    assert(full != device && wcom_link_get_permission(full) == expected_permission);
    handshake(&wire, full);
    unsigned initial_management = management_calls;
    assert(command(&wire, full, 0, WendyComCommand_app_start_tag) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(management_calls == initial_management + 1);
    console_input(&wire, full, 0);
    assert(stdin_calls == 1);
    resetting = true;
    console_input(&wire, full, 0);
    assert(stdin_calls == 1);
    assert(command(&wire, full, 0, WendyComCommand_app_start_tag) == WendyComResult_WENDY_COM_RESULT_BAD_STATE);
    assert(management_calls == initial_management + 1);
    resetting = false;
    wcom_remove_link(full);
    expected_permission = WCOM_LINK_PERMISSION_SENSOR_ONLY;
    device = wcom_add_socket_link_with_permission(&ops, &wire, NULL, expected_permission);
    handshake(&wire, device);
    check_device_commands(&wire, device, 0);
    assert(stdin_calls == 1);
    wcom_remove_link(device);

    expected_permission = WCOM_LINK_PERMISSION_FULL;
    int stream = wcom_add_stream_link(&ops, &wire, NULL);
    assert(wcom_link_get_permission(stream) == WCOM_LINK_PERMISSION_FULL);
    wcom_remove_link(stream);
    int descriptors[2];
    assert(!pipe(descriptors));
    esp_tls_t tls = {.fd = descriptors[0]};
    int tls_link = wcom_add_tls_link(&tls, NULL);
    assert(wcom_link_get_permission(tls_link) == WCOM_LINK_PERMISSION_FULL);
    wcom_remove_link(tls_link);
    expected_permission = WCOM_LINK_PERMISSION_SENSOR_ONLY;
    tls_link = wcom_add_tls_link_with_permission(&tls, NULL, expected_permission);
    assert(wcom_link_get_permission(tls_link) == expected_permission);
    wcom_remove_link(tls_link);
    expected_permission = WCOM_LINK_PERMISSION_FULL;
    wendy_com_uart_t uart = {.fd = descriptors[0]};
    int local = wcom_add_uart_link(&uart, NULL);
    assert(wcom_link_is_local(local) && wcom_link_get_permission(local) == WCOM_LINK_PERMISSION_FULL);
    wcom_remove_link(local);
    close(descriptors[0]); close(descriptors[1]);
    assert(disconnected_calls > 0);
    return 0;
}
