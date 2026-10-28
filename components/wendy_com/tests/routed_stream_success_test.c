/* Normal routed plaintext protocol/allocator integration. The encryption and
 * authenticated permission belong to the provider; this fixture drives the
 * production link, framing, dispatcher and allowed command delegates only. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <sys/select.h>
#include <unistd.h>
#include "esp_vfs_eventfd.h"
static int core_eventfd(unsigned initial,int flags);
static ssize_t core_read(int fd,void *data,size_t size);
static ssize_t core_write(int fd,const void *data,size_t size);
static int core_select(int nfds,fd_set *readfds,fd_set *writefds,fd_set *exceptfds,struct timeval *timeout);
#define eventfd core_eventfd
/* This translation unit substitutes both syscall calls and the matching
 * vtable member spelling; layout and dispatch remain the production code. */
#define read core_read
#define write core_write
#define select core_select
#define _links transport_links
#define TAG transport_tag
#include "../src/wendy_com_link.c"
#undef _links
#undef TAG
#undef eventfd
#undef read
#undef write
#undef select
#include "../src/wendy_com_agent.c"
#define TAG command_tag
#include "../src/wendy_com_cmd.c"
#undef TAG

static char large_name[700];
static char large_payload[1200];
static bool long_identity, long_manifest;
static bool last_wifi_only;
static unsigned management_calls, stdin_calls, sensor_calls, disconnected_calls;
static int sensor_client;
static enum wcom_sensor_link_result subscription_result = WCOM_SENSOR_LINK_OK;
static bool resetting;
static unsigned net_receipts;
static uint32_t fence_token;
static void (*fence_done)(uint32_t);
static WendyComResult net_set(const WendyComNetConfig *config,WendyComNetStatus *status,uint32_t *token)
{assert(config->enabled);*token=123;status->restarting=true;return WendyComResult_WENDY_COM_RESULT_APPLIED_RESTARTING;}
static void net_reply(uint32_t token){assert(token==123);net_receipts++;}

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
void wendy_conf_enrollment_identity(char tenant[37], char device[65])
{ tenant[0] = device[0] = 0; }
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
static WendyComResult conf_begin(size_t size, WendyComConfPushMode mode, bool wifi_only) { last_wifi_only = wifi_only; return managed(); }
static WendyComResult push_data(size_t offset, const uint8_t *data, size_t size) { assert(offset==0&&size==strlen(large_payload)&&!memcmp(data,large_payload,size)); return managed(); }
static void identity(const char **id, const char **name, const char **display, const char **enrolled)
{ management_calls++; if(long_identity)*display=large_name; }
static void info(const char **os, const char **version, const char **arch, const char **target,
                 bool *wasm, bool *native) { management_calls++; }
static enum wcom_sensor_link_result manifest(struct wcom_sensor_descriptor *sensors, size_t max, size_t *count)
{ sensor_calls++; *count = long_manifest ? 1:0; if(*count){assert(max>0);memset(sensors,0,sizeof(*sensors));sensors[0].name=large_name;sensors[0].channel_id=7;sensors[0].input_id=1;sensors[0].format_kind=WCOM_SENSOR_FORMAT_SENSOR;sensors[0].format.sensor.schema="f32";sensors[0].format.sensor.rate_hz=10;sensors[0].format.sensor.sample_bytes=4;} return WCOM_SENSOR_LINK_OK; }
static enum wcom_sensor_link_result subscribe(int id, const uint32_t *channels, size_t count)
{ sensor_calls++; sensor_client = id; return subscription_result; }
static void disconnected(int id) { disconnected_calls++; }

struct wire {
    unsigned char input[4096], output[4096];
    size_t input_size, input_offset, output_size;
    size_t read_limit,write_limit,budget,live,peak;
    unsigned allocations,releases,refusals,read_calls,write_calls;
    int link_id;
    bool alive,removing;
};
static ssize_t read_wire(void *ctx, void *data, size_t size)
{
    struct wire *wire = ctx;
    size_t available = wire->input_size - wire->input_offset;
    if (!available) return WCOM_STREAM_ERR_WANT_READ;
    if (size > available) size = available;
    if(wire->read_limit&&size>wire->read_limit)size=wire->read_limit;
    memcpy(data, wire->input + wire->input_offset, size);
    wire->read_calls++;
    wire->input_offset += size;
    return size;
}
static ssize_t write_wire(void *ctx, const void *data, size_t size)
{
    struct wire *wire = ctx;
    if(wire->write_limit&&size>wire->write_limit)size=wire->write_limit;
    wire->write_calls++;
    assert(size <= sizeof wire->output - wire->output_size);
    memcpy(wire->output + wire->output_size, data, size);
    wire->output_size += size;
    return size;
}
static int wire_fd(void *ctx) { return wcom_core_wakeup_fd(); }
static bool wire_readable(void *ctx) {struct wire *wire=ctx;return wire->input_offset<wire->input_size;}
static bool ready(void *ctx) { return true; }
static const struct wcom_stream_ops ops = {
    .core_read = read_wire, .core_write = write_wire, .wakeup_fd = wire_fd,
    .can_read = wire_readable, .can_write = ready,
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
    if(_get_link(id))_link_do_tx(_get_link(id));
    if(!_get_link(id))return (WendyComMessage)WendyComMessage_init_zero;
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


static unsigned core_creates,core_reads,core_writes,core_selects;
static uint64_t core_counter;
static jmp_buf core_finished;
static int core_eventfd(unsigned initial,int flags){assert(initial==0);core_creates++;return 8;}
static ssize_t core_write(int fd,const void *data,size_t size){assert(fd==8&&size==8);core_writes++;core_counter+=*(const uint64_t *)data;return size;}
static ssize_t core_read(int fd,void *data,size_t size){assert(fd==8&&size==8);core_reads++;*(uint64_t *)data=core_counter;core_counter=0;wcom_core_wake();return size;}
static int core_select(int nfds,fd_set *readfds,fd_set *writefds,fd_set *exceptfds,struct timeval *timeout){
    if(++core_selects==2)longjmp(core_finished,1);
    assert(FD_ISSET(8,readfds));FD_ZERO(readfds);FD_ZERO(writefds);FD_SET(8,readfds);return 1;
}
static void prepare_hello(struct wire *wire){
    WendyComMessage message=WendyComMessage_init_zero;message.which_msg=WendyComMessage_handshake_tag;
    message.msg.handshake.has_version=true;message.msg.handshake.version.major=2;
    struct wcom_agent_msg_header header={.magic=WCOM_AGENT_MSG_MAGIC,.version=WCOM_AGENT_MSG_VERSION};
    pb_ostream_t output=pb_ostream_from_buffer(wire->input+sizeof(header),sizeof(wire->input)-sizeof(header));assert(pb_encode(&output,WendyComMessage_fields,&message));
    header.body_size=htons(output.bytes_written);memcpy(wire->input,&header,sizeof(header));wire->input_size=sizeof(header)+output.bytes_written;
}

struct owned_buffer { max_align_t alignment; struct wire *owner; size_t size; };
static void *allocate_buffer(void *context,size_t size)
{
    struct wire *wire=context;assert(wire->alive);
    if(size>wire->budget-wire->live){wire->refusals++;return NULL;}
    struct owned_buffer *owned=malloc(sizeof(*owned)+size);assert(owned);
    owned->owner=wire;owned->size=size;
    wire->allocations++;wire->live+=size;if(wire->live>wire->peak)wire->peak=wire->live;
    return owned+1;
}
static void free_buffer(void *context,void *buffer)
{
    struct wire *wire=context;struct owned_buffer *owned=(struct owned_buffer *)buffer-1;
    assert(wire->alive&&owned->owner==wire&&wire->live>=owned->size);
    if(wire->removing){struct wcom_link_buffer_allocator out;assert(!wcom_link_get_buffer_allocator(wire->link_id,&out));}
    wire->live-=owned->size;wire->releases++;free(owned);
}
static void wire_barrier(void *context,uint32_t token,void (*done)(uint32_t))
{
 struct wire *wire=context;
 assert(wire->output_size>sizeof(struct wcom_agent_msg_header));
 assert(!fence_token);fence_token=token;fence_done=done;
}
static const struct wcom_stream_ops allocated_ops={
    .core_read=read_wire,.core_write=write_wire,.wakeup_fd=wire_fd,.can_read=wire_readable,.can_write=ready,
    .allocate_buffer=allocate_buffer,.free_buffer=free_buffer,.reply_barrier=wire_barrier,
};
static void interrupted(int id,enum wcom_interruption_reason reason){wcom_remove_link(id);}
static int open_routed(struct wire *wire,enum wcom_link_permission permission,bool allocated)
{
    wire->alive=true;wire->read_limit=3;wire->write_limit=5;expected_permission=permission;
    int id=wcom_add_routed_stream_link_with_permission(allocated?&allocated_ops:&ops,wire,interrupted,permission);
    assert(id>0);wire->link_id=id;
    assert(_get_link(id)->type==LINK_TYPE_STREAM&&_get_link(id)->routed);
    assert(_tx_stall_timeout(_get_link(id))==45LL*1000*1000);
    handshake(wire,id);
    assert(wire->read_calls>1&&wire->write_calls>1);
    return id;
}
static void retire(struct wire *wire)
{
    wire->removing=true;wcom_remove_link(wire->link_id);
    assert(!wire->live&&wire->allocations==wire->releases);wire->alive=false;
}
static bool encode_payload(pb_ostream_t *stream,const pb_field_t *field,void *const *arg)
{
    const char *text=*arg;return pb_encode_tag_for_field(stream,field)&&pb_encode_string(stream,(const uint8_t *)text,strlen(text));
}
int main(void)
{
    memset(large_name,'m',sizeof(large_name)-1);
    memset(large_payload,'p',sizeof(large_payload)-1);
    static struct wcom_state_change_handler observer={.func=connected},agent={.func=_on_link_state_changed};
    wcom_add_state_change_handler(&observer);wcom_add_state_change_handler(&agent);
    static const struct wcom_app_delegate application={
        .on_reboot=request_reboot,.on_app_push_begin=app_begin,.on_app_push_data=push_data,
        .on_app_push_end=managed,.on_app_start=managed,.on_app_stop=managed,
        .on_conf_push_begin=conf_begin,.on_conf_push_data=push_data,.on_conf_push_end=managed,
        .on_get_device_identity=identity,.on_get_device_info=info,
    };
    static const struct wcom_sensor_link_delegate sensors={
        .on_sensor_link_get_manifest=manifest,.on_sensor_link_subscribe=subscribe,
        .on_sensor_link_unsubscribe=subscribe,.on_sensor_link_disconnected=disconnected,
    };
    wcom_cmd_set_app_delegate(&application);wcom_cmd_set_sensor_link_delegate(&sensors);

    struct wire full={.budget=2048},sensor={.budget=2048};
    int full_id=open_routed(&full,WCOM_LINK_PERMISSION_FULL,true);
    int sensor_id=open_routed(&sensor,WCOM_LINK_PERMISSION_SENSOR_ONLY,true);
    struct wire reserved_a={.budget=2048},reserved_b={.budget=2048};
    (void)open_routed(&reserved_a,WCOM_LINK_PERMISSION_FULL,false);
    (void)open_routed(&reserved_b,WCOM_LINK_PERMISSION_FULL,false);
    unsigned active=0;for(int i=0;i<WCOM_LINK_COUNT;i++)active+=transport_links[i].state==WCOM_LINK_STATE_CONNECTED;
    assert(active==4&&WCOM_LINK_COUNT==4);
    assert(command(&full,full_id,0,WendyComCommand_app_start_tag)==WendyComResult_WENDY_COM_RESULT_OK);
    console_input(&full,full_id,0);assert(stdin_calls==1);
    static const struct wcom_net_delegate net={.set=net_set,.reply_complete=net_reply};
    wcom_cmd_set_net_delegate(&net);
    WendyComMessage configure=WendyComMessage_init_zero;
    configure.which_msg=WendyComMessage_command_tag;
    configure.msg.command.which_params=WendyComCommand_net_set_tag;
    configure.msg.command.params.net_set.has_config=true;
    configure.msg.command.params.net_set.config.enabled=true;
    assert(exchange(&full,full_id,0,&configure).msg.response.result==WendyComResult_WENDY_COM_RESULT_APPLIED_RESTARTING);
    assert(fence_token==123&&!net_receipts); /* full reply accepted, provider still draining */
    fence_done(fence_token);fence_token=0;assert(net_receipts==1);
    /* Direct stream transports without deferred output finish at write. */
    assert(exchange(&reserved_a,reserved_a.link_id,0,&configure).msg.response.result==WendyComResult_WENDY_COM_RESULT_APPLIED_RESTARTING);
    assert(net_receipts==2&&!fence_token);

    long_identity=true;
    assert(command(&full,full_id,0,WendyComCommand_get_device_identity_tag)==WendyComResult_WENDY_COM_RESULT_OK);
    assert(full.live>256&&full.allocations==1&&sensor.live==0);
    WendyComMessage begin=WendyComMessage_init_zero;begin.which_msg=WendyComMessage_command_tag;
    begin.msg.command.which_params=WendyComCommand_app_push_begin_tag;
    begin.msg.command.params.app_push_begin.size=strlen(large_payload);
    assert(exchange(&full,full_id,0,&begin).msg.response.result==WendyComResult_WENDY_COM_RESULT_OK);
    WendyComMessage upload=WendyComMessage_init_zero;upload.which_msg=WendyComMessage_command_tag;
    upload.msg.command.which_params=WendyComCommand_app_push_data_tag;
    upload.msg.command.params.app_push_data.data.funcs.encode=encode_payload;
    upload.msg.command.params.app_push_data.data.arg=large_payload;
    assert(exchange(&full,full_id,0,&upload).msg.response.result==WendyComResult_WENDY_COM_RESULT_OK);
    assert(full.allocations==2&&full.releases==1&&full.live>1024&&full.peak==full.live);
    assert(command(&full,full_id,0,WendyComCommand_app_push_end_tag)==WendyComResult_WENDY_COM_RESULT_OK);
    long_manifest=true;
    assert(command(&sensor,sensor_id,0,WendyComCommand_sensor_link_get_manifest_tag)==WendyComResult_WENDY_COM_RESULT_OK);
    assert(sensor.live>256&&sensor.allocations==1);
    channel_state(&sensor,sensor_id,7,true);
    WendyComMessage subscription=WendyComMessage_init_zero;subscription.which_msg=WendyComMessage_command_tag;
    subscription.msg.command.which_params=WendyComCommand_sensor_link_subscribe_tag;
    subscription.msg.command.params.sensor_link_subscribe.channel_id_count=1;
    subscription.msg.command.params.sensor_link_subscribe.channel_id[0]=7;
    assert(exchange(&sensor,sensor_id,7,&subscription).msg.response.result==WendyComResult_WENDY_COM_RESULT_OK);
    subscription.msg.command.which_params=WendyComCommand_sensor_link_unsubscribe_tag;
    subscription.msg.command.params.sensor_link_unsubscribe.channel_id_count=1;
    subscription.msg.command.params.sensor_link_unsubscribe.channel_id[0]=7;
    assert(exchange(&sensor,sensor_id,7,&subscription).msg.response.result==WendyComResult_WENDY_COM_RESULT_OK);
    channel_state(&sensor,sensor_id,7,false);
    retire(&full);assert(sensor.live>256);retire(&sensor);retire(&reserved_a);retire(&reserved_b);

    /* A legacy provider uses libc, including a response larger than static_buf. */
    struct wire baseline={.budget=2048};int baseline_id=open_routed(&baseline,WCOM_LINK_PERMISSION_FULL,false);
    assert(command(&baseline,baseline_id,0,WendyComCommand_get_device_identity_tag)==WendyComResult_WENDY_COM_RESULT_OK);
    assert(!baseline.allocations&&!baseline.live);retire(&baseline);

    /* Ordinary receive-body admission failure: a valid app upload chunk cannot
     * obtain its configured protocol budget, and is never queued into NULL. */
    struct wire rx_budget={.budget=256};int rx_id=open_routed(&rx_budget,WCOM_LINK_PERMISSION_FULL,true);
    begin.msg.command.params.app_push_begin.size=strlen(large_name);
    assert(exchange(&rx_budget,rx_id,0,&begin).msg.response.result==WendyComResult_WENDY_COM_RESULT_OK);
    WendyComMessage chunk=WendyComMessage_init_zero;chunk.which_msg=WendyComMessage_command_tag;
    chunk.msg.command.which_params=WendyComCommand_app_push_data_tag;
    chunk.msg.command.params.app_push_data.data.funcs.encode=encode_payload;
    chunk.msg.command.params.app_push_data.data.arg=large_name;
    (void)exchange(&rx_budget,rx_id,0,&chunk);
    assert(!_get_link(rx_id)&&rx_budget.refusals==1&&!rx_budget.live);
    rx_budget.alive=false;

    /* Ordinary response admission failure likewise closes before pb_encode. */
    struct wire tx_budget={.budget=256};int tx_id=open_routed(&tx_budget,WCOM_LINK_PERMISSION_FULL,true);
    WendyComMessage request=WendyComMessage_init_zero;request.which_msg=WendyComMessage_command_tag;
    request.msg.command.which_params=WendyComCommand_get_device_identity_tag;
    (void)exchange(&tx_budget,tx_id,0,&request);
    assert(!_get_link(tx_id)&&tx_budget.refusals==1&&!tx_budget.live);
    tx_budget.alive=false;

    /* Two routed providers share the permanent baseline wake fd. The com loop
     * drains it once, while a new producer edge after that drain remains set. */
    _wakeup_efd=8;
    struct wire shared_a={.budget=2048,.alive=true,.read_limit=3,.write_limit=5};
    struct wire shared_b={.budget=2048,.alive=true,.read_limit=3,.write_limit=5};
    expected_permission=WCOM_LINK_PERMISSION_FULL;
    shared_a.link_id=wcom_add_routed_stream_link_with_permission(&allocated_ops,&shared_a,interrupted,expected_permission);
    expected_permission=WCOM_LINK_PERMISSION_SENSOR_ONLY;
    shared_b.link_id=wcom_add_routed_stream_link_with_permission(&allocated_ops,&shared_b,interrupted,expected_permission);
    assert(shared_a.link_id>0&&shared_b.link_id>0);
    prepare_hello(&shared_a);prepare_hello(&shared_b);
    core_counter=1;
    if(!setjmp(core_finished))_main(NULL);
    assert(core_creates==1&&core_reads==1&&core_writes==1&&core_counter==1);
    assert(shared_a.output_size>0&&shared_b.output_size>0);
    assert(shared_a.input_offset==shared_a.input_size&&shared_b.input_offset==shared_b.input_size);
    retire(&shared_a);retire(&shared_b);
    return 0;
}
