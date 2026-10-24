/* Production SensorLink framing and cross-task submissions with a transport
 * whose completion order is controlled by the test. Both borrowed payloads and
 * XIAO coalesced messages are decoded to verify bytes, ordering and lifetime. */
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wendy_com_sensor.h"
#include "wendy_com_agent.h"
#include "wendy_com_link.h"
#include "wendy_core_sensor.h"
#include "pb_decode.h"

#define OK WendyComResult_WENDY_COM_RESULT_OK
#define BUSY WendyComResult_WENDY_COM_RESULT_BUSY
#define BAD_STATE WendyComResult_WENDY_COM_RESULT_BAD_STATE
#define FRAME_SIZE (32 * 1024)

static const uint32_t channels[] = {0, 1, 99, UINT32_MAX};
static unsigned completions[4], end_completions[4], chunks[4], frame_seq[4];
static size_t received[4];
static uint8_t payload[4][FRAME_SIZE];
static bool connected[] = {false, true, true};
static int link_ids[] = {0, 10, 10};
static struct wcom_tx_chunk *wire_first, *wire_last;
static struct wcom_operation *op_first, *op_last;
static pthread_mutex_t op_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned wire_messages, control_messages;
static uint32_t order[128];
static unsigned order_count;

static size_t channel_index(uint32_t channel)
{
    for (size_t i = 0; i < 4; i++)
        if (channels[i] == channel) return i;
    assert(!"unknown channel");
    return 0;
}

int wcom_get_link_id(int client)
{
    return client > 0 && client < 3 && connected[client] ? link_ids[client] : -1;
}
int wcom_get_channel(int client) { return wcom_get_link_id(client) > 0 ? client : -1; }
void wcom_set_sensor_link_delegate(const struct wcom_sensor_link_delegate *delegate) {}

void wcom_exec(struct wcom_operation *op)
{
    pthread_mutex_lock(&op_lock);
    for (struct wcom_operation *it = op_first; it; it = it->next)
        assert(it != op); // Reusing an intrusive node corrupts the actual queue.
    op->next = NULL;
    if (op_last) op_last->next = op;
    else op_first = op;
    op_last = op;
    pthread_mutex_unlock(&op_lock);
}

void wcom_core_exec(struct wcom_operation *op) { wcom_exec(op); }

static void run_ops(void)
{
    while (op_first) {
        struct wcom_operation *op = op_first;
        op_first = op->next;
        if (!op_first) op_last = NULL;
        op->func(op);
    }
}

void wcom_send(int link_id, struct wcom_tx_chunk *chunk)
{
    assert(link_id == 10 || link_id == 20);
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
    assert(chunk->next == NULL); // One node per submission, before queue linkage.
#endif
    if (wire_last) wire_last->next = chunk;
    else wire_first = chunk;
    while (chunk->next) chunk = chunk->next;
    wire_last = chunk;
}

static void frame_done(uint32_t channel) { completions[channel_index(channel)]++; }
static void end_done(uint32_t channel) { end_completions[channel_index(channel)]++; }

static bool decode_payload(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    size_t i = *(size_t *)*arg;
    size_t size = stream->bytes_left;
    assert(size > 0 && received[i] + size <= FRAME_SIZE);
    uint8_t actual[FRAME_SIZE];
    assert(pb_read(stream, actual, size));
    assert(memcmp(actual, payload[i] + received[i], size) == 0);
    received[i] += size;
    return true;
}

static void pump_message(void)
{
    assert(wire_first);
    struct wcom_agent_msg_header header;
    assert(wire_first->size >= sizeof(header));
    memcpy(&header, wire_first->data, sizeof(header));
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
    assert(wire_first->size == sizeof(header) + ntohs(header.body_size));
#else
    assert(wire_first->size == sizeof(header));
#endif
    assert(header.magic == WCOM_AGENT_MSG_MAGIC && header.version == WCOM_AGENT_MSG_VERSION);
    uint8_t bytes[10 * 1024];
    size_t size = 0;
    for (unsigned n = 0; size < sizeof(header) + ntohs(header.body_size); n++) {
        struct wcom_tx_chunk *chunk = wire_first;
        assert(chunk && size + chunk->size <= sizeof(bytes));
#if !CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
        if (n == 2) {
            bool borrowed = false;
            for (size_t i = 0; i < 4; i++) {
                uintptr_t ptr = (uintptr_t)chunk->data;
                uintptr_t start = (uintptr_t)payload[i];
                borrowed |= ptr >= start && ptr + chunk->size <= start + sizeof(payload[i]);
            }
            assert(borrowed); // The payload tx node references the producer.
        }
#endif
        memcpy(bytes + size, chunk->data, chunk->size);
        size += chunk->size;
        wire_first = chunk->next;
        if (!wire_first) wire_last = NULL;
        if (chunk->done_handler) chunk->done_handler(link_ids[header.channel], chunk, true);
    }
    assert(size == sizeof(header) + ntohs(header.body_size));
    pb_istream_t outer = pb_istream_from_buffer(bytes + sizeof(header), ntohs(header.body_size));
    pb_wire_type_t wire_type;
    uint32_t tag;
    bool eof;
    assert(pb_decode_tag(&outer, &wire_type, &tag, &eof));
    assert(!eof && wire_type == PB_WT_STRING && tag == WendyComMessage_sensor_data_tag);
    pb_istream_t inner;
    assert(pb_make_string_substream(&outer, &inner));
    // Decode scalars first so the payload callback knows its channel.
    wendy_lite_sensorlink_SensorData data = wendy_lite_sensorlink_SensorData_init_zero;
    pb_istream_t scalars = inner;
    assert(pb_decode(&scalars, wendy_lite_sensorlink_SensorData_fields, &data));
    size_t i = channel_index(data.channel_id);
    assert(data.frame_seq == frame_seq[i]);
    assert(data.chunk_seq == chunks[i]++);
    assert(data.ts_us == UINT64_MAX);
    assert(data.flags & 1); // Independent frame/keyframe flag.
    data = (wendy_lite_sensorlink_SensorData)wendy_lite_sensorlink_SensorData_init_zero;
    data.payload.funcs.decode = decode_payload;
    data.payload.arg = &i;
    assert(pb_decode(&inner, wendy_lite_sensorlink_SensorData_fields, &data));
    assert(pb_close_string_substream(&outer, &inner) && outer.bytes_left == 0);
    if (data.flags & 2) assert(received[i] == FRAME_SIZE);
    order[order_count++ % 128] = data.channel_id;
    wire_messages++;
}

static void drain(void)
{
    while (wire_first || op_first) {
        run_ops();
        if (wire_first) pump_message();
    }
}
static void open_stream(size_t i, int client) { assert(wcom_sensor_stream_begin(client, channels[i]) == OK); }
static void push(size_t i, int client)
{
    assert(wcom_sensor_stream_push(client, channels[i], payload[i], FRAME_SIZE, UINT64_MAX, frame_done) == OK);
}

static void control_done(int link_id, const struct wcom_tx_chunk *chunk, bool success)
{
    assert(success);
    control_messages++;
}

static void test_parallel(void)
{
    open_stream(0, 1); open_stream(1, 1);
    push(0, 1); push(1, 1);
    static const uint8_t response = 42;
    struct wcom_tx_chunk control = {.data = &response, .size = 1, .done_handler = control_done};
    wcom_send(10, &control);
    pump_message();
    assert(op_first); // Continuation yields to RX/operations in the com loop.
    // Control traffic queued behind video is next, before audio or more video.
    assert(wire_first == &control && !completions[0] && !completions[1]);
    wire_first = control.next;
    if (!wire_first) wire_last = NULL;
    control.done_handler(10, &control, true);
    drain();
    assert(control_messages == 1 && wire_messages == 8);
    for (size_t i = 0; i < 8; i++) assert(order[i] == channels[i % 2]);
    assert(completions[0] == 1 && completions[1] == 1);
    // Sequences belong to each stream and advance independently.
    received[0] = chunks[0] = 0;
    frame_seq[0] = 1;
    push(0, 1); drain();
    assert(completions[0] == 2 && completions[1] == 1);
}

static void test_independent_links(void)
{
    link_ids[2] = 20;
    for (size_t i = 0; i < 4; i++) open_stream(i, i < 2 ? 1 : 2);
    for (size_t i = 0; i < 4; i++) push(i, i < 2 ? 1 : 2);
    drain();
    unsigned seen[2] = {0};
    for (size_t n = 0; n < order_count; n++) {
        size_t i = channel_index(order[n]);
        size_t link = i / 2;
        assert(i == 2 * link + seen[link] % 2);
        seen[link]++;
    }
    assert(seen[0] == 8 && seen[1] == 8);
    for (size_t i = 0; i < 4; i++) assert(completions[i] == 1);
}

static void test_cancel_deferred(void)
{
    open_stream(0, 1); open_stream(1, 1);
    push(0, 1); push(1, 1);
    pump_message();
    assert(!wire_first && op_first && !completions[0] && !completions[1]);
    connected[1] = false;
    wcom_sensor_client_disconnected(1);
    assert(completions[0] == 1 && completions[1] == 1);
    run_ops();
    assert(!wire_first); // A stale scheduler cannot resurrect disconnected data.
}

static void test_busy(void)
{
    assert(wcom_sensor_stream_begin(0, 0) == BAD_STATE);
    assert(wcom_sensor_stream_push(1, 0, payload[0], FRAME_SIZE, 0, frame_done) == BAD_STATE);
    for (size_t i = 0; i < 4; i++) open_stream(i, 1);
    assert(wcom_sensor_stream_begin(1, 0) == BUSY);
    assert(wcom_sensor_stream_begin(2, 10) == BUSY);
    assert(wcom_sensor_stream_push(1, 0, NULL, 1, 0, frame_done) == BAD_STATE);
    for (size_t i = 0; i < 4; i++) push(i, 1);
    assert(wcom_sensor_stream_push(1, 0, payload[0], FRAME_SIZE, 0, frame_done) == BUSY);
    assert(!completions[0]);
    drain();
    for (size_t i = 0; i < 4; i++) {
        assert(completions[i] == 1);
        assert(wcom_sensor_stream_end(1, channels[i]) == OK);
        assert(wcom_sensor_stream_end(1, channels[i]) == BAD_STATE);
    }
    assert(wcom_sensor_stream_begin(2, 10) == OK);
}

static void test_cancel(void)
{
    open_stream(0, 1); open_stream(1, 1); open_stream(2, 1);
    push(0, 1); push(1, 1); push(2, 1);
    assert(wcom_sensor_stream_end(1, 1) == OK);
    assert(completions[1] == 1 && !received[1]); // Waiting buffer released now.
    assert(wcom_sensor_stream_begin(1, 1) == OK);
    assert(wcom_sensor_stream_end(1, 0) == OK);
    assert(!completions[0]); // The transport still borrows this buffer.
    assert(wcom_sensor_stream_begin(1, 0) == BUSY);
    pump_message();
    assert(completions[0] == 1 && received[0] < FRAME_SIZE);
    assert(wcom_sensor_stream_begin(1, 0) == OK);
    drain();
    assert(completions[0] == 1 && completions[1] == 1 && completions[2] == 1);
    assert(chunks[0] == 1 && chunks[1] == 0 && received[2] == FRAME_SIZE);
}

static void test_disconnect(void)
{
    open_stream(0, 1); open_stream(1, 1); open_stream(2, 2);
    push(0, 1); push(1, 1); push(2, 2);
    connected[1] = false;
    wcom_sensor_client_disconnected(1);
    assert(!completions[0] && completions[1] == 1 && !completions[2]);
    pump_message();
    assert(completions[0] == 1);
    drain();
    assert(completions[2] == 1 && received[2] == FRAME_SIZE);
    wcom_sensor_client_disconnected(1);
    assert(completions[0] == 1 && completions[1] == 1);
    connected[1] = true;
    open_stream(0, 1); open_stream(1, 1);
}

static void test_link_failure(void)
{
    for (size_t i = 0; i < 4; i++) { open_stream(i, 1); push(i, 1); }
    // Mimic transport teardown, including its rule that callbacks cannot
    // append to the queue being destroyed.
    struct wcom_tx_chunk *chunk = wire_first;
    wire_first = wire_last = NULL;
    while (chunk) {
        struct wcom_tx_chunk *next = chunk->next;
        if (chunk->done_handler) chunk->done_handler(10, chunk, false);
        assert(!wire_first);
        chunk = next;
    }
    connected[1] = false;
    wcom_sensor_client_disconnected(1);
    for (size_t i = 0; i < 4; i++) assert(completions[i] == 1);
    connected[1] = true;
    link_ids[1] = 20;
    open_stream(0, 1); push(0, 1); drain();
    assert(completions[0] == 2);
}

static void test_core_queue(void)
{
    for (size_t i = 0; i < 4; i++) wendy_core_sensor_stream_begin(1, channels[i]);
    // Begin and push use distinct pools and preserve queue order.
    for (size_t i = 0; i < 4; i++)
        assert(wendy_core_sensor_stream_try_push(1, channels[i], payload[i], FRAME_SIZE, UINT64_MAX, frame_done) == OK);
    assert(wendy_core_sensor_stream_try_push(1, 0, payload[0], FRAME_SIZE, UINT64_MAX, frame_done) == BUSY);
    assert(!completions[0]);
    wendy_core_sensor_stream_push(1, 0, payload[0], FRAME_SIZE, UINT64_MAX, frame_done);
    assert(completions[0] == 1); // Compatibility wrapper returns refused buffer.
    run_ops(); drain();
    for (size_t i = 0; i < 4; i++) assert(completions[i] == (i == 0 ? 2 : 1));
    // Same-stream excess is rejected by the com task, with one callback each.
    received[0] = chunks[0] = 0; frame_seq[0] = 1;
    for (size_t i = 0; i < 4; i++)
        wendy_core_sensor_stream_push(1, 0, payload[0], FRAME_SIZE, UINT64_MAX, frame_done);
    run_ops();
    assert(completions[0] == 5);
    drain(); assert(completions[0] == 6);
    for (size_t i = 0; i < 4; i++) wendy_core_sensor_stream_end(1, channels[i], end_done);
    run_ops();
    for (size_t i = 0; i < 4; i++) { assert(end_completions[i] == 1); open_stream(i, 1); }
}

static void *producer(void *arg)
{
    size_t i = *(size_t *)arg;
    assert(wendy_core_sensor_stream_try_push(1, channels[i], payload[i], FRAME_SIZE, UINT64_MAX, frame_done) == OK);
    return NULL;
}

static void test_core_parallel(void)
{
    for (size_t i = 0; i < 4; i++) open_stream(i, 1);
    for (unsigned round = 0; round < 100; round++) {
        pthread_t threads[4];
        size_t indices[] = {0, 1, 2, 3};
        for (size_t i = 0; i < 4; i++) {
            received[i] = chunks[i] = 0;
            frame_seq[i] = round;
            assert(pthread_create(&threads[i], NULL, producer, &indices[i]) == 0);
        }
        for (size_t i = 0; i < 4; i++) assert(pthread_join(threads[i], NULL) == 0);
        run_ops(); drain();
        for (size_t i = 0; i < 4; i++) assert(completions[i] == round + 1);
    }
}

int main(int argc, char **argv)
{
    assert(argc == 2 && WCOM_SENSOR_MAX_STREAMS == 4);
    for (size_t i = 0; i < 4; i++)
        for (size_t j = 0; j < FRAME_SIZE; j++) payload[i][j] = (uint8_t)(i * 17 + j);
    if (!strcmp(argv[1], "parallel")) test_parallel();
    else if (!strcmp(argv[1], "independent_links")) test_independent_links();
    else if (!strcmp(argv[1], "cancel_deferred")) test_cancel_deferred();
    else if (!strcmp(argv[1], "busy")) test_busy();
    else if (!strcmp(argv[1], "cancel")) test_cancel();
    else if (!strcmp(argv[1], "disconnect")) test_disconnect();
    else if (!strcmp(argv[1], "link_failure")) test_link_failure();
    else if (!strcmp(argv[1], "core_queue")) test_core_queue();
    else if (!strcmp(argv[1], "core_parallel")) test_core_parallel();
    else assert(!"unknown scenario");
    return 0;
}
