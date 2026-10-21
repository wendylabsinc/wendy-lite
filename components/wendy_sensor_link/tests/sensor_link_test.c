#include <assert.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "cam_capture.h"
#include "cam_loop.h"
#include "mic.h"
#include "wendy_com_sensor.h"
#include "wendy_core_sensor.h"
#include "wendy_sensor_link.h"

static const struct wcom_sensor_link_delegate *delegate;
static unsigned registrations, camera_inits, mic_inits;
static unsigned camera_deinits, mic_deinits, event_creates, event_deletes, task_creates;
static esp_err_t camera_init_result = ESP_OK, mic_init_result = ESP_OK;
static esp_err_t mic_start_result = ESP_OK;
static bool fail_events, fail_task;
static EventBits_t event_bits[2];
static bool event_used[2];
static void (*sender_tasks[2])(void *);
static void *sender_args[2];
static jmp_buf sender_idle;

static const uint8_t jpeg_frame[] = {0xff, 0xd8, 0xff, 0xd9};
static unsigned captures, releases, mic_starts, mic_reads, mic_stops;
static bool camera_buffer_held, stream_open;
static int stream_client;
static uint32_t stream_channel;
static unsigned stream_begins, stream_ends, frame_pushes;
static WendyComResult begin_result = WendyComResult_WENDY_COM_RESULT_OK;
static void (*frame_done)(uint32_t channel_id);
static void (*while_frame_pending)(void);
static unsigned stop_phase;
static bool stop_by_disconnect;
static char last_warning[256];
static int64_t mock_now = 123456789;
static unsigned capture_latency_us, completion_latency_us;
static bool reject_push, complete_inline, fail_capture_once;
static size_t queued_samples, expected_audio_samples = MIC_READ_SAMPLES;

void sensor_link_test_warning(const char *tag, const char *format, ...)
{
    (void)tag;
    va_list args;
    va_start(args, format);
    vsnprintf(last_warning, sizeof(last_warning), format, args);
    va_end(args);
}

static enum wcom_sensor_link_result subscribe(int client, uint32_t channel)
{
    return delegate->on_sensor_link_subscribe(client, &channel, 1);
}

static enum wcom_sensor_link_result unsubscribe(int client, uint32_t channel)
{
    return delegate->on_sensor_link_unsubscribe(client, &channel, 1);
}

const char *esp_err_to_name(esp_err_t error) { return "injected failure"; }
int64_t esp_timer_get_time(void) { return mock_now; }

esp_err_t cam_capture_init(void) { camera_inits++; return camera_init_result; }
void cam_capture_deinit(void) { camera_deinits++; }
esp_err_t mic_init(void) { mic_inits++; return mic_init_result; }
void mic_deinit(void) { mic_deinits++; }

esp_err_t cam_capture_retrieve_jpeg_frame(const uint8_t **jpeg, size_t *size,
                                         int *width, int *height)
{
    assert(!camera_buffer_held && !frame_done && stream_open);
    mock_now += capture_latency_us;
    if (fail_capture_once) {
        fail_capture_once = false;
        return ESP_ERR_TIMEOUT;
    }
    captures++;
    camera_buffer_held = true;
    *jpeg = jpeg_frame;
    *size = sizeof(jpeg_frame);
    *width = 800;
    *height = 600;
    return ESP_OK;
}

void cam_capture_release_frame(const uint8_t *jpeg)
{
    // The transport owns the borrowed camera buffer until its done callback.
    assert(jpeg == jpeg_frame && camera_buffer_held && !frame_done);
    camera_buffer_held = false;
    releases++;
}

esp_err_t mic_start(void) { mic_starts++; return mic_start_result; }
esp_err_t mic_read(int16_t *buffer, size_t samples, size_t *bytes_read)
{
    assert(stream_open && !frame_done && samples == MIC_READ_SAMPLES);
    mic_reads++;
    for (size_t i = 0; i < samples; ++i) buffer[i] = (int16_t)i;
    *bytes_read = samples * sizeof(*buffer);
    return ESP_OK;
}

esp_err_t mic_read_queued(int16_t *buffer, size_t samples, size_t *bytes_read)
{
    // Asked straight after a full block, for the room left behind it.
    assert(stream_open && !frame_done && samples == MIC_MAX_READ_SAMPLES - MIC_READ_SAMPLES);
    size_t count = queued_samples < samples ? queued_samples : samples;
    for (size_t i = 0; i < count; ++i) buffer[i] = (int16_t)(MIC_READ_SAMPLES + i);
    queued_samples -= count;
    *bytes_read = count * sizeof(*buffer);
    return ESP_OK;
}

void mic_stop(void)
{
    assert(!frame_done);
    mic_stops++;
}

void wendy_core_register_sensor_link_source(const struct wcom_sensor_link_delegate *source)
{
    assert(sender_tasks[0] && sender_tasks[1] && !delegate);
    delegate = source;
    registrations++;
}

static bool is_event_group(EventGroupHandle_t group)
{
    return group == &event_bits[0] || group == &event_bits[1];
}

EventGroupHandle_t xEventGroupCreate(void)
{
    event_creates++;
    if (fail_events) return NULL;
    for (unsigned i = 0; i < 2; ++i) {
        if (!event_used[i]) {
            event_used[i] = true;
            event_bits[i] = 0;
            return &event_bits[i];
        }
    }
    assert(!"more event groups than senders");
    return NULL;
}

void vEventGroupDelete(EventGroupHandle_t group)
{
    assert(is_event_group(group));
    event_used[group - event_bits] = false;
    event_deletes++;
}

EventBits_t xEventGroupSetBits(EventGroupHandle_t group, EventBits_t bits)
{
    assert(is_event_group(group));
    return *group |= bits;
}

EventBits_t xEventGroupClearBits(EventGroupHandle_t group, EventBits_t bits)
{
    assert(is_event_group(group));
    EventBits_t before = *group;
    *group &= ~bits;
    return before;
}

EventBits_t xEventGroupGetBits(EventGroupHandle_t group)
{
    assert(is_event_group(group));
    return *group;
}

EventBits_t xEventGroupWaitBits(EventGroupHandle_t group, EventBits_t bits,
                               int clear, int all, TickType_t ticks)
{
    assert(is_event_group(group) && ticks == portMAX_DELAY);
    for (;;) {
        EventBits_t matched = *group & bits;
        if (all ? matched == bits : matched != 0) {
            EventBits_t before = *group;
            if (clear) *group &= ~bits;
            return before;
        }
        if (frame_done) {
            assert(while_frame_pending);
            while_frame_pending();
        } else {
            // The deterministic sender yields when it has no work to run.
            assert(!stream_open);
            longjmp(sender_idle, 1);
        }
    }
}

int xTaskCreate(void (*task)(void *), const char *name, unsigned stack,
                void *arg, unsigned priority, TaskHandle_t *handle)
{
    task_creates++;
    if (fail_task) return 0;
    unsigned channel = !strcmp(name, "mic_loop");
    sender_tasks[channel] = task;
    sender_args[channel] = arg;
    *handle = &sender_args[channel];
    return pdPASS;
}

void vTaskDelete(TaskHandle_t task) { assert(task); }

void vTaskDelay(TickType_t ticks)
{
    // Capture succeeds in these scenarios. Unexpected retry loops are failures.
    assert(!"unexpected capture retry");
}

void wcom_exec(struct wcom_operation *operation) { operation->func(operation); }

WendyComResult wcom_sensor_stream_begin(int client, uint32_t channel)
{
    assert(!stream_open && !frame_done);
    stream_begins++;
    if (begin_result != WendyComResult_WENDY_COM_RESULT_OK) return begin_result;
    stream_open = true;
    stream_client = client;
    stream_channel = channel;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wcom_sensor_stream_end(int client, uint32_t channel)
{
    assert(stream_open);
    assert(client == stream_client && channel == stream_channel);
    stream_open = false;
    stream_ends++;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

WendyComResult wendy_core_sensor_stream_try_push(int client, uint32_t channel, const void *data,
                                  size_t size, uint64_t timestamp,
                                  void (*done)(uint32_t))
{
    assert(stream_open && !frame_done && done);
    assert(client == stream_client && channel == stream_channel);
    if (reject_push) {
        assert(unsubscribe(client, channel) == WCOM_SENSOR_LINK_OK);
        return WendyComResult_WENDY_COM_RESULT_BUSY;
    }
    if (channel == 0) {
        assert(data == jpeg_frame && size == sizeof(jpeg_frame));
        assert(camera_buffer_held && timestamp == (uint64_t)esp_timer_get_time());
    } else {
        size_t samples = size / sizeof(int16_t);
        assert(channel == 1 && samples == expected_audio_samples);
        assert(((const int16_t *)data)[samples - 1] == (int16_t)(samples - 1));
        // Stamped when the oldest sample in the frame was captured.
        assert(timestamp == (uint64_t)esp_timer_get_time() - samples * 1000000ULL / 16000);
    }
    frame_pushes++;
    frame_done = done;
    if (complete_inline) {
        assert(unsubscribe(client, channel) == WCOM_SENSOR_LINK_OK);
        frame_done = NULL;
        mock_now += completion_latency_us;
        done(channel);
        struct wendy_sensor_link_stats stats;
        assert(wendy_sensor_link_get_stats(channel, &stats) == ESP_OK);
        assert(stats.frames_submitted == 0 && stats.frames_completed == 0);
    }
    return WendyComResult_WENDY_COM_RESULT_OK;
}

static void run_sender_until_idle(uint32_t channel)
{
    assert(sender_tasks[channel]);
    if (!setjmp(sender_idle)) sender_tasks[channel](sender_args[channel]);
}

static void initialize(void)
{
    assert(wendy_sensor_link_init() == ESP_OK);
    assert(delegate && registrations == 1 && task_creates == 2);
}

static void check_manifest(bool camera, bool microphone)
{
    struct wcom_sensor_descriptor sensors[2] = {0};
    size_t count = 999;
    assert(delegate->on_sensor_link_get_manifest(sensors, 2, &count) == WCOM_SENSOR_LINK_OK);
    assert(count == (size_t)camera + (size_t)microphone);
    size_t i = 0;
    if (camera) {
        const struct wcom_sensor_descriptor *sensor = &sensors[i++];
        assert(sensor->channel_id == 0 && sensor->input_id == 0);
        assert(!strcmp(sensor->name, "camera") && sensor->format_kind == WCOM_SENSOR_FORMAT_VIDEO);
        assert(sensor->format.video.codec == wendy_lite_sensorlink_VideoFormat_Codec_MJPEG);
        assert(sensor->format.video.width == 800 && sensor->format.video.height == 600);
    }
    if (microphone) {
        const struct wcom_sensor_descriptor *sensor = &sensors[i++];
        assert(sensor->channel_id == 1 && sensor->input_id == 1);
        assert(!strcmp(sensor->name, "microphone") && sensor->format_kind == WCOM_SENSOR_FORMAT_AUDIO);
        assert(sensor->format.audio.codec == wendy_lite_sensorlink_AudioFormat_Codec_PCM_S16LE);
        assert(sensor->format.audio.sample_rate == 16000 && sensor->format.audio.channels == 1);
    }

    // Capacity is an output bound, including a zero-capacity query.
    assert(delegate->on_sensor_link_get_manifest(NULL, 0, &count) == WCOM_SENSOR_LINK_OK);
    assert(count == 0);
    memset(sensors, 0x5a, sizeof(sensors));
    unsigned char untouched[sizeof(sensors[1])];
    memcpy(untouched, &sensors[1], sizeof(untouched));
    assert(delegate->on_sensor_link_get_manifest(sensors, 1, &count) == WCOM_SENSOR_LINK_OK);
    assert(count == 1 && !memcmp(&sensors[1], untouched, sizeof(untouched)));
}

static void test_manifest(bool camera, bool microphone)
{
    camera_init_result = camera ? ESP_OK : ESP_FAIL;
    mic_init_result = microphone ? ESP_OK : ESP_FAIL;
    initialize();
    check_manifest(camera, microphone);
    assert(wendy_sensor_link_init() == ESP_OK);
    assert(registrations == 1 && camera_inits == 1 && mic_inits == 1 && task_creates == 2);
    if (!camera) assert(subscribe(7, 0) == WCOM_SENSOR_LINK_FAIL);
    if (!microphone) assert(subscribe(7, 1) == WCOM_SENSOR_LINK_FAIL);
    assert(subscribe(7, camera ? 0 : 1) == WCOM_SENSOR_LINK_OK);
}

static void test_no_sensors_retry(void)
{
    camera_init_result = mic_init_result = ESP_FAIL;
    assert(wendy_sensor_link_init() == ESP_ERR_NOT_FOUND);
    assert(!registrations && !event_creates && !task_creates);
    camera_init_result = ESP_OK;
    initialize();
    check_manifest(true, false);
    assert(camera_inits == 2 && mic_inits == 2);
}

static void test_sender_init_failure_retry(bool events_fail)
{
    fail_events = events_fail;
    fail_task = !events_fail;
    assert(wendy_sensor_link_init() == ESP_ERR_NO_MEM);
    assert(!registrations && !delegate && camera_deinits == 1 && mic_deinits == 1);
    assert(cam_loop_start(7, 0) == WCOM_SENSOR_LINK_FAIL);
    assert(event_deletes == (events_fail ? 0u : 1u));
    fail_events = fail_task = false;
    assert(wendy_sensor_link_init() == ESP_OK);
    assert(registrations == 1 && camera_inits == 2 && mic_inits == 2);
    check_manifest(true, true);
    assert(subscribe(7, 0) == WCOM_SENSOR_LINK_OK);
}

static void run_senders_until_idle(void)
{
    run_sender_until_idle(0);
    run_sender_until_idle(1);
}

static void test_subscription_lifecycle(void)
{
    assert(cam_loop_start(7, 0) == WCOM_SENSOR_LINK_FAIL);
    initialize();
    const uint32_t pair[] = {0, 1}, twice[] = {0, 0}, three[] = {0, 1, 0};
    assert(delegate->on_sensor_link_subscribe(7, NULL, 0) == WCOM_SENSOR_LINK_OK);
    assert(delegate->on_sensor_link_unsubscribe(7, NULL, 0) == WCOM_SENSOR_LINK_OK);
    assert(delegate->on_sensor_link_subscribe(7, twice, 2) == WCOM_SENSOR_LINK_FAIL);
    assert(delegate->on_sensor_link_subscribe(7, three, 3) == WCOM_SENSOR_LINK_FAIL);
    assert(delegate->on_sensor_link_unsubscribe(7, three, 3) == WCOM_SENSOR_LINK_FAIL);
    assert(subscribe(7, 2) == WCOM_SENSOR_LINK_FAIL);
    assert(unsubscribe(7, 2) == WCOM_SENSOR_LINK_FAIL);

    assert(subscribe(7, 0) == WCOM_SENSOR_LINK_OK);
    assert(subscribe(7, 0) == WCOM_SENSOR_LINK_OK);
    assert(subscribe(8, 0) == WCOM_SENSOR_LINK_BUSY);
    assert(strstr(last_warning, "requested client=8 channel=0"));
    assert(strstr(last_warning, "owner client=7 channel=0 (pending, stopping=0)"));
    // A pair is all or nothing: refused for the camera, it leaves the
    // microphone free.
    assert(delegate->on_sensor_link_subscribe(8, pair, 2) == WCOM_SENSOR_LINK_BUSY);
    assert(subscribe(9, 1) == WCOM_SENSOR_LINK_OK);
    assert(unsubscribe(9, 1) == WCOM_SENSOR_LINK_OK);
    // One client can hold both channels; the one it already has stays put.
    assert(delegate->on_sensor_link_subscribe(7, pair, 2) == WCOM_SENSOR_LINK_OK);
    assert(subscribe(8, 1) == WCOM_SENSOR_LINK_BUSY);
    assert(unsubscribe(8, 0) == WCOM_SENSOR_LINK_OK);
    delegate->on_sensor_link_disconnected(8);
    assert(subscribe(8, 0) == WCOM_SENSOR_LINK_BUSY);
    assert(subscribe(8, 1) == WCOM_SENSOR_LINK_BUSY);

    // Cancel latched starts before the senders can capture anything.
    assert(delegate->on_sensor_link_unsubscribe(7, pair, 2) == WCOM_SENSOR_LINK_OK);
    run_senders_until_idle();
    assert(!stream_begins && !captures && !mic_reads);

    // Two clients, one channel each: a disconnect frees only its own.
    assert(subscribe(8, 1) == WCOM_SENSOR_LINK_OK);
    assert(subscribe(7, 0) == WCOM_SENSOR_LINK_OK);
    delegate->on_sensor_link_disconnected(7);
    assert(subscribe(9, 1) == WCOM_SENSOR_LINK_BUSY);
    assert(subscribe(9, 0) == WCOM_SENSOR_LINK_OK);
    delegate->on_sensor_link_disconnected(8);
    delegate->on_sensor_link_disconnected(9);
    run_senders_until_idle();
    assert(!stream_begins && !captures && !mic_reads);
    assert(delegate->on_sensor_link_subscribe(7, pair, 2) == WCOM_SENSOR_LINK_OK);
}

static void stop_with_frame_in_flight(void)
{
    assert(frame_done && !releases && !mic_stops);
    if (stop_phase++ == 0) {
        assert(!stream_ends);
        uint32_t other = 1 - stream_channel;
        // A different client or channel must not cancel the active producer.
        assert(unsubscribe(stream_client + 1, stream_channel) == WCOM_SENSOR_LINK_OK);
        assert(unsubscribe(stream_client, other) == WCOM_SENSOR_LINK_OK);
        delegate->on_sensor_link_disconnected(stream_client + 1);
        assert(subscribe(stream_client, stream_channel) == WCOM_SENSOR_LINK_OK);
        assert(subscribe(stream_client + 1, stream_channel) == WCOM_SENSOR_LINK_BUSY);
        assert(strstr(last_warning, "active, stopping=0"));
        // The other channel's sender stays free for any client meanwhile.
        assert(subscribe(stream_client + 1, other) == WCOM_SENSOR_LINK_OK);
        assert(unsubscribe(stream_client + 1, other) == WCOM_SENSOR_LINK_OK);
        if (stop_by_disconnect) delegate->on_sensor_link_disconnected(stream_client);
        else assert(unsubscribe(stream_client, stream_channel) == WCOM_SENSOR_LINK_OK);
        // Neither a repeat subscription nor a new client may race stream teardown.
        assert(subscribe(stream_client, stream_channel) == WCOM_SENSOR_LINK_BUSY);
        assert(strstr(last_warning, "active, stopping=1"));
        assert(subscribe(stream_client + 1, stream_channel) == WCOM_SENSOR_LINK_BUSY);
        return;
    }
    assert(stop_phase == 2);
    assert(stream_ends == 1 && !stream_open);
    void (*done)(uint32_t) = frame_done;
    frame_done = NULL;
    mock_now += completion_latency_us;
    done(stream_channel);
}

static void test_stats(bool rejected, bool inline_done, bool capture_failed)
{
    struct wendy_sensor_link_stats stats;
    assert(wendy_sensor_link_get_stats(2, &stats) == ESP_ERR_INVALID_ARG);
    assert(wendy_sensor_link_get_stats(0, NULL) == ESP_ERR_INVALID_ARG);
    assert(wendy_sensor_link_get_stats(0, &stats) == ESP_OK);
    assert(stats.frames_submitted == 0 && stats.frames_completed == 0);
    capture_latency_us = 50;
    completion_latency_us = 200;
    reject_push = rejected;
    complete_inline = inline_done;
    fail_capture_once = capture_failed;
    initialize();
    while_frame_pending = stop_with_frame_in_flight;
    assert(subscribe(7, 0) == WCOM_SENSOR_LINK_OK);
    run_sender_until_idle(0);
    assert(releases == 1 && !camera_buffer_held && stream_ends == 1);
    assert(wendy_sensor_link_get_stats(0, &stats) == ESP_OK);
    assert(stats.frames_submitted == (rejected ? 0u : 1u));
    assert(stats.frames_completed == stats.frames_submitted);
    assert(stats.bytes_submitted == (rejected ? 0u : sizeof(jpeg_frame)));
    assert(stats.queue_rejected == rejected);
    assert(stats.capture_errors == capture_failed);
    assert(stats.capture_time_us == (capture_failed ? 100u : 50u));
    assert(stats.capture_time_max_us == 50);
    assert(stats.completion_time_us == (rejected ? 0u : 200u));
    assert(stats.completion_time_max_us == stats.completion_time_us);
    assert(wendy_sensor_link_get_stats(1, &stats) == ESP_OK);
    assert(stats.frames_submitted == 0 && stats.frames_completed == 0 && stats.capture_time_us == 0);
}

static void test_frame_lifetime(bool audio)
{
    initialize();
    stop_by_disconnect = audio;
    while_frame_pending = stop_with_frame_in_flight;
    assert(subscribe(7, audio ? 1 : 0) == WCOM_SENSOR_LINK_OK);
    run_sender_until_idle(audio ? 1 : 0);
    assert(stop_phase == 2 && frame_pushes == 1 && stream_begins == 1 && stream_ends == 1);
    assert(!frame_done && !stream_open && !camera_buffer_held);
    assert(captures == (audio ? 0u : 1u) && releases == captures);
    assert(mic_starts == (audio ? 1u : 0u) && mic_stops == mic_starts && mic_reads == mic_starts);
    assert(subscribe(8, audio ? 1 : 0) == WCOM_SENSOR_LINK_OK);
}

static void test_microphone_catch_up(size_t queued)
{
    initialize();
    queued_samples = queued;
    size_t carried = MIC_READ_SAMPLES + queued;
    expected_audio_samples = carried < MIC_MAX_READ_SAMPLES ? carried : MIC_MAX_READ_SAMPLES;
    while_frame_pending = stop_with_frame_in_flight;
    assert(subscribe(7, 1) == WCOM_SENSOR_LINK_OK);
    run_sender_until_idle(1);
    assert(frame_pushes == 1 && mic_reads == 1 && stream_ends == 1);
    // What did not fit stays queued for the next frame.
    assert(queued_samples == MIC_READ_SAMPLES + queued - expected_audio_samples);
    struct wendy_sensor_link_stats stats;
    assert(wendy_sensor_link_get_stats(1, &stats) == ESP_OK);
    assert(stats.bytes_submitted == expected_audio_samples * sizeof(int16_t));
}

static void test_stream_begin_failure(void)
{
    initialize();
    begin_result = WendyComResult_WENDY_COM_RESULT_BUSY;
    assert(subscribe(7, 1) == WCOM_SENSOR_LINK_OK);
    run_sender_until_idle(1);
    assert(stream_begins == 1 && !stream_ends && !frame_pushes);
    assert(mic_starts == 1 && mic_stops == 1 && !mic_reads);
    assert(subscribe(8, 1) == WCOM_SENSOR_LINK_OK);
}

static void test_microphone_start_failure(void)
{
    initialize();
    mic_start_result = ESP_FAIL;
    assert(subscribe(7, 1) == WCOM_SENSOR_LINK_OK);
    run_sender_until_idle(1);
    assert(mic_starts == 1 && !mic_reads && !stream_begins && !frame_pushes);
    assert(subscribe(8, 1) == WCOM_SENSOR_LINK_OK);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    const char *scenario = argv[1];
    if (!strcmp(scenario, "manifest_both")) test_manifest(true, true);
    else if (!strcmp(scenario, "manifest_camera_only")) test_manifest(true, false);
    else if (!strcmp(scenario, "manifest_microphone_only")) test_manifest(false, true);
    else if (!strcmp(scenario, "no_sensors_retry")) test_no_sensors_retry();
    else if (!strcmp(scenario, "event_group_failure_retry")) test_sender_init_failure_retry(true);
    else if (!strcmp(scenario, "sender_task_failure_retry")) test_sender_init_failure_retry(false);
    else if (!strcmp(scenario, "subscription_lifecycle")) test_subscription_lifecycle();
    else if (!strcmp(scenario, "camera_frame_lifetime")) test_frame_lifetime(false);
    else if (!strcmp(scenario, "microphone_frame_lifetime")) test_frame_lifetime(true);
    else if (!strcmp(scenario, "stream_begin_failure")) test_stream_begin_failure();
    else if (!strcmp(scenario, "microphone_start_failure")) test_microphone_start_failure();
    else if (!strcmp(scenario, "microphone_catches_up")) test_microphone_catch_up(3 * MIC_READ_SAMPLES);
    else if (!strcmp(scenario, "microphone_catch_up_bounded")) test_microphone_catch_up(MIC_MAX_READ_SAMPLES);
    else if (!strcmp(scenario, "stats_completion")) test_stats(false, false, false);
    else if (!strcmp(scenario, "stats_rejection")) test_stats(true, false, false);
    else if (!strcmp(scenario, "stats_inline_completion")) test_stats(false, true, false);
    else if (!strcmp(scenario, "stats_capture_failure")) test_stats(false, false, true);
    else assert(!"unknown scenario");
    puts(scenario);
    return 0;
}
