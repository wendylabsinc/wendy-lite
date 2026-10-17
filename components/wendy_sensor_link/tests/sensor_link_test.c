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
static EventBits_t event_bits;
static void (*sender_task)(void *);
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
int64_t esp_timer_get_time(void) { return 123456789; }

esp_err_t cam_capture_init(void) { camera_inits++; return camera_init_result; }
void cam_capture_deinit(void) { camera_deinits++; }
esp_err_t mic_init(void) { mic_inits++; return mic_init_result; }
void mic_deinit(void) { mic_deinits++; }

esp_err_t cam_capture_retrieve_jpeg_frame(const uint8_t **jpeg, size_t *size,
                                         int *width, int *height)
{
    assert(!camera_buffer_held && !frame_done && stream_open);
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

void mic_stop(void)
{
    assert(!frame_done);
    mic_stops++;
}

void wendy_core_register_sensor_link_source(const struct wcom_sensor_link_delegate *source)
{
    assert(sender_task && !delegate);
    delegate = source;
    registrations++;
}

EventGroupHandle_t xEventGroupCreate(void)
{
    event_creates++;
    if (fail_events) return NULL;
    event_bits = 0;
    return &event_bits;
}

void vEventGroupDelete(EventGroupHandle_t group)
{
    assert(group == &event_bits);
    event_deletes++;
}

EventBits_t xEventGroupSetBits(EventGroupHandle_t group, EventBits_t bits)
{
    assert(group == &event_bits);
    return event_bits |= bits;
}

EventBits_t xEventGroupClearBits(EventGroupHandle_t group, EventBits_t bits)
{
    assert(group == &event_bits);
    EventBits_t before = event_bits;
    event_bits &= ~bits;
    return before;
}

EventBits_t xEventGroupGetBits(EventGroupHandle_t group)
{
    assert(group == &event_bits);
    return event_bits;
}

EventBits_t xEventGroupWaitBits(EventGroupHandle_t group, EventBits_t bits,
                               int clear, int all, TickType_t ticks)
{
    assert(group == &event_bits && ticks == portMAX_DELAY);
    for (;;) {
        EventBits_t matched = event_bits & bits;
        if (all ? matched == bits : matched != 0) {
            EventBits_t before = event_bits;
            if (clear) event_bits &= ~bits;
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
    sender_task = task;
    *handle = &event_bits;
    return pdPASS;
}

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
    assert(stream_open && !frame_done && !camera_buffer_held);
    assert(client == stream_client && channel == stream_channel);
    if (channel == 1) assert(mic_stops == mic_starts);
    stream_open = false;
    stream_ends++;
    return WendyComResult_WENDY_COM_RESULT_OK;
}

void wendy_core_sensor_stream_push(int client, uint32_t channel, const void *data,
                                  size_t size, uint64_t timestamp,
                                  void (*done)(uint32_t))
{
    assert(stream_open && !frame_done && done);
    assert(client == stream_client && channel == stream_channel);
    if (channel == 0) {
        assert(data == jpeg_frame && size == sizeof(jpeg_frame));
        assert(camera_buffer_held && timestamp == (uint64_t)esp_timer_get_time());
    } else {
        assert(channel == 1 && size == MIC_READ_SAMPLES * sizeof(int16_t));
        assert(((const int16_t *)data)[MIC_READ_SAMPLES - 1] == MIC_READ_SAMPLES - 1);
        assert(timestamp == (uint64_t)esp_timer_get_time() - 20000);
    }
    frame_pushes++;
    frame_done = done;
}

static void run_sender_until_idle(void)
{
    assert(sender_task);
    if (!setjmp(sender_idle)) sender_task(NULL);
}

static void initialize(void)
{
    assert(wendy_sensor_link_init() == ESP_OK);
    assert(delegate && registrations == 1 && task_creates == 1);
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
        assert(sensor->channel_id == 1 && sensor->input_id == 0);
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
    assert(registrations == 1 && camera_inits == 1 && mic_inits == 1 && task_creates == 1);
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

static void test_subscription_lifecycle(void)
{
    assert(cam_loop_start(7, 0) == WCOM_SENSOR_LINK_FAIL);
    initialize();
    const uint32_t pair[] = {0, 1};
    assert(delegate->on_sensor_link_subscribe(7, NULL, 0) == WCOM_SENSOR_LINK_OK);
    assert(delegate->on_sensor_link_unsubscribe(7, NULL, 0) == WCOM_SENSOR_LINK_OK);
    assert(delegate->on_sensor_link_subscribe(7, pair, 2) == WCOM_SENSOR_LINK_FAIL);
    assert(delegate->on_sensor_link_unsubscribe(7, pair, 2) == WCOM_SENSOR_LINK_FAIL);
    assert(subscribe(7, 2) == WCOM_SENSOR_LINK_FAIL);
    assert(unsubscribe(7, 2) == WCOM_SENSOR_LINK_FAIL);

    assert(subscribe(7, 0) == WCOM_SENSOR_LINK_OK);
    assert(subscribe(7, 0) == WCOM_SENSOR_LINK_OK);
    assert(subscribe(8, 0) == WCOM_SENSOR_LINK_BUSY);
    assert(strstr(last_warning, "requested client=8 channel=0"));
    assert(strstr(last_warning, "owner client=7 channel=0 (pending, stopping=0)"));
    assert(subscribe(7, 1) == WCOM_SENSOR_LINK_BUSY);
    assert(unsubscribe(8, 0) == WCOM_SENSOR_LINK_OK);
    assert(unsubscribe(7, 1) == WCOM_SENSOR_LINK_OK);
    delegate->on_sensor_link_disconnected(8);
    assert(subscribe(8, 1) == WCOM_SENSOR_LINK_BUSY);

    // Cancel a latched camera start before the sender can capture anything.
    assert(unsubscribe(7, 0) == WCOM_SENSOR_LINK_OK);
    run_sender_until_idle();
    assert(!stream_begins && !captures && !mic_reads);
    assert(subscribe(8, 1) == WCOM_SENSOR_LINK_OK);
    delegate->on_sensor_link_disconnected(7);
    assert(subscribe(7, 0) == WCOM_SENSOR_LINK_BUSY);
    delegate->on_sensor_link_disconnected(8);
    run_sender_until_idle();
    assert(!stream_begins && !captures && !mic_reads);
    assert(subscribe(7, 0) == WCOM_SENSOR_LINK_OK);
    delegate->on_sensor_link_disconnected(7);
    assert(subscribe(8, 1) == WCOM_SENSOR_LINK_OK);
}

static void stop_with_frame_in_flight(void)
{
    assert(frame_done && !stream_ends && !releases && !mic_stops);
    if (stop_phase++ == 0) {
        // A different client or channel must not cancel the active producer.
        assert(unsubscribe(stream_client + 1, stream_channel) == WCOM_SENSOR_LINK_OK);
        assert(unsubscribe(stream_client, 1 - stream_channel) == WCOM_SENSOR_LINK_OK);
        delegate->on_sensor_link_disconnected(stream_client + 1);
        assert(subscribe(stream_client, stream_channel) == WCOM_SENSOR_LINK_OK);
        assert(subscribe(stream_client + 1, 1 - stream_channel) == WCOM_SENSOR_LINK_BUSY);
        assert(strstr(last_warning, "active, stopping=0"));
        if (stop_by_disconnect) delegate->on_sensor_link_disconnected(stream_client);
        else assert(unsubscribe(stream_client, stream_channel) == WCOM_SENSOR_LINK_OK);
        // Neither a repeat subscription nor a switch may race stream teardown.
        assert(subscribe(stream_client, stream_channel) == WCOM_SENSOR_LINK_BUSY);
        assert(strstr(last_warning, "active, stopping=1"));
        assert(subscribe(stream_client + 1, 1 - stream_channel) == WCOM_SENSOR_LINK_BUSY);
        return;
    }
    assert(stop_phase == 2);
    void (*done)(uint32_t) = frame_done;
    frame_done = NULL;
    done(stream_channel);
}

static void test_frame_lifetime(bool audio)
{
    initialize();
    stop_by_disconnect = audio;
    while_frame_pending = stop_with_frame_in_flight;
    assert(subscribe(7, audio ? 1 : 0) == WCOM_SENSOR_LINK_OK);
    run_sender_until_idle();
    assert(stop_phase == 2 && frame_pushes == 1 && stream_begins == 1 && stream_ends == 1);
    assert(!frame_done && !stream_open && !camera_buffer_held);
    assert(captures == (audio ? 0u : 1u) && releases == captures);
    assert(mic_starts == (audio ? 1u : 0u) && mic_stops == mic_starts && mic_reads == mic_starts);
    assert(subscribe(8, audio ? 0 : 1) == WCOM_SENSOR_LINK_OK);
}

static void test_stream_begin_failure(void)
{
    initialize();
    begin_result = WendyComResult_WENDY_COM_RESULT_BUSY;
    assert(subscribe(7, 1) == WCOM_SENSOR_LINK_OK);
    run_sender_until_idle();
    assert(stream_begins == 1 && !stream_ends && !frame_pushes);
    assert(mic_starts == 1 && mic_stops == 1 && !mic_reads);
    assert(subscribe(8, 0) == WCOM_SENSOR_LINK_OK);
}

static void test_microphone_start_failure(void)
{
    initialize();
    mic_start_result = ESP_FAIL;
    assert(subscribe(7, 1) == WCOM_SENSOR_LINK_OK);
    run_sender_until_idle();
    assert(mic_starts == 1 && !mic_reads && !stream_begins && !frame_pushes);
    assert(subscribe(8, 0) == WCOM_SENSOR_LINK_OK);
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
    else assert(!"unknown scenario");
    puts(scenario);
    return 0;
}
