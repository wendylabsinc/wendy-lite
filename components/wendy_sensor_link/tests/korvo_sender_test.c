#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "cam_capture.h"
#include "mic.h"
#include "wendy_com_sensor.h"
#include "wendy_core_sensor.h"
#include "wendy_sensor_link.h"

struct test_event_group {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    EventBits_t bits;
};
struct test_task {
    pthread_t thread;
    void (*function)(void *);
    void *arg;
};
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t state_changed = PTHREAD_COND_INITIALIZER;
static const struct wcom_sensor_link_delegate *delegate;
static unsigned events_created, events_deleted, tasks_created, tasks_deleted;
static unsigned fail_task_number, camera_deinits, mic_deinits;
static const uint8_t jpeg[] = {0xff, 0xd8, 0xff, 0xd9};
static bool camera_held;
static struct {
    int client;
    bool open;
    unsigned starts, stops, frames;
    void (*done)(uint32_t);
} streams[2];

void sensor_link_test_warning(const char *tag, const char *format, ...) {}
const char *esp_err_to_name(esp_err_t error) { return "injected failure"; }
int64_t esp_timer_get_time(void) { return 123456789; }

EventGroupHandle_t xEventGroupCreate(void)
{
    struct test_event_group *group = calloc(1, sizeof(*group));
    assert(group);
    pthread_mutex_init(&group->lock, NULL);
    pthread_cond_init(&group->changed, NULL);
    ++events_created;
    return group;
}
void vEventGroupDelete(EventGroupHandle_t group)
{
    pthread_mutex_destroy(&group->lock);
    pthread_cond_destroy(&group->changed);
    free(group);
    ++events_deleted;
}
EventBits_t xEventGroupSetBits(EventGroupHandle_t group, EventBits_t bits)
{
    pthread_mutex_lock(&group->lock);
    EventBits_t result = group->bits |= bits;
    pthread_cond_broadcast(&group->changed);
    pthread_mutex_unlock(&group->lock);
    return result;
}
EventBits_t xEventGroupClearBits(EventGroupHandle_t group, EventBits_t bits)
{
    pthread_mutex_lock(&group->lock);
    EventBits_t result = group->bits;
    group->bits &= ~bits;
    pthread_mutex_unlock(&group->lock);
    return result;
}
EventBits_t xEventGroupGetBits(EventGroupHandle_t group)
{
    pthread_mutex_lock(&group->lock);
    EventBits_t result = group->bits;
    pthread_mutex_unlock(&group->lock);
    return result;
}
static void unlock_mutex(void *mutex) { pthread_mutex_unlock(mutex); }
EventBits_t xEventGroupWaitBits(EventGroupHandle_t group, EventBits_t bits,
                               int clear, int all, TickType_t ticks)
{
    EventBits_t result;
    pthread_mutex_lock(&group->lock);
    pthread_cleanup_push(unlock_mutex, &group->lock);
    while (all ? (group->bits & bits) != bits : !(group->bits & bits)) {
        pthread_cond_wait(&group->changed, &group->lock);
    }
    result = group->bits;
    if (clear) group->bits &= ~bits;
    pthread_cleanup_pop(1);
    return result;
}
static void *run_task(void *arg)
{
    struct test_task *task = arg;
    task->function(task->arg);
    return NULL;
}
int xTaskCreate(void (*function)(void *), const char *name, unsigned stack,
                void *arg, unsigned priority, TaskHandle_t *handle)
{
    if (++tasks_created == fail_task_number) return 0;
    struct test_task *task = calloc(1, sizeof(*task));
    assert(task);
    task->function = function;
    task->arg = arg;
    assert(!pthread_create(&task->thread, NULL, run_task, task));
    *handle = task;
    return pdPASS;
}
void vTaskDelete(TaskHandle_t handle)
{
    struct test_task *task = handle;
    pthread_cancel(task->thread);
    pthread_join(task->thread, NULL);
    free(task);
    ++tasks_deleted;
}
void vTaskDelay(TickType_t ticks) { usleep(ticks * 1000); }

esp_err_t cam_capture_init(void) { return ESP_OK; }
void cam_capture_deinit(void) { ++camera_deinits; }
esp_err_t mic_init(void) { return ESP_OK; }
void mic_deinit(void) { ++mic_deinits; }
static esp_err_t capture_start(unsigned channel)
{
    pthread_mutex_lock(&state_lock);
    ++streams[channel].starts;
    pthread_mutex_unlock(&state_lock);
    return ESP_OK;
}
esp_err_t cam_capture_start(void) { return capture_start(0); }
esp_err_t mic_start(void) { return capture_start(1); }
static void capture_stop(unsigned channel)
{
    pthread_mutex_lock(&state_lock);
    assert(!streams[channel].done);
    ++streams[channel].stops;
    pthread_cond_broadcast(&state_changed);
    pthread_mutex_unlock(&state_lock);
}
void cam_capture_stop(void) { capture_stop(0); }
void mic_stop(void) { capture_stop(1); }
esp_err_t cam_capture_retrieve_jpeg_frame(const uint8_t **frame, size_t *len, int *width, int *height)
{
    pthread_mutex_lock(&state_lock);
    assert(!camera_held && !streams[0].done);
    camera_held = true;
    pthread_mutex_unlock(&state_lock);
    *frame = jpeg;
    *len = sizeof(jpeg);
    *width = CAM_FRAME_WIDTH;
    *height = CAM_FRAME_HEIGHT;
    return ESP_OK;
}
void cam_capture_release_frame(const uint8_t *frame)
{
    pthread_mutex_lock(&state_lock);
    assert(frame == jpeg && camera_held && !streams[0].done);
    camera_held = false;
    pthread_mutex_unlock(&state_lock);
}
esp_err_t mic_read(int16_t *pcm, size_t samples, size_t *bytes_read)
{
    assert(samples == 640);
    pthread_mutex_lock(&state_lock);
    assert(!streams[1].done);
    pthread_mutex_unlock(&state_lock);
    for (size_t i = 0; i < samples; ++i) pcm[i] = i;
    *bytes_read = samples * sizeof(*pcm);
    return ESP_OK;
}
void wendy_core_register_sensor_link_source(const struct wcom_sensor_link_delegate *source)
{
    assert(!delegate);
    delegate = source;
}
void wcom_exec(struct wcom_operation *operation) { operation->func(operation); }
WendyComResult wcom_sensor_stream_begin(int client, uint32_t channel)
{
    pthread_mutex_lock(&state_lock);
    assert(channel < 2 && !streams[channel].open);
    streams[channel].open = true;
    streams[channel].client = client;
    pthread_mutex_unlock(&state_lock);
    return WendyComResult_WENDY_COM_RESULT_OK;
}
WendyComResult wcom_sensor_stream_end(int client, uint32_t channel)
{
    pthread_mutex_lock(&state_lock);
    assert(streams[channel].open && streams[channel].client == client);
    streams[channel].open = false;
    pthread_cond_broadcast(&state_changed);
    pthread_mutex_unlock(&state_lock);
    return WendyComResult_WENDY_COM_RESULT_OK;
}
WendyComResult wendy_core_sensor_stream_try_push(int client, uint32_t channel, const void *data,
                                  size_t size, uint64_t timestamp, void (*done)(uint32_t))
{
    pthread_mutex_lock(&state_lock);
    assert(streams[channel].open && !streams[channel].done && streams[channel].client == client);
    if (!channel) assert(data == jpeg && size == sizeof(jpeg) && camera_held);
    else assert(size == 1280 && timestamp == (uint64_t)esp_timer_get_time() - 20000);
    streams[channel].done = done;
    ++streams[channel].frames;
    pthread_cond_broadcast(&state_changed);
    pthread_mutex_unlock(&state_lock);
    return WendyComResult_WENDY_COM_RESULT_OK;
}

static void wait_state(unsigned channel, bool pending)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    pthread_mutex_lock(&state_lock);
    while (pending ? !streams[channel].done : (streams[channel].open || streams[channel].starts != streams[channel].stops)) {
        assert(!pthread_cond_timedwait(&state_changed, &state_lock, &deadline));
    }
    pthread_mutex_unlock(&state_lock);
}
static void wait_cancel(unsigned channel)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    pthread_mutex_lock(&state_lock);
    while (streams[channel].open) {
        assert(!pthread_cond_timedwait(&state_changed, &state_lock, &deadline));
    }
    assert(streams[channel].done && streams[channel].starts != streams[channel].stops);
    pthread_mutex_unlock(&state_lock);
}
static void complete(unsigned channel)
{
    pthread_mutex_lock(&state_lock);
    void (*done)(uint32_t) = streams[channel].done;
    assert(done);
    streams[channel].done = NULL;
    pthread_mutex_unlock(&state_lock);
    done(channel);
}
static enum wcom_sensor_link_result subscribe(int client, uint32_t channel)
{
    return delegate->on_sensor_link_subscribe(client, &channel, 1);
}
static void concurrent(void)
{
    assert(wendy_sensor_link_init() == ESP_OK);
    struct wcom_sensor_descriptor sensors[2];
    size_t count;
    assert(delegate->on_sensor_link_get_manifest(sensors, 2, &count) == WCOM_SENSOR_LINK_OK && count == 2);
    assert(sensors[0].format.video.width == 640 && sensors[0].format.video.height == 480);
    assert(sensors[1].input_id == 1 && sensors[1].format.audio.channels == 2);
    uint32_t pair[] = {0, 1};
    assert(delegate->on_sensor_link_subscribe(7, pair, 2) == WCOM_SENSOR_LINK_OK);
    wait_state(0, true);
    wait_state(1, true);
    assert(subscribe(8, 0) == WCOM_SENSOR_LINK_BUSY);
    assert(subscribe(7, 1) == WCOM_SENSOR_LINK_OK);
    uint32_t camera = 0;
    assert(delegate->on_sensor_link_unsubscribe(7, &camera, 1) == WCOM_SENSOR_LINK_OK);
    wait_cancel(0);
    complete(0);
    wait_state(0, false);
    // Stream-end executes before the producer drops its active reservation.
    for (unsigned i = 0; i < 1000 && subscribe(9, 0) == WCOM_SENSOR_LINK_BUSY; ++i) usleep(1000);
    wait_state(0, true);
    pthread_mutex_lock(&state_lock);
    assert(streams[0].client == 9 && streams[1].client == 7 && streams[1].done);
    pthread_mutex_unlock(&state_lock);
    delegate->on_sensor_link_disconnected(7);
    wait_cancel(1);
    complete(1);
    wait_state(1, false);
    pthread_mutex_lock(&state_lock);
    assert(streams[0].open && streams[0].done);
    pthread_mutex_unlock(&state_lock);
    delegate->on_sensor_link_disconnected(9);
    wait_cancel(0);
    complete(0);
    wait_state(0, false);
    struct wendy_sensor_link_stats stats;
    assert(wendy_sensor_link_get_stats(0, &stats) == ESP_OK);
    assert(stats.frames_submitted == 2 && stats.frames_completed == 2 && stats.bytes_submitted == 2 * sizeof(jpeg));
    assert(wendy_sensor_link_get_stats(1, &stats) == ESP_OK);
    assert(stats.frames_submitted == 1 && stats.frames_completed == 1 && stats.bytes_submitted == 1280);
}
static void second_task_failure(void)
{
    fail_task_number = 2;
    assert(wendy_sensor_link_init() == ESP_ERR_NO_MEM);
    assert(!delegate && tasks_deleted == 1 && events_deleted == 2);
    assert(camera_deinits == 1 && mic_deinits == 1);
    fail_task_number = 0;
    assert(wendy_sensor_link_init() == ESP_OK);
    assert(delegate && tasks_created == 4 && events_created == 4);
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    if (!strcmp(argv[1], "concurrent")) concurrent();
    else if (!strcmp(argv[1], "second_task_failure")) second_task_failure();
    else assert(!"unknown scenario");
    puts(argv[1]);
    return 0;
}
