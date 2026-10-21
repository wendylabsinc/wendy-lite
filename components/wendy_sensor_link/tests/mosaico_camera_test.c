#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cam_capture.h"
#include "driver/jpeg_encode.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mosaico_module_camera.h"

struct test_semaphore { pthread_mutex_t lock; };
struct test_event_group {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    EventBits_t bits;
};
struct test_task { pthread_t thread; void (*run)(void *); void *arg; };
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool streaming, borrowed, waiting, pending, block_encode, encoding;
static unsigned sequence, returned, completed, encoded, starts, stops;
static unsigned camera_count, encoder_count, task_count, event_count, mutex_count;
static unsigned allocations, fail_allocation;
static bool fail_task, fail_event, fail_start;
enum fault { NONE, READ_ERROR, PARTIAL, FORMAT, STRIDE, ENCODE_ERROR, RETURN_ERROR };
static enum fault fault;

static struct timespec deadline(unsigned ms)
{
    struct timespec end;
    clock_gettime(CLOCK_REALTIME, &end);
    end.tv_nsec += (ms % 1000) * 1000000L;
    end.tv_sec += ms / 1000 + end.tv_nsec / 1000000000L;
    end.tv_nsec %= 1000000000L;
    return end;
}
static void unlock(void *p) { pthread_mutex_unlock(p); }
void sensor_link_test_warning(const char *tag, const char *format, ...) {}
const char *esp_err_to_name(esp_err_t err) { return "test error"; }

SemaphoreHandle_t xSemaphoreCreateMutex(void)
{
    SemaphoreHandle_t s = calloc(1, sizeof(*s));
    assert(s);
    pthread_mutex_init(&s->lock, NULL);
    ++mutex_count;
    return s;
}
int xSemaphoreTake(SemaphoreHandle_t s, TickType_t ticks) { return !pthread_mutex_lock(&s->lock); }
int xSemaphoreGive(SemaphoreHandle_t s) { return !pthread_mutex_unlock(&s->lock); }
void vSemaphoreDelete(SemaphoreHandle_t s)
{
    pthread_mutex_destroy(&s->lock);
    free(s);
    --mutex_count;
}
EventGroupHandle_t xEventGroupCreate(void)
{
    if (fail_event) return NULL;
    EventGroupHandle_t e = calloc(1, sizeof(*e));
    assert(e);
    pthread_mutex_init(&e->lock, NULL);
    pthread_cond_init(&e->changed, NULL);
    ++event_count;
    return e;
}
void vEventGroupDelete(EventGroupHandle_t e)
{
    pthread_mutex_destroy(&e->lock);
    pthread_cond_destroy(&e->changed);
    free(e);
    --event_count;
}
EventBits_t xEventGroupSetBits(EventGroupHandle_t e, EventBits_t bits)
{
    pthread_mutex_lock(&e->lock);
    EventBits_t result = e->bits |= bits;
    pthread_cond_broadcast(&e->changed);
    pthread_mutex_unlock(&e->lock);
    return result;
}
EventBits_t xEventGroupClearBits(EventGroupHandle_t e, EventBits_t bits)
{
    pthread_mutex_lock(&e->lock);
    EventBits_t result = e->bits;
    e->bits &= ~bits;
    pthread_mutex_unlock(&e->lock);
    return result;
}
EventBits_t xEventGroupWaitBits(EventGroupHandle_t e, EventBits_t bits, int clear, int all, TickType_t ticks)
{
    EventBits_t result;
    struct timespec end = deadline(ticks == portMAX_DELAY ? 5000 : ticks);
    pthread_mutex_lock(&e->lock);
    pthread_cleanup_push(unlock, &e->lock);
    while (all ? (e->bits & bits) != bits : !(e->bits & bits)) {
        int rc = pthread_cond_timedwait(&e->changed, &e->lock, &end);
        if (rc == ETIMEDOUT) break;
        assert(!rc);
    }
    result = e->bits;
    if (clear) e->bits &= ~bits;
    pthread_cleanup_pop(1);
    return result;
}
static void *run_task(void *p)
{
    struct test_task *task = p;
    task->run(task->arg);
    return NULL;
}
int xTaskCreate(void (*run)(void *), const char *name, unsigned stack, void *arg,
                unsigned priority, TaskHandle_t *handle)
{
    if (fail_task) return 0;
    struct test_task *task = calloc(1, sizeof(*task));
    assert(task);
    task->run = run;
    task->arg = arg;
    assert(!pthread_create(&task->thread, NULL, run_task, task));
    *handle = task;
    ++task_count;
    return pdPASS;
}
void vTaskDelete(TaskHandle_t p)
{
    struct test_task *task = p;
    pthread_cancel(task->thread);
    pthread_join(task->thread, NULL);
    free(task);
    --task_count;
}
void vTaskDelay(TickType_t ticks) { usleep(ticks * 1000); }

esp_err_t mosaico_camera_new(const mosaico_camera_config_t *config, mosaico_camera_handle_t *camera)
{
    assert(config->width == 1280 && config->height == 720 && config->frame_timeout_ms == 200);
    *camera = &camera_count;
    ++camera_count;
    return ESP_OK;
}
esp_err_t mosaico_camera_open(mosaico_camera_handle_t camera) { return ESP_OK; }
esp_err_t mosaico_camera_del(mosaico_camera_handle_t camera)
{
    assert(!streaming && !borrowed);
    --camera_count;
    return ESP_OK;
}
esp_err_t mosaico_camera_start_stream(mosaico_camera_handle_t camera)
{
    if (fail_start) return ESP_FAIL;
    pthread_mutex_lock(&lock);
    assert(!streaming);
    streaming = true;
    ++starts;
    pthread_mutex_unlock(&lock);
    return ESP_OK;
}
esp_err_t mosaico_camera_stop_stream(mosaico_camera_handle_t camera)
{
    pthread_mutex_lock(&lock);
    assert(streaming && !borrowed && !encoding);
    streaming = waiting = false;
    ++stops;
    pthread_mutex_unlock(&lock);
    return ESP_OK;
}
esp_err_t mosaico_camera_get_frame(mosaico_camera_handle_t camera, mosaico_camera_frame_t *frame)
{
    struct timespec end = deadline(200);
    pthread_mutex_lock(&lock);
    assert(streaming && !borrowed);
    waiting = true;
    pthread_cond_broadcast(&changed);
    while (!pending) {
        int rc = pthread_cond_timedwait(&changed, &lock, &end);
        if (rc == ETIMEDOUT) {
            waiting = false;
            pthread_mutex_unlock(&lock);
            return ESP_ERR_TIMEOUT;
        }
        assert(!rc);
    }
    pending = waiting = false;
    completed = sequence;
    if (fault == READ_ERROR) {
        pthread_mutex_unlock(&lock);
        return ESP_FAIL;
    }
    borrowed = true;
    *frame = (mosaico_camera_frame_t){
        .data = &sequence, .size = 1280 * 720 * 2 - (fault == PARTIAL),
        .width = 1280, .height = 720, .index = sequence,
        .pixel_format = fault == FORMAT ? 99 : V4L2_PIX_FMT_UYVY,
        .bytes_per_line = 2560 + (fault == STRIDE),
    };
    pthread_mutex_unlock(&lock);
    return ESP_OK;
}
esp_err_t mosaico_camera_return_frame(mosaico_camera_handle_t camera, const mosaico_camera_frame_t *frame)
{
    pthread_mutex_lock(&lock);
    assert(borrowed && frame->index == sequence);
    borrowed = false;
    ++returned;
    esp_err_t err = fault == RETURN_ERROR ? ESP_FAIL : ESP_OK;
    pthread_mutex_unlock(&lock);
    return err;
}
esp_err_t jpeg_new_encoder_engine(const jpeg_encode_engine_cfg_t *config, jpeg_encoder_handle_t *encoder)
{
    *encoder = &encoder_count;
    ++encoder_count;
    return ESP_OK;
}
esp_err_t jpeg_del_encoder_engine(jpeg_encoder_handle_t encoder) { --encoder_count; return ESP_OK; }
void *jpeg_alloc_encoder_mem(size_t size, const jpeg_encode_memory_alloc_cfg_t *config, size_t *capacity)
{
    if (++allocations == fail_allocation) return NULL;
    *capacity = size;
    return malloc(size);
}
esp_err_t jpeg_encoder_process(jpeg_encoder_handle_t encoder, const jpeg_encode_cfg_t *config,
                               const void *data, size_t size, uint8_t *output, size_t capacity, uint32_t *written)
{
    pthread_mutex_lock(&lock);
    assert(borrowed && size == 1280 * 720 * 2 && capacity >= 64);
    assert(config->width == 1280 && config->height == 720 && config->image_quality == 75);
    encoding = true;
    pthread_cond_broadcast(&changed);
    while (block_encode) pthread_cond_wait(&changed, &lock);
    ++encoded;
    memset(output, *(const unsigned *)data, 64);
    *written = 64;
    encoding = false;
    esp_err_t err = fault == ENCODE_ERROR ? ESP_FAIL : ESP_OK;
    pthread_mutex_unlock(&lock);
    return err;
}

// Advance capture without a consumer, then wait until publication finishes.
static void feed(unsigned id, enum fault error)
{
    pthread_mutex_lock(&lock);
    while (!waiting) pthread_cond_wait(&changed, &lock);
    sequence = id;
    fault = error;
    pending = true;
    waiting = false;
    pthread_cond_broadcast(&changed);
    while (completed != id || !waiting) pthread_cond_wait(&changed, &lock);
    pthread_mutex_unlock(&lock);
}
static const uint8_t *receive(unsigned id)
{
    const uint8_t *jpeg;
    size_t size;
    int width, height;
    assert(cam_capture_retrieve_jpeg_frame(&jpeg, &size, &width, &height) == ESP_OK);
    assert(size == 64 && width == 1280 && height == 720);
    for (size_t i = 0; i < size; ++i) assert(jpeg[i] == id);
    return jpeg;
}
static void assert_clean(void)
{
    assert(!camera_count && !encoder_count && !mutex_count && !event_count && !task_count);
    assert(!streaming && !borrowed);
}
static void *stop_capture(void *unused) { cam_capture_stop(); return NULL; }

int main(int argc, char **argv)
{
    assert(argc == 2);
    if (!strcmp(argv[1], "init_failure")) {
        fail_allocation = 2;
        assert(cam_capture_init() == ESP_ERR_NO_MEM);
        assert_clean();
        fail_allocation = 0;
        fail_event = true;
        assert(cam_capture_init() == ESP_ERR_NO_MEM);
        assert_clean();
        fail_event = false;
        fail_task = true;
        assert(cam_capture_init() == ESP_ERR_NO_MEM);
        assert_clean();
        fail_task = false;
        assert(cam_capture_init() == ESP_OK);
        cam_capture_deinit();
        assert_clean();
        return 0;
    }
    assert(cam_capture_init() == ESP_OK);
    fail_start = true;
    assert(cam_capture_start() == ESP_FAIL);
    fail_start = false;
    assert(cam_capture_start() == ESP_OK);

    if (!strcmp(argv[1], "latest")) {
        feed(1, NONE);
        const uint8_t *held = receive(1);
        for (unsigned i = 2; i <= 12; ++i) {
            feed(i, NONE);
            // The sender can retain this JPEG across arbitrarily many captures.
            for (size_t n = 0; n < 64; ++n) assert(held[n] == 1);
        }
        cam_capture_release_frame(held);
        held = receive(12);
        feed(13, NONE);
        assert(held[0] == 12);
        cam_capture_release_frame(held);
        // Leave a ready image at stop. A new subscription must not receive it.
        cam_capture_stop();
        assert(cam_capture_start() == ESP_OK);
        const uint8_t *jpeg;
        size_t size;
        int width, height;
        assert(cam_capture_retrieve_jpeg_frame(&jpeg, &size, &width, &height) == ESP_ERR_TIMEOUT);
        feed(14, NONE);
        cam_capture_release_frame(receive(14));
        assert(returned == 14 && encoded == 14);
    } else if (!strcmp(argv[1], "errors")) {
        for (enum fault error = READ_ERROR; error <= RETURN_ERROR; ++error) {
            unsigned id = (unsigned)error * 2;
            feed(id, error);
            const uint8_t *jpeg;
            size_t size;
            int width, height;
            esp_err_t result = cam_capture_retrieve_jpeg_frame(&jpeg, &size, &width, &height);
            assert(result == (error >= PARTIAL && error <= STRIDE ? ESP_ERR_INVALID_SIZE : ESP_FAIL));
            feed(id + 1, NONE);
            cam_capture_release_frame(receive(id + 1));
        }
        assert(returned == 11 && encoded == 8);
    } else if (!strcmp(argv[1], "stop_encoding")) {
        pthread_mutex_lock(&lock);
        while (!waiting) pthread_cond_wait(&changed, &lock);
        sequence = 1;
        pending = block_encode = true;
        waiting = false;
        pthread_cond_broadcast(&changed);
        while (!encoding) pthread_cond_wait(&changed, &lock);
        pthread_mutex_unlock(&lock);
        pthread_t stopper;
        assert(!pthread_create(&stopper, NULL, stop_capture, NULL));
        usleep(20000);
        pthread_mutex_lock(&lock);
        assert(!stops && borrowed);
        block_encode = false;
        pthread_cond_broadcast(&changed);
        pthread_mutex_unlock(&lock);
        pthread_join(stopper, NULL);
        assert(stops == 1 && returned == 1);
    } else {
        assert(false);
    }
    cam_capture_stop();
    cam_capture_deinit();
    assert(starts == stops);
    assert_clean();
    return 0;
}
