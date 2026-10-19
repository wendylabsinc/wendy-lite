#include "cam_capture.h"

#include <stdbool.h>
#include <stdlib.h>

#include "driver/jpeg_encode.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mosaico_module_camera.h"

static const char *TAG = "mosaico_sensor_camera";
static mosaico_camera_handle_t s_camera;
static jpeg_encoder_handle_t s_encoder;
// One JPEG may be borrowed by the transport while capture replaces the other.
// Never queue old frames behind a slow subscriber.
static uint8_t *s_jpeg[2];
static size_t s_capacity[2];
static size_t s_size[2];
static SemaphoreHandle_t s_mutex;
static EventGroupHandle_t s_events;
static TaskHandle_t s_task;
static bool s_running;
static int s_held = -1;
static int s_ready = -1;
static esp_err_t s_capture_error = ESP_ERR_TIMEOUT;

#define START_BIT (1 << 0)
#define IDLE_BIT (1 << 1)
#define READY_BIT (1 << 2)

static void capture_task(void *arg);

void cam_capture_stop(void)
{
    if (s_task) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        bool running = s_running;
        s_running = false;
        xSemaphoreGive(s_mutex);
        if (!running) {
            return;
        }
        // The worker's bounded dequeue/encode finishes before the driver stops.
        xEventGroupWaitBits(s_events, IDLE_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
        esp_err_t err = mosaico_camera_stop_stream(s_camera);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "camera stop failed: %s", esp_err_to_name(err));
        }
    }
}

void cam_capture_deinit(void)
{
    cam_capture_stop();
    if (s_task) {
        vTaskDelete(s_task);
        s_task = NULL;
    }
    if (s_camera) {
        mosaico_camera_del(s_camera);
        s_camera = NULL;
    }
    if (s_encoder) {
        jpeg_del_encoder_engine(s_encoder);
        s_encoder = NULL;
    }
    for (unsigned i = 0; i < 2; ++i) {
        free(s_jpeg[i]);
        s_jpeg[i] = NULL;
    }
    s_held = s_ready = -1;
    if (s_events) {
        vEventGroupDelete(s_events);
        s_events = NULL;
    }
    if (s_mutex) {
        vSemaphoreDelete(s_mutex);
        s_mutex = NULL;
    }
}

esp_err_t cam_capture_init(void)
{
    if (s_camera) {
        return ESP_OK;
    }
    s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) {
        return ESP_ERR_NO_MEM;
    }
    mosaico_camera_config_t config = MOSAICO_CAMERA_DEFAULT_CONFIG();
    config.width = CAM_FRAME_WIDTH;
    config.height = CAM_FRAME_HEIGHT;
    config.frame_timeout_ms = 200;
    esp_err_t err = mosaico_camera_new(&config, &s_camera);
    if (err != ESP_OK) {
        goto fail;
    }
    err = mosaico_camera_open(s_camera);
    if (err != ESP_OK) {
        goto fail;
    }
    const jpeg_encode_engine_cfg_t engine = {.timeout_ms = 200};
    err = jpeg_new_encoder_engine(&engine, &s_encoder);
    if (err != ESP_OK) {
        goto fail;
    }
    const jpeg_encode_memory_alloc_cfg_t memory = {.buffer_direction = JPEG_ENC_ALLOC_OUTPUT_BUFFER};
    for (unsigned i = 0; i < 2; ++i) {
        s_jpeg[i] = jpeg_alloc_encoder_mem(CAM_FRAME_WIDTH * CAM_FRAME_HEIGHT * 2,
                                         &memory, &s_capacity[i]);
        if (!s_jpeg[i]) {
            err = ESP_ERR_NO_MEM;
            goto fail;
        }
    }
    s_events = xEventGroupCreate();
    if (!s_events) {
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    xEventGroupSetBits(s_events, IDLE_BIT);
    if (xTaskCreate(capture_task, "mosaico_capture", 4096, NULL, 5, &s_task) != pdPASS) {
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    ESP_LOGI(TAG, "camera ready: %dx%d hardware JPEG", CAM_FRAME_WIDTH, CAM_FRAME_HEIGHT);
    return ESP_OK;
fail:
    cam_capture_deinit();
    return err;
}

esp_err_t cam_capture_start(void)
{
    if (!s_task) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (s_running || s_held >= 0) {
        xSemaphoreGive(s_mutex);
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = mosaico_camera_start_stream(s_camera);
    if (err == ESP_OK) {
        s_ready = -1;
        s_capture_error = ESP_ERR_TIMEOUT;
        s_running = true;
        xEventGroupClearBits(s_events, IDLE_BIT | READY_BIT);
        xEventGroupSetBits(s_events, START_BIT);
    }
    xSemaphoreGive(s_mutex);
    return err;
}

static esp_err_t encode_frame(const mosaico_camera_frame_t *frame, unsigned index, uint32_t *written)
{
    // Reject partial DVP frames and padded layouts before the encoder reads
    // them. The worker returns the buffer even when encoding fails.
    if (frame->width != CAM_FRAME_WIDTH || frame->height != CAM_FRAME_HEIGHT ||
        frame->pixel_format != V4L2_PIX_FMT_UYVY ||
        (frame->bytes_per_line && frame->bytes_per_line != CAM_FRAME_WIDTH * 2) ||
        frame->size != CAM_FRAME_WIDTH * CAM_FRAME_HEIGHT * 2) {
        return ESP_ERR_INVALID_SIZE;
    }
    const jpeg_encode_cfg_t encode = {
        .width = CAM_FRAME_WIDTH,
        .height = CAM_FRAME_HEIGHT,
        .src_type = JPEG_ENCODE_IN_FORMAT_YUV422,
        .sub_sample = JPEG_DOWN_SAMPLING_YUV422,
        .image_quality = 75,
    };
    return jpeg_encoder_process(s_encoder, &encode, frame->data, frame->size,
                                s_jpeg[index], s_capacity[index], written);
}

static void capture_task(void *arg)
{
    (void)arg;
    for (;;) {
        xEventGroupWaitBits(s_events, START_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
        for (;;) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            bool running = s_running;
            xSemaphoreGive(s_mutex);
            if (!running) {
                break;
            }

            mosaico_camera_frame_t frame;
            esp_err_t err = mosaico_camera_get_frame(s_camera, &frame);
            uint32_t written = 0;
            int index = -1;
            if (err == ESP_OK) {
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                running = s_running;
                if (running) {
                    index = s_held == 0 ? 1 : 0;
                    // Withdraw the waiting image before overwriting it. The
                    // borrowed image is immutable until release_frame().
                    s_ready = -1;
                    xEventGroupClearBits(s_events, READY_BIT);
                }
                xSemaphoreGive(s_mutex);
                if (running) {
                    err = encode_frame(&frame, index, &written);
                }
                esp_err_t returned = mosaico_camera_return_frame(s_camera, &frame);
                if (err == ESP_OK) {
                    err = returned;
                }
            }
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            if (s_running) {
                s_capture_error = err;
                if (err == ESP_OK && index >= 0) {
                    s_size[index] = written;
                    s_ready = index;
                }
                xEventGroupSetBits(s_events, READY_BIT);
            }
            xSemaphoreGive(s_mutex);
            if (err != ESP_OK) {
                // Some driver failures return immediately. Keep cancellation
                // and other tasks responsive while the sensor recovers.
                vTaskDelay(pdMS_TO_TICKS(20));
            }
        }
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        s_ready = -1;
        xSemaphoreGive(s_mutex);
        xEventGroupSetBits(s_events, IDLE_BIT);
    }
}

esp_err_t cam_capture_retrieve_jpeg_frame(const uint8_t **jpeg, size_t *jpeg_len, int *width, int *height)
{
    if (!jpeg || !jpeg_len || !width || !height) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_task) {
        return ESP_ERR_INVALID_STATE;
    }
    xEventGroupWaitBits(s_events, READY_BIT | IDLE_BIT, pdFALSE, pdFALSE, pdMS_TO_TICKS(200));
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    esp_err_t err = ESP_ERR_INVALID_STATE;
    if (s_running && s_held < 0 && s_ready >= 0) {
        s_held = s_ready;
        s_ready = -1;
        *jpeg = s_jpeg[s_held];
        *jpeg_len = s_size[s_held];
        *width = CAM_FRAME_WIDTH;
        *height = CAM_FRAME_HEIGHT;
        err = ESP_OK;
    } else if (s_running && s_held < 0) {
        err = s_capture_error == ESP_OK ? ESP_ERR_TIMEOUT : s_capture_error;
    }
    xEventGroupClearBits(s_events, READY_BIT);
    xSemaphoreGive(s_mutex);
    return err;
}

void cam_capture_release_frame(const uint8_t *jpeg)
{
    if (!s_mutex || !jpeg) {
        return;
    }
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (s_held >= 0 && jpeg == s_jpeg[s_held]) {
        s_held = -1;
    } else {
        ESP_LOGE(TAG, "release of unowned JPEG frame");
    }
    xSemaphoreGive(s_mutex);
}
