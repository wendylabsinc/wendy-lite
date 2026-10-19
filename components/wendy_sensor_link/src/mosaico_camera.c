#include "cam_capture.h"

#include <stdbool.h>
#include <stdlib.h>

#include "driver/jpeg_encode.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mosaico_module_camera.h"

static const char *TAG = "mosaico_sensor_camera";
static mosaico_camera_handle_t s_camera;
static jpeg_encoder_handle_t s_encoder;
static uint8_t *s_jpeg;
static size_t s_capacity;
static SemaphoreHandle_t s_mutex;
static bool s_frame_held;

void cam_capture_stop(void)
{
    if (s_camera) {
        esp_err_t err = mosaico_camera_stop_stream(s_camera);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "camera stop failed: %s", esp_err_to_name(err));
        }
    }
}

void cam_capture_deinit(void)
{
    if (s_camera) {
        mosaico_camera_del(s_camera);
        s_camera = NULL;
    }
    if (s_encoder) {
        jpeg_del_encoder_engine(s_encoder);
        s_encoder = NULL;
    }
    free(s_jpeg);
    s_jpeg = NULL;
    s_frame_held = false;
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
    s_jpeg = jpeg_alloc_encoder_mem(CAM_FRAME_WIDTH * CAM_FRAME_HEIGHT * 2,
                                   &memory, &s_capacity);
    if (!s_jpeg) {
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
    return s_camera ? mosaico_camera_start_stream(s_camera) : ESP_ERR_INVALID_STATE;
}

esp_err_t cam_capture_retrieve_jpeg_frame(const uint8_t **jpeg, size_t *jpeg_len, int *width, int *height)
{
    if (!jpeg || !jpeg_len || !width || !height) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_camera) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    esp_err_t err = ESP_ERR_INVALID_STATE;
    if (s_frame_held) {
        goto done;
    }
    mosaico_camera_frame_t frame;
    err = mosaico_camera_get_frame(s_camera, &frame);
    if (err != ESP_OK) {
        goto done;
    }
    // Reject partial DVP frames and padded layouts before the encoder reads
    // them. Always return the driver's buffer, including on encode failure.
    uint32_t written = 0;
    if (frame.width != CAM_FRAME_WIDTH || frame.height != CAM_FRAME_HEIGHT ||
        frame.pixel_format != V4L2_PIX_FMT_UYVY ||
        (frame.bytes_per_line && frame.bytes_per_line != CAM_FRAME_WIDTH * 2) ||
        frame.size != CAM_FRAME_WIDTH * CAM_FRAME_HEIGHT * 2) {
        err = ESP_ERR_INVALID_SIZE;
    } else {
        const jpeg_encode_cfg_t encode = {
            .width = CAM_FRAME_WIDTH,
            .height = CAM_FRAME_HEIGHT,
            .src_type = JPEG_ENCODE_IN_FORMAT_YUV422,
            .sub_sample = JPEG_DOWN_SAMPLING_YUV422,
            .image_quality = 75,
        };
        err = jpeg_encoder_process(s_encoder, &encode, frame.data, frame.size,
                                   s_jpeg, s_capacity, &written);
    }
    esp_err_t returned = mosaico_camera_return_frame(s_camera, &frame);
    if (err == ESP_OK) {
        err = returned;
    }
    if (err == ESP_OK) {
        *jpeg = s_jpeg;
        *jpeg_len = written;
        *width = CAM_FRAME_WIDTH;
        *height = CAM_FRAME_HEIGHT;
        s_frame_held = true;
    }
done:
    xSemaphoreGive(s_mutex);
    return err;
}

void cam_capture_release_frame(const uint8_t *jpeg)
{
    if (!s_mutex || !jpeg) {
        return;
    }
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (s_frame_held && jpeg == s_jpeg) {
        s_frame_held = false;
    } else {
        ESP_LOGE(TAG, "release of unowned JPEG frame");
    }
    xSemaphoreGive(s_mutex);
}
