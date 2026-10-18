#include "cam_capture.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "driver/jpeg_encode.h"
#include "esp_cam_sensor_xclk.h"
#include "esp_log.h"
#include "esp_video_device.h"
#include "esp_video_init.h"
#include "esp_video_ioctl.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "korvo_board.h"

static const char *TAG = "korvo_camera";

#define CAMERA_BUFFERS 2
static int s_fd = -1;
static bool s_video_initialized;
static bool s_i2c_acquired;
static bool s_streaming;
static bool s_frame_held;
static uint32_t s_frame_index;
static uint32_t s_pixel_format;
static uint8_t *s_frames[CAMERA_BUFFERS];
static size_t s_frame_sizes[CAMERA_BUFFERS];
static bool s_queued[CAMERA_BUFFERS];
static esp_cam_sensor_xclk_handle_t s_xclk;
static jpeg_encoder_handle_t s_encoder;
static uint8_t *s_jpeg;
static size_t s_jpeg_capacity;
static SemaphoreHandle_t s_mutex;

static esp_err_t queue_frame(uint32_t index)
{
    struct v4l2_buffer buffer = {
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .memory = V4L2_MEMORY_MMAP,
        .index = index,
    };
    if (ioctl(s_fd, VIDIOC_QBUF, &buffer) != 0) {
        return ESP_FAIL;
    }
    s_queued[index] = true;
    return ESP_OK;
}

void cam_capture_stop(void)
{
    if (!s_streaming) {
        return;
    }
    const int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(s_fd, VIDIOC_STREAMOFF, &type) != 0) {
        ESP_LOGW(TAG, "camera stream stop failed");
        return;
    }
    s_streaming = false;
    for (unsigned i = 0; i < CAMERA_BUFFERS; ++i) {
        s_queued[i] = false;
    }
}

void cam_capture_deinit(void)
{
    cam_capture_stop();
    if (s_fd >= 0) {
        // esp_video owns MMAP storage and releases it when the fd closes.
        close(s_fd);
        s_fd = -1;
    }
    if (s_encoder) {
        jpeg_del_encoder_engine(s_encoder);
        s_encoder = NULL;
    }
    free(s_jpeg);
    s_jpeg = NULL;
    s_frame_held = false;
    s_streaming = false;
    for (unsigned i = 0; i < CAMERA_BUFFERS; ++i) {
        s_queued[i] = false;
    }
    if (s_video_initialized) {
        esp_video_deinit_with_flags(ESP_VIDEO_INIT_FLAGS_DVP);
        s_video_initialized = false;
    }
    if (s_xclk) {
        esp_cam_sensor_xclk_stop(s_xclk);
        esp_cam_sensor_xclk_free(s_xclk);
        s_xclk = NULL;
    }
    if (s_i2c_acquired) {
        korvo_i2c_release();
        s_i2c_acquired = false;
    }
    if (s_mutex) {
        vSemaphoreDelete(s_mutex);
        s_mutex = NULL;
    }
}

esp_err_t cam_capture_init(void)
{
    if (s_fd >= 0) {
        return ESP_OK;
    }
    esp_err_t err = ESP_ERR_NO_MEM;
    s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) {
        return err;
    }
    i2c_master_bus_handle_t bus;
    err = korvo_i2c_acquire(&bus);
    if (err != ESP_OK) {
        goto fail;
    }
    s_i2c_acquired = true;

    // The Korvo requires a stable XCLK before SCCB detection. Keep LEDC as
    // the clock owner, as in Espressif's board-manager Korvo definition.
    const esp_cam_sensor_xclk_config_t clock = {
        .ledc_cfg = {
            .timer = LEDC_TIMER_1,
            .clk_cfg = LEDC_AUTO_CLK,
            .channel = LEDC_CHANNEL_0,
            .xclk_freq_hz = 20000000,
            .xclk_pin = GPIO_NUM_55,
        },
    };
    err = esp_cam_sensor_xclk_allocate(ESP_CAM_SENSOR_XCLK_LEDC, &s_xclk);
    if (err != ESP_OK) {
        goto fail;
    }
    err = esp_cam_sensor_xclk_start(s_xclk, &clock);
    if (err != ESP_OK) {
        goto fail;
    }
    vTaskDelay(pdMS_TO_TICKS(50));

    const esp_video_init_dvp_config_t dvp = {
        .sccb_config = {
            .init_sccb = false,
            .i2c_handle = bus,
            .freq = 100000,
        },
        .reset_pin = -1,
        .pwdn_pin = -1,
        .dvp_pin = {
            .data_width = 8,
            .data_io = {46, 47, 48, 49, 50, 51, 52, 53},
            .vsync_io = 56,
            .de_io = 57,
            .pclk_io = 54,
            .xclk_io = -1,
        },
    };
    const esp_video_init_config_t video = {.dvp = &dvp};
    err = esp_video_init_with_flags(&video, ESP_VIDEO_INIT_FLAGS_DVP);
    if (err != ESP_OK) {
        goto fail;
    }
    s_video_initialized = true;
    s_fd = open(ESP_VIDEO_DVP_DEVICE_NAME, O_RDONLY);
    if (s_fd < 0) {
        err = ESP_FAIL;
        goto fail;
    }

    // OV3660 supplies JPEG directly; SC101IOT supplies UYVY for the S31
    // hardware encoder. Explicitly negotiate VGA so the manifest stays true.
    struct v4l2_format format = {
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .fmt.pix = {
            .width = CAM_FRAME_WIDTH,
            .height = CAM_FRAME_HEIGHT,
            .pixelformat = V4L2_PIX_FMT_JPEG,
        },
    };
    if (ioctl(s_fd, VIDIOC_S_FMT, &format) != 0) {
        format.fmt.pix.pixelformat = V4L2_PIX_FMT_UYVY;
        if (ioctl(s_fd, VIDIOC_S_FMT, &format) != 0) {
            err = ESP_ERR_NOT_SUPPORTED;
            goto fail;
        }
    }
    if (ioctl(s_fd, VIDIOC_G_FMT, &format) != 0 ||
        format.fmt.pix.width != CAM_FRAME_WIDTH || format.fmt.pix.height != CAM_FRAME_HEIGHT ||
        (format.fmt.pix.pixelformat != V4L2_PIX_FMT_JPEG && format.fmt.pix.pixelformat != V4L2_PIX_FMT_UYVY)) {
        err = ESP_ERR_NOT_SUPPORTED;
        goto fail;
    }
    s_pixel_format = format.fmt.pix.pixelformat;
    const struct timeval timeout = {.tv_usec = 100000};
    if (ioctl(s_fd, VIDIOC_S_DQBUF_TIMEOUT, &timeout) != 0) {
        err = ESP_FAIL;
        goto fail;
    }
    struct v4l2_requestbuffers request = {
        .count = CAMERA_BUFFERS,
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .memory = V4L2_MEMORY_MMAP,
    };
    if (ioctl(s_fd, VIDIOC_REQBUFS, &request) != 0 || request.count != CAMERA_BUFFERS) {
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    for (unsigned i = 0; i < CAMERA_BUFFERS; ++i) {
        struct v4l2_buffer buffer = {
            .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
            .memory = V4L2_MEMORY_MMAP,
            .index = i,
        };
        if (ioctl(s_fd, VIDIOC_QUERYBUF, &buffer) != 0) {
            err = ESP_FAIL;
            goto fail;
        }
        s_frames[i] = mmap(NULL, buffer.length, PROT_READ | PROT_WRITE, MAP_SHARED, s_fd, buffer.m.offset);
        s_frame_sizes[i] = buffer.length;
        if (!s_frames[i] || s_frames[i] == MAP_FAILED) {
            err = ESP_ERR_NO_MEM;
            goto fail;
        }
    }
    if (s_pixel_format == V4L2_PIX_FMT_UYVY) {
        const jpeg_encode_engine_cfg_t engine = {.timeout_ms = 200};
        err = jpeg_new_encoder_engine(&engine, &s_encoder);
        if (err != ESP_OK) {
            goto fail;
        }
        const jpeg_encode_memory_alloc_cfg_t memory = {.buffer_direction = JPEG_ENC_ALLOC_OUTPUT_BUFFER};
        s_jpeg = jpeg_alloc_encoder_mem(CAM_FRAME_WIDTH * CAM_FRAME_HEIGHT * 2,
                                       &memory, &s_jpeg_capacity);
        if (!s_jpeg) {
            err = ESP_ERR_NO_MEM;
            goto fail;
        }
    }
    ESP_LOGI(TAG, "camera ready: %dx%d, %s JPEG", CAM_FRAME_WIDTH, CAM_FRAME_HEIGHT,
             s_encoder ? "hardware" : "sensor");
    return ESP_OK;

fail:
    cam_capture_deinit();
    return err;
}

esp_err_t cam_capture_start(void)
{
    if (s_fd < 0) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_streaming) {
        return ESP_OK;
    }
    for (unsigned i = 0; i < CAMERA_BUFFERS; ++i) {
        if (!s_queued[i] && queue_frame(i) != ESP_OK) {
            return ESP_FAIL;
        }
    }
    const int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(s_fd, VIDIOC_STREAMON, &type) != 0) {
        return ESP_FAIL;
    }
    s_streaming = true;
    return ESP_OK;
}

esp_err_t cam_capture_retrieve_jpeg_frame(const uint8_t **jpeg, size_t *jpeg_len, int *width, int *height)
{
    if (!jpeg || !jpeg_len || !width || !height) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_streaming) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    esp_err_t err = ESP_ERR_INVALID_STATE;
    if (s_frame_held) {
        goto done;
    }
    struct v4l2_buffer buffer = {
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .memory = V4L2_MEMORY_MMAP,
    };
    if (ioctl(s_fd, VIDIOC_DQBUF, &buffer) != 0) {
        err = (errno == EAGAIN || errno == ETIMEDOUT) ? ESP_ERR_TIMEOUT : ESP_FAIL;
        goto done;
    }
    if (buffer.index >= CAMERA_BUFFERS) {
        err = ESP_FAIL;
        goto done;
    }
    s_queued[buffer.index] = false;
    if (!(buffer.flags & V4L2_BUF_FLAG_DONE) || !buffer.bytesused ||
        buffer.bytesused > s_frame_sizes[buffer.index]) {
        queue_frame(buffer.index);
        err = ESP_FAIL;
        goto done;
    }
    if (s_encoder) {
        const jpeg_encode_cfg_t encode = {
            .width = CAM_FRAME_WIDTH,
            .height = CAM_FRAME_HEIGHT,
            .src_type = JPEG_ENCODE_IN_FORMAT_YUV422,
            .sub_sample = JPEG_DOWN_SAMPLING_YUV422,
            .image_quality = 80,
        };
        uint32_t bytes_written = 0;
        err = jpeg_encoder_process(s_encoder, &encode, s_frames[buffer.index], buffer.bytesused,
                                   s_jpeg, s_jpeg_capacity, &bytes_written);
        esp_err_t queue_err = queue_frame(buffer.index);
        if (err != ESP_OK || queue_err != ESP_OK) {
            err = err != ESP_OK ? err : queue_err;
            goto done;
        }
        *jpeg = s_jpeg;
        *jpeg_len = bytes_written;
    } else {
        *jpeg = s_frames[buffer.index];
        *jpeg_len = buffer.bytesused;
        s_frame_index = buffer.index;
    }
    s_frame_held = true;
    *width = CAM_FRAME_WIDTH;
    *height = CAM_FRAME_HEIGHT;
    err = ESP_OK;
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
    const uint8_t *expected = s_encoder ? s_jpeg : s_frames[s_frame_index];
    if (s_frame_held && jpeg == expected) {
        if (!s_encoder && queue_frame(s_frame_index) != ESP_OK) {
            ESP_LOGW(TAG, "camera buffer could not be requeued");
        }
        s_frame_held = false;
    } else {
        ESP_LOGE(TAG, "release of unowned camera frame");
    }
    xSemaphoreGive(s_mutex);
}
