#include "cam_capture.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_camera.h"
#include "esp_log.h"

static const char *TAG = "cam_capture";

// OV2640 on the XIAO ESP32S3 Sense expansion board (DVP interface).
#define CAM_PIN_PWDN  -1
#define CAM_PIN_RESET -1
#define CAM_PIN_XCLK  10
#define CAM_PIN_SIOD  40
#define CAM_PIN_SIOC  39
#define CAM_PIN_D7    48
#define CAM_PIN_D6    11
#define CAM_PIN_D5    12
#define CAM_PIN_D4    14
#define CAM_PIN_D3    16
#define CAM_PIN_D2    18
#define CAM_PIN_D1    17
#define CAM_PIN_D0    15
#define CAM_PIN_VSYNC 38
#define CAM_PIN_HREF  47
#define CAM_PIN_PCLK  13

// How many frame buffers the driver owns, and therefore how many frames can be
// checked out at once: the driver never hands out more than it has. Callers
// must not hold this many and expect another capture to succeed. cam_loop
// returns its transmitted frame before requesting the next capture.
#define CAM_CAPTURE_MAX_INFLIGHT 2

static const camera_config_t s_config = {
    .pin_pwdn = CAM_PIN_PWDN,
    .pin_reset = CAM_PIN_RESET,
    .pin_xclk = CAM_PIN_XCLK,
    .pin_sccb_sda = CAM_PIN_SIOD,
    .pin_sccb_scl = CAM_PIN_SIOC,
    .pin_d7 = CAM_PIN_D7,
    .pin_d6 = CAM_PIN_D6,
    .pin_d5 = CAM_PIN_D5,
    .pin_d4 = CAM_PIN_D4,
    .pin_d3 = CAM_PIN_D3,
    .pin_d2 = CAM_PIN_D2,
    .pin_d1 = CAM_PIN_D1,
    .pin_d0 = CAM_PIN_D0,
    .pin_vsync = CAM_PIN_VSYNC,
    .pin_href = CAM_PIN_HREF,
    .pin_pclk = CAM_PIN_PCLK,

    .xclk_freq_hz = 20000000,
    .ledc_timer = LEDC_TIMER_0,
    .ledc_channel = LEDC_CHANNEL_0,

    .pixel_format = PIXFORMAT_JPEG,
    .frame_size = FRAMESIZE_VGA,
    .jpeg_quality = 24,
    .fb_count = CAM_CAPTURE_MAX_INFLIGHT,
    .fb_location = CAMERA_FB_IN_PSRAM,
    .grab_mode = CAMERA_GRAB_LATEST,
    .sccb_i2c_port = -1,
};

// Frames handed out and not released yet, so cam_capture_release_frame() can
// map a JPEG pointer back to the camera_fb_t it came from.
static camera_fb_t *s_inflight[CAM_CAPTURE_MAX_INFLIGHT];

static SemaphoreHandle_t s_mutex;
static bool s_initialized;

esp_err_t cam_capture_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    if (!s_mutex) {
        s_mutex = xSemaphoreCreateMutex();
        if (!s_mutex) {
            return ESP_ERR_NO_MEM;
        }
    }

    esp_err_t err = esp_camera_init(&s_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_camera_init failed: %s", esp_err_to_name(err));
        vSemaphoreDelete(s_mutex);
        s_mutex = NULL;
        return err;
    }

    // The OV2640 on this board delivers a horizontally mirrored image, which
    // QR decoding cannot tolerate (and face coordinates would be flipped).
    sensor_t *sensor = esp_camera_sensor_get();
    if (sensor && sensor->set_hmirror) {
        sensor->set_hmirror(sensor, 1);
    }

    s_initialized = true;
    ESP_LOGI(TAG, "camera ready");
    return ESP_OK;
}

void cam_capture_deinit(void)
{
    if (s_initialized) {
        esp_camera_deinit();
        s_initialized = false;
    }
    if (s_mutex) {
        vSemaphoreDelete(s_mutex);
        s_mutex = NULL;
    }
}

esp_err_t cam_capture_retrieve_jpeg_frame(const uint8_t **jpeg, size_t *jpeg_len, int *width, int *height)
{
    if (!jpeg || !jpeg_len || !width || !height) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    esp_err_t err = ESP_FAIL;

    // Claim the slot before grabbing a frame: a frame we cannot track is a
    // frame we could never hand back to the driver.
    int slot = -1;
    for (int i = 0; i < CAM_CAPTURE_MAX_INFLIGHT; i++) {
        if (!s_inflight[i]) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        ESP_LOGE(TAG, "all %d frames are still checked out", CAM_CAPTURE_MAX_INFLIGHT);
        err = ESP_ERR_NO_MEM;
        goto done;
    }

    camera_fb_t *fb = esp_camera_fb_get();
    if (!fb) {
        ESP_LOGE(TAG, "capture failed");
        goto done;
    }

    // Hand out the driver's buffer as-is. It goes back to the driver in
    // cam_capture_release_frame(), not here.
    s_inflight[slot] = fb;
    *jpeg = fb->buf;
    *jpeg_len = fb->len;
    *width = fb->width;
    *height = fb->height;
    err = ESP_OK;

done:
    xSemaphoreGive(s_mutex);
    return err;
}

void cam_capture_release_frame(const uint8_t *jpeg)
{
    if (!jpeg) {
        return;
    }

    bool found = false;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    for (int i = 0; i < CAM_CAPTURE_MAX_INFLIGHT; i++) {
        if (s_inflight[i] && s_inflight[i]->buf == jpeg) {
            esp_camera_fb_return(s_inflight[i]);
            s_inflight[i] = NULL;
            found = true;
            break;
        }
    }
    xSemaphoreGive(s_mutex);

    if (!found) {
        // Either a double release or a pointer from somewhere else. Both are
        // caller bugs, and both would starve the driver of frame buffers.
        ESP_LOGE(TAG, "release of a frame we never handed out: %p", jpeg);
    }
}
