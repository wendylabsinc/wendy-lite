#include "wendy_sensor_link.h"

#include <stdbool.h>

#include "esp_log.h"

#include "cam_capture.h"
#include "cam_loop.h"
#include "mic.h"
#include "wendy_core_sensor.h"

static const char *TAG = "wendy_sensor_link";

static bool s_camera_ready;
static bool s_microphone_ready;
static bool s_initialized;

static enum wcom_sensor_link_result sensor_link_get_manifest(
    struct wcom_sensor_descriptor *sensors, size_t max_sensors, size_t *sensor_count)
{
    *sensor_count = 0;
    if (s_camera_ready && *sensor_count < max_sensors) {
        sensors[(*sensor_count)++] = (struct wcom_sensor_descriptor){
            .channel_id = 0,
            .input_id = 0,
            .name = "camera",
            .format_kind = WCOM_SENSOR_FORMAT_VIDEO,
            .format.video = {
                .codec = wendy_lite_sensorlink_VideoFormat_Codec_MJPEG,
                .width = 800,
                .height = 600,
                .fps = 0,
            },
        };
    }
    if (s_microphone_ready && *sensor_count < max_sensors) {
        sensors[(*sensor_count)++] = (struct wcom_sensor_descriptor){
            .channel_id = 1,
            // The SDK supports one input at a time.
            .input_id = 0,
            .name = "microphone",
            .format_kind = WCOM_SENSOR_FORMAT_AUDIO,
            .format.audio = {
                .codec = wendy_lite_sensorlink_AudioFormat_Codec_PCM_S16LE,
                .sample_rate = MIC_SAMPLE_RATE_HZ,
                .channels = 1,
            },
        };
    }
    return WCOM_SENSOR_LINK_OK;
}

static enum wcom_sensor_link_result sensor_link_subscribe(
    int client_id, const uint32_t *channel_ids, size_t count)
{
    if (count == 0) {
        return WCOM_SENSOR_LINK_OK;
    }
    if (count != 1 || !((channel_ids[0] == 0 && s_camera_ready) ||
                        (channel_ids[0] == 1 && s_microphone_ready))) {
        return WCOM_SENSOR_LINK_FAIL;
    }
    return cam_loop_start(client_id, channel_ids[0]);
}

static enum wcom_sensor_link_result sensor_link_unsubscribe(
    int client_id, const uint32_t *channel_ids, size_t count)
{
    if (count == 0) {
        return WCOM_SENSOR_LINK_OK;
    }
    if (count != 1 || channel_ids[0] > 1) {
        return WCOM_SENSOR_LINK_FAIL;
    }
    cam_loop_stop(client_id, channel_ids[0]);
    return WCOM_SENSOR_LINK_OK;
}

static void sensor_link_disconnected(int client_id)
{
    cam_loop_stop(client_id, 0);
    cam_loop_stop(client_id, 1);
}

static const struct wcom_sensor_link_delegate s_delegate = {
    .on_sensor_link_get_manifest = sensor_link_get_manifest,
    .on_sensor_link_subscribe = sensor_link_subscribe,
    .on_sensor_link_unsubscribe = sensor_link_unsubscribe,
    .on_sensor_link_disconnected = sensor_link_disconnected,
};

esp_err_t wendy_sensor_link_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    // Reserve internal DMA memory before WiFi and TLS fragment the heap.
    esp_err_t err = cam_capture_init();
    s_camera_ready = err == ESP_OK;
    if (!s_camera_ready) {
        ESP_LOGW(TAG, "camera unavailable: %s", esp_err_to_name(err));
    }

    err = mic_init();
    s_microphone_ready = err == ESP_OK;
    if (!s_microphone_ready) {
        ESP_LOGW(TAG, "microphone unavailable: %s", esp_err_to_name(err));
    }
    if (!s_camera_ready && !s_microphone_ready) {
        return ESP_ERR_NOT_FOUND;
    }

    err = cam_loop_init();
    if (err != ESP_OK) {
        // Nothing can stream. Return the DMA memory to device management.
        if (s_camera_ready) {
            cam_capture_deinit();
            s_camera_ready = false;
        }
        if (s_microphone_ready) {
            mic_deinit();
            s_microphone_ready = false;
        }
        return err;
    }

    wendy_core_register_sensor_link_source(&s_delegate);
    s_initialized = true;
    return ESP_OK;
}
