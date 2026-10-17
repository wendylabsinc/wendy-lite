#include "cam_loop.h"

#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "cam_capture.h"
#include "mic.h"
#include "wendy_core.h"
#include "wendy_com.h"
#include "wendy_com_sensor.h"

static const char *TAG = "cam_loop";

#define FRAME_DONE_BIT (1 << 0)
#define STOP_BIT (1 << 1)
#define START_BIT (1 << 2)
#define CONTROL_DONE_BIT (1 << 3)

static TaskHandle_t s_task;
static EventGroupHandle_t s_events;

// Guards the pending/active target fields below.
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static bool s_pending_valid;
static int s_pending_client_id;
static uint32_t s_pending_channel_id;

static bool s_active_valid;
static bool s_stopping;
static int s_active_client_id;
static uint32_t s_active_channel_id;

// Only the sender task submits this operation. It waits for completion before
// reuse, so a rapid unsubscribe/resubscribe cannot lose a stream begin or end.
static struct {
    struct wcom_operation op;
    int client_id;
    uint32_t channel_id;
    bool begin;
    WendyComResult result;
} s_control;

static void stream_control_exec(struct wcom_operation *op)
{
    s_control.result = s_control.begin
        ? wcom_sensor_stream_begin(s_control.client_id, s_control.channel_id)
        : wcom_sensor_stream_end(s_control.client_id, s_control.channel_id);
    xEventGroupSetBits(s_events, CONTROL_DONE_BIT);
}

static WendyComResult stream_control(int client_id, uint32_t channel_id, bool begin)
{
    s_control.op.func = stream_control_exec;
    s_control.client_id = client_id;
    s_control.channel_id = channel_id;
    s_control.begin = begin;
    xEventGroupClearBits(s_events, CONTROL_DONE_BIT);
    wcom_exec(&s_control.op);
    xEventGroupWaitBits(s_events, CONTROL_DONE_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
    return s_control.result;
}

static void frame_done_cb(uint32_t channel_id)
{
    xEventGroupSetBits(s_events, FRAME_DONE_BIT);
}

static void cam_loop_task(void *arg)
{
    for (;;) {
        xEventGroupWaitBits(s_events, START_BIT, pdTRUE, pdFALSE, portMAX_DELAY);

        taskENTER_CRITICAL(&s_lock);
        bool valid = s_pending_valid;
        int client_id = s_pending_client_id;
        uint32_t channel_id = s_pending_channel_id;
        if (valid) {
            s_pending_valid = false;
            s_active_valid = true;
            s_active_client_id = client_id;
            s_active_channel_id = channel_id;
        }
        taskEXIT_CRITICAL(&s_lock);

        if (!valid) {
            // Latched start was cancelled by a race with cam_loop_stop()
            // before we got here.
            continue;
        }

        ESP_LOGI(TAG, "starting stream for client %d channel %" PRIu32, client_id, channel_id);
        if (channel_id == 1 && mic_start() != ESP_OK) {
            ESP_LOGE(TAG, "microphone capture could not start");
            taskENTER_CRITICAL(&s_lock);
            s_active_valid = false;
            taskEXIT_CRITICAL(&s_lock);
            continue;
        }
        if (stream_control(client_id, channel_id, true) != WendyComResult_WENDY_COM_RESULT_OK) {
            if (channel_id == 1) {
                mic_stop();
            }
            taskENTER_CRITICAL(&s_lock);
            s_active_valid = false;
            taskEXIT_CRITICAL(&s_lock);
            continue;
        }

        const uint8_t *pending_jpeg = NULL;
        static int16_t pcm[MIC_READ_SAMPLES];
        bool audio_pending = false;

        for (;;) {
            if (xEventGroupGetBits(s_events) & STOP_BIT) {
                break;
            }

            if (audio_pending) {
                xEventGroupWaitBits(s_events, FRAME_DONE_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
                audio_pending = false;
                if (xEventGroupGetBits(s_events) & STOP_BIT) {
                    break;
                }
            }
            if (channel_id == 1) {
                size_t bytes_read = 0;
                esp_err_t err = mic_read(pcm, MIC_READ_SAMPLES, &bytes_read);
                if (err != ESP_OK || bytes_read == 0) {
                    if (err != ESP_ERR_TIMEOUT) {
                        ESP_LOGW(TAG, "microphone read failed: %s", esp_err_to_name(err));
                        vTaskDelay(pdMS_TO_TICKS(20));
                    }
                    continue;
                }
                if (xEventGroupGetBits(s_events) & STOP_BIT) {
                    break;
                }
                xEventGroupClearBits(s_events, FRAME_DONE_BIT);
                audio_pending = true;
                uint64_t timestamp = esp_timer_get_time() -
                    (bytes_read / sizeof(int16_t)) * 1000000ULL / MIC_SAMPLE_RATE_HZ;
                wendy_core_sensor_stream_push(client_id, channel_id, pcm, bytes_read,
                                              timestamp, frame_done_cb);
                continue;
            }

            // Return the transmitted frame before requesting another one.
            // Holding a frame while capture waits can starve the driver's
            // two-buffer pool, and ages the next frame behind a slow send.
            if (pending_jpeg) {
                EventBits_t bits = xEventGroupWaitBits(s_events, FRAME_DONE_BIT | STOP_BIT,
                                                      pdFALSE, pdFALSE, portMAX_DELAY);
                if (bits & STOP_BIT) {
                    break;
                }
                cam_capture_release_frame(pending_jpeg);
                pending_jpeg = NULL;
            }

            const uint8_t *jpeg;
            size_t jpeg_len;
            int width, height;
            esp_err_t err = cam_capture_retrieve_jpeg_frame(&jpeg, &jpeg_len, &width, &height);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "cam_capture_retrieve_jpeg_frame failed: %s", esp_err_to_name(err));
                vTaskDelay(pdMS_TO_TICKS(20));
                continue;
            }

            if (xEventGroupGetBits(s_events) & STOP_BIT) {
                cam_capture_release_frame(jpeg);
                break;
            }

            pending_jpeg = jpeg;
            xEventGroupClearBits(s_events, FRAME_DONE_BIT);
            wendy_core_sensor_stream_push(client_id, channel_id, jpeg, jpeg_len, esp_timer_get_time(), frame_done_cb);
        }

        if (pending_jpeg) {
            // The last frame sent may still be in flight; wait for its done
            // callback before handing the buffer back.
            xEventGroupWaitBits(s_events, FRAME_DONE_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
            cam_capture_release_frame(pending_jpeg);
        }

        if (audio_pending) {
            xEventGroupWaitBits(s_events, FRAME_DONE_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
        }
        if (channel_id == 1) {
            mic_stop();
        }
        stream_control(client_id, channel_id, false);
        ESP_LOGI(TAG, "stopped stream for client %d channel %" PRIu32, client_id, channel_id);

        taskENTER_CRITICAL(&s_lock);
        s_active_valid = false;
        taskEXIT_CRITICAL(&s_lock);
    }
}

esp_err_t cam_loop_init(void)
{
    if (s_task) {
        return ESP_OK;
    }

    s_events = xEventGroupCreate();
    if (!s_events) {
        return ESP_ERR_NO_MEM;
    }

    if (xTaskCreate(cam_loop_task, "cam_loop", 4096, NULL, 5, &s_task) != pdPASS) {
        vEventGroupDelete(s_events);
        s_events = NULL;
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

enum wcom_sensor_link_result cam_loop_start(int client_id, uint32_t channel_id)
{
    if (!s_events || channel_id > 1) {
        return WCOM_SENSOR_LINK_FAIL;
    }

    taskENTER_CRITICAL(&s_lock);
    if (s_pending_valid || s_active_valid) {
        bool same = (s_pending_valid && s_pending_client_id == client_id && s_pending_channel_id == channel_id) ||
                    (s_active_valid && s_active_client_id == client_id && s_active_channel_id == channel_id);
        if (same && !s_stopping) {
            taskEXIT_CRITICAL(&s_lock);
            return WCOM_SENSOR_LINK_OK;
        }
        bool pending = s_pending_valid;
        int owner_client = pending ? s_pending_client_id : s_active_client_id;
        uint32_t owner_channel = pending ? s_pending_channel_id : s_active_channel_id;
        bool stopping = s_stopping;
        taskEXIT_CRITICAL(&s_lock);
        ESP_LOGW(TAG, "stream busy: requested client=%d channel=%" PRIu32
                 ", owner client=%d channel=%" PRIu32 " (%s, stopping=%d)",
                 client_id, channel_id, owner_client, owner_channel,
                 pending ? "pending" : "active", stopping);
        return WCOM_SENSOR_LINK_BUSY;
    }
    xEventGroupClearBits(s_events, STOP_BIT);
    s_stopping = false;
    s_pending_valid = true;
    s_pending_client_id = client_id;
    s_pending_channel_id = channel_id;
    taskEXIT_CRITICAL(&s_lock);

    xEventGroupSetBits(s_events, START_BIT);
    return WCOM_SENSOR_LINK_OK;
}

void cam_loop_stop(int client_id, uint32_t channel_id)
{
    if (!s_events) {
        return;
    }

    bool stop_active = false;

    taskENTER_CRITICAL(&s_lock);
    if (s_pending_valid && s_pending_client_id == client_id && s_pending_channel_id == channel_id) {
        s_pending_valid = false;
    }
    if (s_active_valid && s_active_client_id == client_id && s_active_channel_id == channel_id) {
        s_stopping = true;
        stop_active = true;
    }
    taskEXIT_CRITICAL(&s_lock);

    if (stop_active) {
        xEventGroupSetBits(s_events, STOP_BIT);
    }
}
