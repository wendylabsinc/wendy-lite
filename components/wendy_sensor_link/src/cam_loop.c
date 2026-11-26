#include "cam_loop.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "cam_capture.h"
#include "mic.h"
#include "wendy_core.h"
#include "wendy_core_sensor.h"
#include "wendy_sensor_link.h"

static const char *TAG = "cam_loop";

#define FRAME_DONE_BIT (1 << 0)
#define STOP_BIT (1 << 1)
#define START_BIT (1 << 2)
#define CONTROL_DONE_BIT (1 << 3)

// One sender per channel, so the camera and microphone stream independently.
#define SENDER_COUNT 2

struct sender {
    TaskHandle_t task;
    EventGroupHandle_t events;
    bool pending_valid;
    int pending_client_id;
    uint32_t pending_channel_id;
    bool active_valid;
    bool stopping;
    int active_client_id;
    uint32_t active_channel_id;
};

static struct sender s_senders[SENDER_COUNT];
static bool s_initialized;
// Allocated, not static: on the XIAO an allocation this size goes to PSRAM,
// leaving internal RAM to DMA and networking.
static int16_t *s_pcm;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static struct wendy_sensor_link_stats s_stats[2];
static struct {
    uint64_t started_us;
    size_t size;
} s_inflight[2];

esp_err_t wendy_sensor_link_get_stats(uint32_t channel_id, struct wendy_sensor_link_stats *stats)
{
    if (channel_id >= 2 || !stats) {
        return ESP_ERR_INVALID_ARG;
    }
    taskENTER_CRITICAL(&s_lock);
    *stats = s_stats[channel_id];
    taskEXIT_CRITICAL(&s_lock);
    return ESP_OK;
}

static void record_capture(uint32_t channel_id, uint64_t start_us, bool failed)
{
    uint64_t elapsed = esp_timer_get_time() - start_us;
    taskENTER_CRITICAL(&s_lock);
    struct wendy_sensor_link_stats *stats = &s_stats[channel_id];
    stats->capture_errors += failed;
    stats->capture_time_us += elapsed;
    if (elapsed > stats->capture_time_max_us) {
        stats->capture_time_max_us = elapsed;
    }
    taskEXIT_CRITICAL(&s_lock);
}

/* Caller holds s_lock. This records buffer return, not successful delivery. */
static void record_completion(uint32_t channel_id, uint64_t elapsed)
{
    struct wendy_sensor_link_stats *stats = &s_stats[channel_id];
    ++stats->frames_completed;
    stats->completion_time_us += elapsed;
    if (elapsed > stats->completion_time_max_us) {
        stats->completion_time_max_us = elapsed;
    }
}

static struct sender *sender_for_channel(uint32_t channel_id)
{
    return &s_senders[channel_id];
}

static void stream_end_cb(int client_id, uint32_t channel_id, enum wendy_core_sensor_result result)
{
    if (channel_id < SENDER_COUNT) {
        xEventGroupSetBits(sender_for_channel(channel_id)->events, CONTROL_DONE_BIT);
    }
}

/* Waits until the com task has closed the stream, so a later begin of the
 * same stream cannot be refused because this one is still open. */
static void stream_end(struct sender *sender, int client_id, uint32_t channel_id)
{
    xEventGroupClearBits(sender->events, CONTROL_DONE_BIT);
    wendy_core_sensor_stream_end(client_id, channel_id, stream_end_cb);
    xEventGroupWaitBits(sender->events, CONTROL_DONE_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
}

static void frame_done_cb(int client_id, uint32_t channel_id, enum wendy_core_sensor_result result)
{
    if (channel_id < 2) {
        uint64_t now = esp_timer_get_time();
        taskENTER_CRITICAL(&s_lock);
        if (result == WENDY_CORE_SENSOR_OK) {
            ++s_stats[channel_id].frames_submitted;
            s_stats[channel_id].bytes_submitted += s_inflight[channel_id].size;
            record_completion(channel_id, now - s_inflight[channel_id].started_us);
        } else {
            ++s_stats[channel_id].queue_rejected;
        }
        taskEXIT_CRITICAL(&s_lock);
        xEventGroupSetBits(sender_for_channel(channel_id)->events, FRAME_DONE_BIT);
    }
}

static void submit_frame(int client_id, uint32_t channel_id, const void *data,
                         size_t size, uint64_t timestamp)
{
    uint64_t now = esp_timer_get_time();
    taskENTER_CRITICAL(&s_lock);
    s_inflight[channel_id].started_us = now;
    s_inflight[channel_id].size = size;
    taskEXIT_CRITICAL(&s_lock);
    // done runs exactly once, on refusal too, and hands the buffer back.
    wendy_core_sensor_stream_push(client_id, channel_id, data, size, timestamp, frame_done_cb);
}

static void cam_loop_task(void *arg)
{
    struct sender *sender = arg;
    for (;;) {
        xEventGroupWaitBits(sender->events, START_BIT, pdTRUE, pdFALSE, portMAX_DELAY);

        taskENTER_CRITICAL(&s_lock);
        bool valid = sender->pending_valid;
        int client_id = sender->pending_client_id;
        uint32_t channel_id = sender->pending_channel_id;
        if (valid) {
            sender->pending_valid = false;
            sender->active_valid = true;
            sender->active_client_id = client_id;
            sender->active_channel_id = channel_id;
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
            sender->active_valid = false;
            taskEXIT_CRITICAL(&s_lock);
            continue;
        }
#if CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1 || CONFIG_WENDY_SENSOR_LINK_MOSAICO
        if (channel_id == 0 && cam_capture_start() != ESP_OK) {
            ESP_LOGE(TAG, "camera capture could not start");
            taskENTER_CRITICAL(&s_lock);
            sender->active_valid = false;
            taskEXIT_CRITICAL(&s_lock);
            continue;
        }
#endif
        enum wendy_core_sensor_result begun = wendy_core_sensor_stream_begin(client_id, channel_id);
        if (begun != WENDY_CORE_SENSOR_OK) {
            ESP_LOGW(TAG, "stream begin refused for client %d channel %" PRIu32 ": %d",
                     client_id, channel_id, begun);
            if (channel_id == 1) {
                mic_stop();
            }
#if CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1 || CONFIG_WENDY_SENSOR_LINK_MOSAICO
            else {
                cam_capture_stop();
            }
#endif
            taskENTER_CRITICAL(&s_lock);
            sender->active_valid = false;
            taskEXIT_CRITICAL(&s_lock);
            continue;
        }

        const uint8_t *pending_jpeg = NULL;
        bool audio_pending = false;

        for (;;) {
            if (xEventGroupGetBits(sender->events) & STOP_BIT) {
                break;
            }

            if (audio_pending) {
                EventBits_t bits = xEventGroupWaitBits(sender->events, FRAME_DONE_BIT | STOP_BIT,
                                                      pdFALSE, pdFALSE, portMAX_DELAY);
                if (bits & STOP_BIT) {
                    break;
                }
                xEventGroupClearBits(sender->events, FRAME_DONE_BIT);
                audio_pending = false;
            }
            if (channel_id == 1) {
                size_t bytes_read = 0;
                uint64_t capture_started = esp_timer_get_time();
                esp_err_t err = mic_read(s_pcm, MIC_READ_SAMPLES, &bytes_read);
                record_capture(channel_id, capture_started, err != ESP_OK || bytes_read == 0);
                if (err != ESP_OK || bytes_read == 0) {
                    if (err != ESP_ERR_TIMEOUT) {
                        ESP_LOGW(TAG, "microphone read failed: %s", esp_err_to_name(err));
                        vTaskDelay(pdMS_TO_TICKS(20));
                    }
                    continue;
                }
                // Sending a frame can take longer than recording a block,
                // above all while camera chunks share the link. Send what
                // queued up meanwhile with this block, so audio keeps pace
                // instead of overrunning the capture buffer.
                size_t read_samples = bytes_read / sizeof(*s_pcm);
                size_t queued = 0;
                if (read_samples < MIC_MAX_READ_SAMPLES &&
                    mic_read_queued(s_pcm + read_samples, MIC_MAX_READ_SAMPLES - read_samples,
                                    &queued) == ESP_OK) {
                    bytes_read += queued;
                }
                if (xEventGroupGetBits(sender->events) & STOP_BIT) {
                    break;
                }
                xEventGroupClearBits(sender->events, FRAME_DONE_BIT);
                audio_pending = true;
                uint64_t timestamp = esp_timer_get_time() -
                    (bytes_read / (sizeof(int16_t) * MIC_CHANNELS)) * 1000000ULL / MIC_SAMPLE_RATE_HZ;
                submit_frame(client_id, channel_id, s_pcm, bytes_read, timestamp);
                continue;
            }

            // Return the transmitted frame before requesting another one.
            // Holding a frame while capture waits can starve the driver's
            // two-buffer pool, and ages the next frame behind a slow send.
            if (pending_jpeg) {
                EventBits_t bits = xEventGroupWaitBits(sender->events, FRAME_DONE_BIT | STOP_BIT,
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
            uint64_t capture_started = esp_timer_get_time();
            esp_err_t err = cam_capture_retrieve_jpeg_frame(&jpeg, &jpeg_len, &width, &height);
            record_capture(channel_id, capture_started, err != ESP_OK);
            if (err != ESP_OK) {
                if (err != ESP_ERR_TIMEOUT) {
                    ESP_LOGW(TAG, "camera capture failed: %s", esp_err_to_name(err));
                    vTaskDelay(pdMS_TO_TICKS(20));
                }
                continue;
            }

            if (xEventGroupGetBits(sender->events) & STOP_BIT) {
                cam_capture_release_frame(jpeg);
                break;
            }

            pending_jpeg = jpeg;
            xEventGroupClearBits(sender->events, FRAME_DONE_BIT);
            submit_frame(client_id, channel_id, jpeg, jpeg_len, esp_timer_get_time());
        }

        // Cancel at the transport before waiting for borrowed buffers. A
        // queued chunk finishes first; unsent chunks need not drain in full.
        stream_end(sender, client_id, channel_id);
        if (pending_jpeg) {
            // The last frame sent may still be in flight; wait for its done
            // callback before handing the buffer back.
            xEventGroupWaitBits(sender->events, FRAME_DONE_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
            cam_capture_release_frame(pending_jpeg);
        }

        if (audio_pending) {
            xEventGroupWaitBits(sender->events, FRAME_DONE_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
        }
        if (channel_id == 1) {
            mic_stop();
        }
#if CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1 || CONFIG_WENDY_SENSOR_LINK_MOSAICO
        else {
            cam_capture_stop();
        }
#endif
        ESP_LOGI(TAG, "stopped stream for client %d channel %" PRIu32, client_id, channel_id);

        taskENTER_CRITICAL(&s_lock);
        sender->active_valid = false;
        taskEXIT_CRITICAL(&s_lock);
    }
}

esp_err_t cam_loop_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }
    s_pcm = malloc(MIC_MAX_READ_SAMPLES * sizeof(*s_pcm));
    if (!s_pcm) {
        goto fail;
    }
    for (unsigned i = 0; i < SENDER_COUNT; ++i) {
        struct sender *sender = &s_senders[i];
        sender->events = xEventGroupCreate();
        if (!sender->events) {
            goto fail;
        }
        if (xTaskCreate(cam_loop_task, i ? "mic_loop" : "cam_loop", 4096,
                        sender, 5, &sender->task) != pdPASS) {
            goto fail;
        }
    }
    s_initialized = true;
    return ESP_OK;
fail:
    for (unsigned i = 0; i < SENDER_COUNT; ++i) {
        struct sender *sender = &s_senders[i];
        if (sender->task) {
            vTaskDelete(sender->task);
            sender->task = NULL;
        }
        if (sender->events) {
            vEventGroupDelete(sender->events);
            sender->events = NULL;
        }
    }
    free(s_pcm);
    s_pcm = NULL;
    return ESP_ERR_NO_MEM;
}

/* Caller holds s_lock. Report ownership without changing the reservation. */
static enum wcom_sensor_link_result check_available(struct sender *sender, int client_id, uint32_t channel_id)
{
    if (!sender->pending_valid && !sender->active_valid) {
        return WCOM_SENSOR_LINK_OK;
    }
    bool same = (sender->pending_valid && sender->pending_client_id == client_id && sender->pending_channel_id == channel_id) ||
                (sender->active_valid && sender->active_client_id == client_id && sender->active_channel_id == channel_id);
    if (same && !sender->stopping) {
        return WCOM_SENSOR_LINK_OK;
    }
    return WCOM_SENSOR_LINK_BUSY;
}

enum wcom_sensor_link_result cam_loop_start_many(int client_id, const uint32_t *channel_ids, size_t count)
{
    if (!s_initialized || !channel_ids || count == 0 || count > SENDER_COUNT) {
        return WCOM_SENSOR_LINK_FAIL;
    }
    for (size_t i = 0; i < count; ++i) {
        if (channel_ids[i] > 1 || (i && channel_ids[i] == channel_ids[0])) {
            return WCOM_SENSOR_LINK_FAIL;
        }
    }
    // Validate the complete request before reserving either channel.
    taskENTER_CRITICAL(&s_lock);
    for (size_t i = 0; i < count; ++i) {
        uint32_t channel_id = channel_ids[i];
        struct sender *sender = sender_for_channel(channel_id);
        if (check_available(sender, client_id, channel_id) != WCOM_SENSOR_LINK_OK) {
            bool pending = sender->pending_valid;
            int owner_client = pending ? sender->pending_client_id : sender->active_client_id;
            uint32_t owner_channel = pending ? sender->pending_channel_id : sender->active_channel_id;
            bool stopping = sender->stopping;
            taskEXIT_CRITICAL(&s_lock);
            ESP_LOGW(TAG, "stream busy: requested client=%d channel=%" PRIu32
                     ", owner client=%d channel=%" PRIu32 " (%s, stopping=%d)",
                     client_id, channel_id, owner_client, owner_channel,
                     pending ? "pending" : "active", stopping);
            return WCOM_SENSOR_LINK_BUSY;
        }
    }
    bool start[SENDER_COUNT] = {0};
    for (size_t i = 0; i < count; ++i) {
        struct sender *sender = sender_for_channel(channel_ids[i]);
        if (!sender->pending_valid && !sender->active_valid) {
            xEventGroupClearBits(sender->events, STOP_BIT);
            sender->stopping = false;
            sender->pending_valid = true;
            sender->pending_client_id = client_id;
            sender->pending_channel_id = channel_ids[i];
            start[i] = true;
        }
    }
    taskEXIT_CRITICAL(&s_lock);
    for (size_t i = 0; i < count; ++i) {
        if (start[i]) {
            xEventGroupSetBits(sender_for_channel(channel_ids[i])->events, START_BIT);
        }
    }
    return WCOM_SENSOR_LINK_OK;
}

enum wcom_sensor_link_result cam_loop_start(int client_id, uint32_t channel_id)
{
    return cam_loop_start_many(client_id, &channel_id, 1);
}

void cam_loop_stop(int client_id, uint32_t channel_id)
{
    if (!s_initialized || channel_id > 1) {
        return;
    }
    struct sender *sender = sender_for_channel(channel_id);
    bool stop_active = false;
    taskENTER_CRITICAL(&s_lock);
    if (sender->pending_valid && sender->pending_client_id == client_id && sender->pending_channel_id == channel_id) {
        sender->pending_valid = false;
    }
    if (sender->active_valid && sender->active_client_id == client_id && sender->active_channel_id == channel_id) {
        sender->stopping = true;
        stop_active = true;
    }
    taskEXIT_CRITICAL(&s_lock);
    if (stop_active) {
        xEventGroupSetBits(sender->events, STOP_BIT);
    }
}
