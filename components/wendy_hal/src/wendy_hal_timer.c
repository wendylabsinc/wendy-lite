#include "wendy_hal.h"

#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"
#include "esp_timer.h"
#include "esp_log.h"

static const char *TAG = "wendy_hal_timer";

#define MAX_TIMERS 8

typedef struct {
    esp_timer_handle_t handle;
    void (*cb)(void *);
    void *arg;
    bool active;
} timer_slot_t;

static timer_slot_t s_timers[MAX_TIMERS];

void wendy_hal_timer_delay_ms(uint32_t ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms));
}

uint64_t wendy_hal_timer_millis(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000);
}

static void timer_callback(void *arg)
{
    timer_slot_t *slot = (timer_slot_t *)arg;
    if (slot->active && slot->cb) {
        slot->cb(slot->arg);
    }
    slot->active = false;
}

int wendy_hal_timer_schedule(uint32_t ms, void (*cb)(void *), void *arg)
{
    /* Find a free slot */
    int id = -1;
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!s_timers[i].active && !s_timers[i].handle) {
            id = i;
            break;
        }
    }
    /* Also reclaim completed timers */
    if (id < 0) {
        for (int i = 0; i < MAX_TIMERS; i++) {
            if (!s_timers[i].active && s_timers[i].handle) {
                esp_timer_delete(s_timers[i].handle);
                s_timers[i].handle = NULL;
                id = i;
                break;
            }
        }
    }
    if (id < 0) {
        ESP_LOGE(TAG, "no free timer slots");
        return -1;
    }

    s_timers[id].cb     = cb;
    s_timers[id].arg    = arg;
    s_timers[id].active = true;

    esp_timer_create_args_t args = {
        .callback        = timer_callback,
        .arg             = &s_timers[id],
        .dispatch_method = ESP_TIMER_TASK,
        .name            = "wendy_timer",
    };

    esp_err_t err = esp_timer_create(&args, &s_timers[id].handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_timer_create failed: %s", esp_err_to_name(err));
        s_timers[id].active = false;
        return -1;
    }

    err = esp_timer_start_once(s_timers[id].handle, (uint64_t)ms * 1000);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_timer_start_once failed: %s", esp_err_to_name(err));
        esp_timer_delete(s_timers[id].handle);
        s_timers[id].handle = NULL;
        s_timers[id].active = false;
        return -1;
    }

    return id + 1; /* return 1-based ID */
}

int wendy_hal_timer_cancel(int timer_id)
{
    int idx = timer_id - 1;
    if (idx < 0 || idx >= MAX_TIMERS || !s_timers[idx].handle) {
        return -1;
    }
    esp_timer_stop(s_timers[idx].handle);
    esp_timer_delete(s_timers[idx].handle);
    s_timers[idx].handle = NULL;
    s_timers[idx].active = false;
    return 0;
}
