#include <stdatomic.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

#include "esp_log.h"
#include "hal/wdt_hal.h"

#include "wendy_com.h"
#include "wendy_core_wdt.h"

static const char *TAG = "wendy_core_wdt";

static wdt_hal_context_t s_rtc_wdt_ctx = RWDT_HAL_CONTEXT_DEFAULT();

void wendy_core_wdt_feed(void)
{
    wdt_hal_write_protect_disable(&s_rtc_wdt_ctx);
    wdt_hal_feed(&s_rtc_wdt_ctx);
    wdt_hal_write_protect_enable(&s_rtc_wdt_ctx);
}

/* Guards against re-queuing the same wcom_operation node before the wcom
 * task has drained the previous one, which would corrupt its intrusive
 * op-queue linked list. If a tick finds this still true, it skips the feed
 * instead of re-queuing: the wcom task is presumed stuck, and the RWDT is
 * left to count down toward a reset rather than being fed blindly. */
static atomic_bool s_feed_pending = false;

static void feed_op(struct wcom_operation *op)
{
    wendy_core_wdt_feed();
    atomic_store(&s_feed_pending, false);
}

static void feed_timer_cb(TimerHandle_t timer)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&s_feed_pending, &expected, true))
        return;

    static struct wcom_operation op = { .func = feed_op };
    wcom_exec(&op);
}

void wendy_core_wdt_start(void)
{
    TimerHandle_t timer = xTimerCreate("wdt_feed", pdMS_TO_TICKS(30000), pdTRUE, NULL, feed_timer_cb);
    if (timer) {
        xTimerStart(timer, 0);
    } else {
        ESP_LOGW(TAG, "failed to create WDT feed timer");
    }
}
