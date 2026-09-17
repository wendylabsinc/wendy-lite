#include <stdatomic.h>
#include <stdbool.h>
#include <sys/param.h>

#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

#include "esp_log.h"
#include "hal/wdt_hal.h"

#include "wendy_com.h"
#include "wendy_core_wdt.h"

static wdt_hal_context_t s_rtc_wdt_ctx = RWDT_HAL_CONTEXT_DEFAULT();

#if CONFIG_WENDY_CORE_WATCHDOG

static const char *TAG = "wendy_core_wdt";

/* How often we feed the RTC watchdog, derived from its timeout so the two
 * cannot drift apart when CONFIG_BOOTLOADER_WDT_TIME_MS is changed: leave 10s
 * of margin, or fall back to half the timeout when it is too short to spare
 * 10s. The subtraction is signed on purpose -- the timeout can be well under
 * 10000, and an unsigned wrap here would disarm the watchdog in practice. */
#define WDT_FEED_PERIOD_MS \
    MAX((int)CONFIG_BOOTLOADER_WDT_TIME_MS / 2, (int)CONFIG_BOOTLOADER_WDT_TIME_MS - 10000)

_Static_assert(WDT_FEED_PERIOD_MS >= 4000,
               "CONFIG_BOOTLOADER_WDT_TIME_MS leaves no room to feed the watchdog under it");

/**
 * Feeds the RTC watchdog once, immediately. Call as the very first thing
 * wendy_core_init() does: CONFIG_BOOTLOADER_WDT_DISABLE_IN_USER_CODE leaves
 * the watchdog the bootloader armed running into user code instead of having
 * ESP-IDF disable it before app_main(), so the firmware owns it from its
 * first instruction. The timeout is CONFIG_BOOTLOADER_WDT_TIME_MS. Does
 * nothing with CONFIG_WENDY_CORE_WATCHDOG unset.
 */
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

/**
 * Arms a periodic timer that keeps feeding the RTC watchdog as long as the
 * wendy_com task stays responsive. The period is derived from
 * CONFIG_BOOTLOADER_WDT_TIME_MS: 10s below it, or half of it when the timeout
 * is under 20s. Does nothing with CONFIG_WENDY_CORE_WATCHDOG unset.
 */
void wendy_core_wdt_start(void)
{
    TimerHandle_t timer = xTimerCreate("wdt_feed", pdMS_TO_TICKS(WDT_FEED_PERIOD_MS), pdTRUE, NULL,
                                       feed_timer_cb);
    if (timer) {
        xTimerStart(timer, 0);
    } else {
        ESP_LOGW(TAG, "failed to create WDT feed timer");
    }
}

#else /* !CONFIG_WENDY_CORE_WATCHDOG */

void wendy_core_wdt_feed(void)
{
}

void wendy_core_wdt_start(void)
{
}

#endif /* CONFIG_WENDY_CORE_WATCHDOG */
