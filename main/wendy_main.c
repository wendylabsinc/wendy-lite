#include "wendy_core.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "wendy_heap_diag.h"

#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3 || CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
#include "wendy_sensor_link.h"
#endif
#if CONFIG_WENDY_DISPLAY_ESP32S31_KORVO_1
#include "wendy_display.h"
#endif
#if CONFIG_WENDY_KORVO_BENCHMARK
#include "wendy_benchmark.h"
#endif

#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
/* TEST-ONLY: periodic heap and SensorLink counters. */
static void diag_tick(void *unused)
{
    (void)unused;
    WENDY_HEAP_DIAG("main", "periodic");
    for (uint32_t ch = 0; ch < 2; ch++) {
        struct wendy_sensor_link_stats st;
        if (wendy_sensor_link_get_stats(ch, &st) == ESP_OK) {
            ESP_LOGW("main", "sldiag ch%u submitted=%llu completed=%llu bytes=%llu capture_errors=%llu rejected=%llu",
                     (unsigned)ch, (unsigned long long)st.frames_submitted,
                     (unsigned long long)st.frames_completed, (unsigned long long)st.bytes_submitted,
                     (unsigned long long)st.capture_errors, (unsigned long long)st.queue_rejected);
        }
    }
}
#endif

void app_main(void)
{
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3 || CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
    WENDY_HEAP_DIAG_EARLY("main", "before sensor_link_init");
    // Reserve sensor DMA memory before networking fragments the internal heap.
    esp_err_t err = wendy_sensor_link_init();
    WENDY_HEAP_DIAG_EARLY("main", "after sensor_link_init");
    ESP_EARLY_LOGW("main", "sldiag sensor_link_init=%s", esp_err_to_name(err));
    if (err != ESP_OK) {
        ESP_LOGW("main", "SensorLink unavailable (%s); device management remains active",
                 esp_err_to_name(err));
    }
#endif
    ESP_ERROR_CHECK(wendy_core_init());
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
    {
        static esp_timer_handle_t t;
        const esp_timer_create_args_t a = { .callback = diag_tick, .name = "maindiag" };
        if (esp_timer_create(&a, &t) == ESP_OK) esp_timer_start_periodic(t, 30 * 1000 * 1000);
    }
#endif
#if CONFIG_WENDY_DISPLAY_ESP32S31_KORVO_1
    esp_err_t display_err = wendy_display_start();
    if (display_err != ESP_OK) {
        ESP_LOGW("main", "Display unavailable (%s); device management remains active",
                 esp_err_to_name(display_err));
    }
#endif
#if CONFIG_WENDY_KORVO_BENCHMARK
    ESP_ERROR_CHECK(wendy_benchmark_start());
#endif
}
