#include "wendy_core.h"

#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3 || CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
#include "esp_log.h"
#include "wendy_sensor_link.h"
#endif
#if CONFIG_WENDY_KORVO_BENCHMARK
#include "wendy_benchmark.h"
#endif

void app_main(void)
{
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3 || CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
    // Reserve sensor DMA memory before networking fragments the internal heap.
    esp_err_t err = wendy_sensor_link_init();
    if (err != ESP_OK) {
        ESP_LOGW("main", "SensorLink unavailable (%s); device management remains active",
                 esp_err_to_name(err));
    }
#endif
    ESP_ERROR_CHECK(wendy_core_init());
#if CONFIG_WENDY_KORVO_BENCHMARK
    ESP_ERROR_CHECK(wendy_benchmark_start());
#endif
}
