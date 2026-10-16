#include "wendy_core.h"

#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
#include "esp_log.h"
#include "wendy_sensor_link.h"
#endif

void app_main(void)
{
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3
    // Reserve sensor DMA memory before networking fragments the internal heap.
    esp_err_t err = wendy_sensor_link_init();
    if (err != ESP_OK) {
        ESP_LOGW("main", "SensorLink unavailable (%s); device management remains active",
                 esp_err_to_name(err));
    }
#endif
    wendy_core_init();
}
