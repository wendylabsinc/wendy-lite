#include "wendy_core.h"
#include "wendy_pki_crypto.h"
#if CONFIG_WENDY_PKI
#include "wendy_pki_clock_observation.h"
#endif
#include "esp_log.h"

#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3 || CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
#include "wendy_sensor_link.h"
#endif
#if CONFIG_WENDY_DISPLAY_ESP32S31_KORVO_1
#include "wendy_display.h"
#endif
#if CONFIG_WENDY_KORVO_BENCHMARK
#include "wendy_benchmark.h"
#endif

/*
 * READ THIS BEFORE YOU ADD CODE HERE (engineers and AI agents).
 *
 * Only the Wendy Lite firmware uses this app_main(). A native Wendy app has
 * its own app_main() and calls only wendy_core_init(), so code here never
 * runs in native apps.
 *
 * Put every generic start step (PKI, Wendy Net, BLE, Wi-Fi, services, ...)
 * in wendy_core_init() (components/wendy_core), so that the firmware and the
 * native apps start the same way. Only firmware-specific board steps belong
 * here: SensorLink, display, benchmark, test probes.
 *
 * The PKI calls below are also in wendy_core_init(). They stay here because
 * SensorLink must start after them and before wendy_core_init().
 */
void app_main(void)
{
#if CONFIG_WENDY_PKI
    wendy_pki_clock_observe_boot();
#endif
    ESP_ERROR_CHECK(wendy_pki_memory_init() ? ESP_FAIL : ESP_OK);
    ESP_ERROR_CHECK(wendy_pki_crypto_init() ? ESP_FAIL : ESP_OK);
#if CONFIG_WENDY_NET_TEST_SENSOR_SERVICE
    void wendy_net_sensor_probe_init(void);
    wendy_net_sensor_probe_init();
#endif
#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3 || CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
    // Reserve sensor DMA memory before networking fragments the internal heap.
    esp_err_t err = wendy_sensor_link_init();
    if (err != ESP_OK) {
        ESP_LOGW("main", "SensorLink unavailable (%s); device management remains active",
                 esp_err_to_name(err));
    }
#endif
    ESP_ERROR_CHECK(wendy_core_init());
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
