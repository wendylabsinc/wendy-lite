#include "wendy_core.h"
#include "wendy_pki_crypto.h"
#include "esp_log.h"
#if CONFIG_WENDY_NET_PEER
#include "wendy_net_peer.h"
#endif

#if CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3 || CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1
#include "wendy_sensor_link.h"
#endif
#if CONFIG_WENDY_DISPLAY_ESP32S31_KORVO_1
#include "wendy_display.h"
#endif
#if CONFIG_WENDY_KORVO_BENCHMARK
#include "wendy_benchmark.h"
#endif

void app_main(void)
{
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
#if CONFIG_WENDY_NET_SELECT_RADIO_AT_BOOT
    bool boot_ble,boot_wifi;
    ESP_ERROR_CHECK(wendy_net_peer_boot_radios(&boot_ble,&boot_wifi));
    ESP_ERROR_CHECK(wendy_core_set_boot_radios(boot_ble,boot_wifi));
#endif
    ESP_ERROR_CHECK(wendy_core_init());
#if CONFIG_WENDY_NET_PEER
    ESP_ERROR_CHECK(wendy_net_peer_start());
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
