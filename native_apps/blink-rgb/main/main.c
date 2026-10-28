#include <stdio.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "rgb_led.h"

#include "wendy_core.h"

// Onboard WS2812 RGB LED
#if CONFIG_IDF_TARGET_ESP32C5
// ESP32-C5-DevKitC-1
#define RGB_LED_GPIO 27
#else
// ESP32-C6-DevKitC-1
// ESP32-C6-DevKitM-1
// ESP32-C61-DevKitC-1
#define RGB_LED_GPIO 8
#endif

void app_main(void)
{
    ESP_ERROR_CHECK(wendy_core_init());
    int count = 0;

    ESP_ERROR_CHECK(rgb_led_init(RGB_LED_GPIO, 1));

    bool on = false;
    while (true) {
        on = !on;
        if (on) {
            ESP_ERROR_CHECK(rgb_led_set(0, 24, 24, 0));
        } else {
            ESP_ERROR_CHECK(rgb_led_clear());
        }
        vTaskDelay(pdMS_TO_TICKS(500));
        printf("Cycle %d\n", count++);
    }
}
