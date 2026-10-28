#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize a WS2812 RGB LED strip using the RMT peripheral, or the
 * SPI-MOSI backend on chips with no RMT peripheral (e.g. ESP32-C61).
 * @param pin       GPIO connected to the data line
 * @param num_leds  Number of LEDs in the strip
 */
esp_err_t rgb_led_init(int pin, int num_leds);

/**
 * Set a pixel color and refresh the strip.
 * @param index  LED index (0-based)
 */
esp_err_t rgb_led_set(int index, uint8_t r, uint8_t g, uint8_t b);

/**
 * Turn off all LEDs.
 */
esp_err_t rgb_led_clear(void);

#ifdef __cplusplus
}
#endif
