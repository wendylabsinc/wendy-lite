#include "rgb_led.h"

#include "soc/soc_caps.h"
#include "led_strip.h"

static led_strip_handle_t s_strip = NULL;

esp_err_t rgb_led_init(int pin, int num_leds)
{
    led_strip_config_t strip_config = {
        .strip_gpio_num = pin,
        .max_leds = num_leds,
        .led_model = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
    };

#if SOC_RMT_SUPPORTED
    led_strip_rmt_config_t rmt_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000, /* 10 MHz */
        .flags.with_dma = false,
    };
    return led_strip_new_rmt_device(&strip_config, &rmt_config, &s_strip);
#else
    led_strip_spi_config_t spi_config = {
        .clk_src = SPI_CLK_SRC_DEFAULT,
        .spi_bus = SPI2_HOST,
        .flags.with_dma = false,
    };
    return led_strip_new_spi_device(&strip_config, &spi_config, &s_strip);
#endif
}

esp_err_t rgb_led_set(int index, uint8_t r, uint8_t g, uint8_t b)
{
    esp_err_t err = led_strip_set_pixel(s_strip, index, r, g, b);
    if (err != ESP_OK) {
        return err;
    }
    return led_strip_refresh(s_strip);
}

esp_err_t rgb_led_clear(void)
{
    return led_strip_clear(s_strip);
}
