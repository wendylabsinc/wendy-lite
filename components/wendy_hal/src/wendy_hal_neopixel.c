#include "wendy_hal.h"
#include "esp_log.h"
#include "led_strip.h"

static const char *TAG = "wendy_hal_neopixel";

static led_strip_handle_t s_strip = NULL;
static int s_strip_pin = -1;
static int s_strip_count = 0;

int wendy_hal_neopixel_init(int pin, int num_leds)
{
    /* Tear down previous strip if reinitializing */
    if (s_strip) {
        led_strip_del(s_strip);
        s_strip = NULL;
    }

    led_strip_config_t strip_config = {
        .strip_gpio_num = pin,
        .max_leds = num_leds,
        .led_model = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .flags.invert_out = false,
    };

    led_strip_rmt_config_t rmt_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000, /* 10 MHz */
        .flags.with_dma = false,
    };

    esp_err_t err = led_strip_new_rmt_device(&strip_config, &rmt_config, &s_strip);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "led_strip_new_rmt_device failed: %s", esp_err_to_name(err));
        return -1;
    }

    s_strip_pin = pin;
    s_strip_count = num_leds;

    /* Clear all LEDs */
    led_strip_clear(s_strip);

    ESP_LOGI(TAG, "NeoPixel initialized: pin=%d, count=%d", pin, num_leds);
    return 0;
}

int wendy_hal_neopixel_set(int index, int r, int g, int b)
{
    if (!s_strip || index < 0 || index >= s_strip_count) {
        return -1;
    }

    esp_err_t err = led_strip_set_pixel(s_strip, index, r, g, b);
    if (err != ESP_OK) {
        return -1;
    }

    err = led_strip_refresh(s_strip);
    return (err == ESP_OK) ? 0 : -1;
}

int wendy_hal_neopixel_clear(void)
{
    if (!s_strip) {
        return -1;
    }

    esp_err_t err = led_strip_clear(s_strip);
    return (err == ESP_OK) ? 0 : -1;
}
