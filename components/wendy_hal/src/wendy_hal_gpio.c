#include "wendy_hal.h"

#include "driver/gpio.h"
#include "driver/ledc.h"
#include "esp_log.h"

static const char *TAG = "wendy_hal_gpio";

/* Track which LEDC channels are assigned to pins for PWM */
#define MAX_PWM_CHANNELS 8
static struct {
    int pin;
    ledc_channel_t channel;
} s_pwm_map[MAX_PWM_CHANNELS];
static int s_pwm_count = 0;

int wendy_hal_gpio_configure(int pin, wendy_gpio_mode_t mode, wendy_gpio_pull_t pull)
{
    gpio_config_t cfg = {
        .pin_bit_mask = (1ULL << pin),
        .intr_type    = GPIO_INTR_DISABLE,
    };

    switch (mode) {
    case WENDY_GPIO_MODE_INPUT:
        cfg.mode = GPIO_MODE_INPUT;
        break;
    case WENDY_GPIO_MODE_OUTPUT:
        cfg.mode = GPIO_MODE_OUTPUT;
        break;
    case WENDY_GPIO_MODE_INPUT_OUTPUT:
        cfg.mode = GPIO_MODE_INPUT_OUTPUT;
        break;
    default:
        return -1;
    }

    switch (pull) {
    case WENDY_GPIO_PULL_NONE:
        cfg.pull_up_en   = GPIO_PULLUP_DISABLE;
        cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
        break;
    case WENDY_GPIO_PULL_UP:
        cfg.pull_up_en   = GPIO_PULLUP_ENABLE;
        cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
        break;
    case WENDY_GPIO_PULL_DOWN:
        cfg.pull_up_en   = GPIO_PULLUP_DISABLE;
        cfg.pull_down_en = GPIO_PULLDOWN_ENABLE;
        break;
    default:
        return -1;
    }

    esp_err_t err = gpio_config(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "gpio_config(%d) failed: %s", pin, esp_err_to_name(err));
        return -1;
    }
    return 0;
}

int wendy_hal_gpio_read(int pin)
{
    return gpio_get_level((gpio_num_t)pin);
}

int wendy_hal_gpio_write(int pin, int level)
{
    esp_err_t err = gpio_set_level((gpio_num_t)pin, level ? 1 : 0);
    return (err == ESP_OK) ? 0 : -1;
}

int wendy_hal_gpio_set_pwm(int pin, uint32_t freq_hz, uint8_t duty_pct)
{
    if (duty_pct > 100) duty_pct = 100;

    /* Find existing channel for this pin, or allocate a new one */
    ledc_channel_t ch = LEDC_CHANNEL_MAX;
    for (int i = 0; i < s_pwm_count; i++) {
        if (s_pwm_map[i].pin == pin) {
            ch = s_pwm_map[i].channel;
            break;
        }
    }

    if (ch == LEDC_CHANNEL_MAX) {
        if (s_pwm_count >= MAX_PWM_CHANNELS) {
            ESP_LOGE(TAG, "no free PWM channels");
            return -1;
        }
        ch = (ledc_channel_t)s_pwm_count;
        s_pwm_map[s_pwm_count].pin     = pin;
        s_pwm_map[s_pwm_count].channel  = ch;
        s_pwm_count++;

        /* Configure timer (one timer per channel for simplicity) */
        ledc_timer_config_t timer_cfg = {
            .speed_mode      = LEDC_LOW_SPEED_MODE,
            .timer_num       = (ledc_timer_t)ch,
            .duty_resolution = LEDC_TIMER_10_BIT,
            .freq_hz         = freq_hz,
            .clk_cfg         = LEDC_AUTO_CLK,
        };
        esp_err_t err = ledc_timer_config(&timer_cfg);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "ledc_timer_config failed: %s", esp_err_to_name(err));
            s_pwm_count--;
            return -1;
        }

        ledc_channel_config_t ch_cfg = {
            .speed_mode = LEDC_LOW_SPEED_MODE,
            .channel    = ch,
            .timer_sel  = (ledc_timer_t)ch,
            .gpio_num   = pin,
            .duty       = 0,
            .hpoint     = 0,
        };
        err = ledc_channel_config(&ch_cfg);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "ledc_channel_config failed: %s", esp_err_to_name(err));
            return -1;
        }
    }

    uint32_t duty = (uint32_t)((1023 * duty_pct) / 100);
    ledc_set_duty(LEDC_LOW_SPEED_MODE, ch, duty);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, ch);

    return 0;
}
