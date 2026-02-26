#include "wendy_hal.h"

#include "driver/gpio.h"
#include "driver/ledc.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_log.h"

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#endif

static const char *TAG = "wendy_hal_gpio";

/* Track which LEDC channels are assigned to pins for PWM */
#define MAX_PWM_CHANNELS 8
static struct {
    int pin;
    ledc_channel_t channel;
} s_pwm_map[MAX_PWM_CHANNELS];
static int s_pwm_count = 0;

/* ADC state */
static adc_oneshot_unit_handle_t s_adc1_handle;
static bool s_adc1_initialized = false;

/* GPIO interrupt handler IDs */
#define MAX_GPIO_ISR 16
static struct {
    int pin;
    uint32_t handler_id;
    bool active;
} s_gpio_isr[MAX_GPIO_ISR];
static bool s_gpio_isr_service_installed = false;

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

/* ── ADC ──────────────────────────────────────────────────────────────── */

int wendy_hal_gpio_analog_read(int pin)
{
    /* Map GPIO pin to ADC1 channel. This is chip-specific;
     * for ESP32-C6, ADC1 channels are GPIO0-6. */
    adc_channel_t channel;
    esp_err_t err = adc_oneshot_io_to_channel(pin, NULL, &channel);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pin %d is not an ADC pin", pin);
        return -1;
    }

    if (!s_adc1_initialized) {
        adc_oneshot_unit_init_cfg_t init_cfg = {
            .unit_id = ADC_UNIT_1,
        };
        err = adc_oneshot_new_unit(&init_cfg, &s_adc1_handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "adc_oneshot_new_unit failed: %s", esp_err_to_name(err));
            return -1;
        }
        s_adc1_initialized = true;
    }

    adc_oneshot_chan_cfg_t chan_cfg = {
        .atten = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    err = adc_oneshot_config_channel(s_adc1_handle, channel, &chan_cfg);
    if (err != ESP_OK) {
        return -1;
    }

    int raw = 0;
    err = adc_oneshot_read(s_adc1_handle, channel, &raw);
    if (err != ESP_OK) {
        return -1;
    }
    return raw;
}

/* ── GPIO Interrupts ──────────────────────────────────────────────────── */

#if CONFIG_WENDY_CALLBACK

static void IRAM_ATTR gpio_isr_handler(void *arg)
{
    int idx = (int)(uintptr_t)arg;
    if (idx >= 0 && idx < MAX_GPIO_ISR && s_gpio_isr[idx].active) {
        int level = gpio_get_level((gpio_num_t)s_gpio_isr[idx].pin);
        wendy_callback_post_from_isr(s_gpio_isr[idx].handler_id,
                                      (uint32_t)s_gpio_isr[idx].pin,
                                      (uint32_t)level, 0);
    }
}

int wendy_hal_gpio_set_interrupt(int pin, int edge_type, uint32_t handler_id)
{
    /* edge_type: 1=rising, 2=falling, 3=any */
    gpio_int_type_t intr;
    switch (edge_type) {
    case 1: intr = GPIO_INTR_POSEDGE;    break;
    case 2: intr = GPIO_INTR_NEGEDGE;    break;
    case 3: intr = GPIO_INTR_ANYEDGE;    break;
    default: return -1;
    }

    if (!s_gpio_isr_service_installed) {
        esp_err_t err = gpio_install_isr_service(0);
        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
            ESP_LOGE(TAG, "gpio_install_isr_service failed: %s", esp_err_to_name(err));
            return -1;
        }
        s_gpio_isr_service_installed = true;
    }

    /* Find or allocate ISR slot */
    int idx = -1;
    for (int i = 0; i < MAX_GPIO_ISR; i++) {
        if (s_gpio_isr[i].active && s_gpio_isr[i].pin == pin) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        for (int i = 0; i < MAX_GPIO_ISR; i++) {
            if (!s_gpio_isr[i].active) {
                idx = i;
                break;
            }
        }
    }
    if (idx < 0) {
        ESP_LOGE(TAG, "no free GPIO ISR slots");
        return -1;
    }

    s_gpio_isr[idx].pin = pin;
    s_gpio_isr[idx].handler_id = handler_id;
    s_gpio_isr[idx].active = true;

    gpio_set_intr_type((gpio_num_t)pin, intr);
    gpio_isr_handler_add((gpio_num_t)pin, gpio_isr_handler, (void *)(uintptr_t)idx);

    return 0;
}

int wendy_hal_gpio_clear_interrupt(int pin)
{
    for (int i = 0; i < MAX_GPIO_ISR; i++) {
        if (s_gpio_isr[i].active && s_gpio_isr[i].pin == pin) {
            gpio_isr_handler_remove((gpio_num_t)pin);
            gpio_set_intr_type((gpio_num_t)pin, GPIO_INTR_DISABLE);
            s_gpio_isr[i].active = false;
            return 0;
        }
    }
    return -1;
}

#endif /* CONFIG_WENDY_CALLBACK */
