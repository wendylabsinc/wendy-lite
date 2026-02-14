#include "wendy_hal.h"
#include "wasm_export.h"
#include "esp_log.h"

/**
 * WASM host functions for GPIO.
 *
 * Imported in WASM as:
 *   (import "wendy" "gpio_configure" (func (param i32 i32 i32) (result i32)))
 *   (import "wendy" "gpio_read"      (func (param i32) (result i32)))
 *   (import "wendy" "gpio_write"     (func (param i32 i32) (result i32)))
 *   (import "wendy" "gpio_set_pwm"   (func (param i32 i32 i32) (result i32)))
 */

static int gpio_configure_wrapper(wasm_exec_env_t exec_env,
                                   int pin, int mode, int pull)
{
    return wendy_hal_gpio_configure(pin, (wendy_gpio_mode_t)mode,
                                     (wendy_gpio_pull_t)pull);
}

static int gpio_read_wrapper(wasm_exec_env_t exec_env, int pin)
{
    return wendy_hal_gpio_read(pin);
}

static int gpio_write_wrapper(wasm_exec_env_t exec_env, int pin, int level)
{
    return wendy_hal_gpio_write(pin, level);
}

static int gpio_set_pwm_wrapper(wasm_exec_env_t exec_env,
                                 int pin, int freq_hz, int duty_pct)
{
    return wendy_hal_gpio_set_pwm(pin, (uint32_t)freq_hz, (uint8_t)duty_pct);
}

static NativeSymbol s_gpio_symbols[] = {
    { "gpio_configure", (void *)gpio_configure_wrapper, "(iii)i", NULL },
    { "gpio_read",      (void *)gpio_read_wrapper,      "(i)i",   NULL },
    { "gpio_write",     (void *)gpio_write_wrapper,      "(ii)i",  NULL },
    { "gpio_set_pwm",   (void *)gpio_set_pwm_wrapper,   "(iii)i", NULL },
};

int wendy_hal_export_gpio(void)
{
    if (!wasm_runtime_register_natives("wendy",
                                       s_gpio_symbols,
                                       sizeof(s_gpio_symbols) / sizeof(s_gpio_symbols[0]))) {
        return -1;
    }
    return 0;
}
