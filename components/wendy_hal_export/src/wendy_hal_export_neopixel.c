#include "wendy_hal.h"
#include "wasm_export.h"
#include "esp_log.h"

/**
 * WASM host functions for NeoPixel (WS2812) LEDs.
 *
 *   (import "wendy" "neopixel_init"  (func (param i32 i32) (result i32)))
 *   (import "wendy" "neopixel_set"   (func (param i32 i32 i32 i32) (result i32)))
 *   (import "wendy" "neopixel_clear" (func (result i32)))
 */

static int neopixel_init_wrapper(wasm_exec_env_t exec_env,
                                  int pin, int num_leds)
{
    return wendy_hal_neopixel_init(pin, num_leds);
}

static int neopixel_set_wrapper(wasm_exec_env_t exec_env,
                                 int index, int r, int g, int b)
{
    return wendy_hal_neopixel_set(index, r, g, b);
}

static int neopixel_clear_wrapper(wasm_exec_env_t exec_env)
{
    return wendy_hal_neopixel_clear();
}

static NativeSymbol s_neopixel_symbols[] = {
    { "neopixel_init",  (void *)neopixel_init_wrapper,  "(ii)i",    NULL },
    { "neopixel_set",   (void *)neopixel_set_wrapper,   "(iiii)i",  NULL },
    { "neopixel_clear", (void *)neopixel_clear_wrapper, "()i",      NULL },
};

int wendy_hal_export_neopixel(void)
{
    if (!wasm_runtime_register_natives("wendy",
                                       s_neopixel_symbols,
                                       sizeof(s_neopixel_symbols) / sizeof(s_neopixel_symbols[0]))) {
        return -1;
    }
    return 0;
}
