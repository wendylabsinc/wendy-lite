#include "wendy_hal.h"
#include "wasm_export.h"

/**
 * WASM host functions for Timer.
 *
 * Imported in WASM as:
 *   (import "wendy" "timer_delay_ms" (func (param i32)))
 *   (import "wendy" "timer_millis"   (func (result i64)))
 */

static void timer_delay_ms_wrapper(wasm_exec_env_t exec_env, int ms)
{
    wendy_hal_timer_delay_ms((uint32_t)ms);
}

static int64_t timer_millis_wrapper(wasm_exec_env_t exec_env)
{
    return (int64_t)wendy_hal_timer_millis();
}

static NativeSymbol s_timer_symbols[] = {
    { "timer_delay_ms", (void *)timer_delay_ms_wrapper, "(i)",  NULL },
    { "timer_millis",   (void *)timer_millis_wrapper,   "()I",  NULL },
};

int wendy_hal_export_timer(void)
{
    if (!wasm_runtime_register_natives("wendy",
                                       s_timer_symbols,
                                       sizeof(s_timer_symbols) / sizeof(s_timer_symbols[0]))) {
        return -1;
    }
    return 0;
}
