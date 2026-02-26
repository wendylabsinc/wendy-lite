#include "wendy_hal.h"
#include "wasm_export.h"

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#endif

/**
 * WASM host functions for Timer.
 *
 *   (import "wendy" "timer_delay_ms"    (func (param i32)))
 *   (import "wendy" "timer_millis"      (func (result i64)))
 *   (import "wendy" "timer_set_timeout" (func (param i32 i32) (result i32)))
 *   (import "wendy" "timer_set_interval"(func (param i32 i32) (result i32)))
 *   (import "wendy" "timer_cancel"      (func (param i32) (result i32)))
 */

static void timer_delay_ms_wrapper(wasm_exec_env_t exec_env, int ms)
{
    wendy_hal_timer_delay_ms((uint32_t)ms);
}

static int64_t timer_millis_wrapper(wasm_exec_env_t exec_env)
{
    return (int64_t)wendy_hal_timer_millis();
}

/* ── Callback-based timer functions ─────────────────────────────────── */

#if CONFIG_WENDY_CALLBACK

static void timeout_cb(void *arg)
{
    uint32_t handler_id = (uint32_t)(uintptr_t)arg;
    wendy_callback_post(handler_id, 0, 0, 0);
}

static void interval_cb(void *arg)
{
    uint32_t handler_id = (uint32_t)(uintptr_t)arg;
    wendy_callback_post(handler_id, 0, 0, 0);
}

/* timer_set_timeout(ms, handler_id) -> timer_id */
static int timer_set_timeout_wrapper(wasm_exec_env_t exec_env,
                                      int ms, int handler_id)
{
    return wendy_hal_timer_schedule((uint32_t)ms, timeout_cb,
                                    (void *)(uintptr_t)handler_id);
}

/* timer_set_interval(ms, handler_id) -> timer_id */
static int timer_set_interval_wrapper(wasm_exec_env_t exec_env,
                                       int ms, int handler_id)
{
    return wendy_hal_timer_schedule_interval((uint32_t)ms, interval_cb,
                                              (void *)(uintptr_t)handler_id);
}

/* timer_cancel(timer_id) -> 0 ok */
static int timer_cancel_wrapper(wasm_exec_env_t exec_env, int timer_id)
{
    return wendy_hal_timer_cancel(timer_id);
}

#endif /* CONFIG_WENDY_CALLBACK */

static NativeSymbol s_timer_symbols[] = {
    { "timer_delay_ms",    (void *)timer_delay_ms_wrapper,    "(i)",   NULL },
    { "timer_millis",      (void *)timer_millis_wrapper,      "()I",   NULL },
#if CONFIG_WENDY_CALLBACK
    { "timer_set_timeout", (void *)timer_set_timeout_wrapper, "(ii)i", NULL },
    { "timer_set_interval",(void *)timer_set_interval_wrapper,"(ii)i", NULL },
    { "timer_cancel",      (void *)timer_cancel_wrapper,      "(i)i",  NULL },
#endif
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
