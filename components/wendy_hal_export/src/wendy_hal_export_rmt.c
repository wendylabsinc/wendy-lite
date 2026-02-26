#include "wendy_hal.h"
#include "wasm_export.h"
#include "esp_log.h"

/**
 * WASM host functions for RMT timing-buffer API.
 *
 *   (import "wendy" "rmt_configure" (func (param i32 i32) (result i32)))
 *   (import "wendy" "rmt_transmit"  (func (param i32 i32 i32) (result i32)))
 *   (import "wendy" "rmt_release"   (func (param i32) (result i32)))
 */

static int rmt_configure_wrapper(wasm_exec_env_t exec_env,
                                  int pin, int resolution_hz)
{
    return wendy_hal_rmt_configure(pin, resolution_hz);
}

static int rmt_transmit_wrapper(wasm_exec_env_t exec_env,
                                 int channel_id, const unsigned char *buf, int len)
{
    return wendy_hal_rmt_transmit(channel_id, buf, len);
}

static int rmt_release_wrapper(wasm_exec_env_t exec_env, int channel_id)
{
    return wendy_hal_rmt_release(channel_id);
}

static NativeSymbol s_rmt_symbols[] = {
    { "rmt_configure", (void *)rmt_configure_wrapper, "(ii)i",   NULL },
    { "rmt_transmit",  (void *)rmt_transmit_wrapper,  "(i*~)i",  NULL },
    { "rmt_release",   (void *)rmt_release_wrapper,   "(i)i",    NULL },
};

int wendy_hal_export_rmt(void)
{
    if (!wasm_runtime_register_natives("wendy",
                                       s_rmt_symbols,
                                       sizeof(s_rmt_symbols) / sizeof(s_rmt_symbols[0]))) {
        return -1;
    }
    return 0;
}
