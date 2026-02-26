#include "wendy_hal.h"
#include "wasm_export.h"
#include "esp_log.h"

/**
 * WASM host functions for I2C.
 *
 *   (import "wendy" "i2c_init"       (func (param i32 i32 i32 i32) (result i32)))
 *   (import "wendy" "i2c_scan"       (func (param i32 i32 i32) (result i32)))
 *   (import "wendy" "i2c_write"      (func (param i32 i32 i32 i32) (result i32)))
 *   (import "wendy" "i2c_read"       (func (param i32 i32 i32 i32) (result i32)))
 *   (import "wendy" "i2c_write_read" (func (param i32 i32 i32 i32 i32 i32) (result i32)))
 */

static int i2c_init_wrapper(wasm_exec_env_t exec_env,
                             int bus, int sda, int scl, int freq)
{
    return wendy_hal_i2c_init(bus, sda, scl, (uint32_t)freq);
}

static int i2c_scan_wrapper(wasm_exec_env_t exec_env,
                             int bus, uint32_t addrs_offset, int max_addrs)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    if (!wasm_runtime_validate_app_addr(inst, addrs_offset, max_addrs)) {
        return -1;
    }
    uint8_t *native_addrs = wasm_runtime_addr_app_to_native(inst, addrs_offset);
    return wendy_hal_i2c_scan(bus, native_addrs, max_addrs);
}

static int i2c_write_wrapper(wasm_exec_env_t exec_env,
                              int bus, int addr, uint32_t data_offset, int len)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    if (!wasm_runtime_validate_app_addr(inst, data_offset, len)) {
        return -1;
    }
    const uint8_t *native_data = wasm_runtime_addr_app_to_native(inst, data_offset);
    return wendy_hal_i2c_write(bus, (uint8_t)addr, native_data, len);
}

static int i2c_read_wrapper(wasm_exec_env_t exec_env,
                             int bus, int addr, uint32_t buf_offset, int len)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    if (!wasm_runtime_validate_app_addr(inst, buf_offset, len)) {
        return -1;
    }
    uint8_t *native_buf = wasm_runtime_addr_app_to_native(inst, buf_offset);
    return wendy_hal_i2c_read(bus, (uint8_t)addr, native_buf, len);
}

static int i2c_write_read_wrapper(wasm_exec_env_t exec_env,
                                   int bus, int addr,
                                   uint32_t wr_offset, int wr_len,
                                   uint32_t rd_offset, int rd_len)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    if (!wasm_runtime_validate_app_addr(inst, wr_offset, wr_len) ||
        !wasm_runtime_validate_app_addr(inst, rd_offset, rd_len)) {
        return -1;
    }
    const uint8_t *wr_data = wasm_runtime_addr_app_to_native(inst, wr_offset);
    uint8_t *rd_buf        = wasm_runtime_addr_app_to_native(inst, rd_offset);
    return wendy_hal_i2c_write_read(bus, (uint8_t)addr,
                                     wr_data, wr_len, rd_buf, rd_len);
}

static NativeSymbol s_i2c_symbols[] = {
    { "i2c_init",       (void *)i2c_init_wrapper,       "(iiii)i",      NULL },
    { "i2c_scan",       (void *)i2c_scan_wrapper,       "(iii)i",       NULL },
    { "i2c_write",      (void *)i2c_write_wrapper,      "(iiii)i",      NULL },
    { "i2c_read",       (void *)i2c_read_wrapper,       "(iiii)i",      NULL },
    { "i2c_write_read", (void *)i2c_write_read_wrapper, "(iiiiii)i",    NULL },
};

int wendy_hal_export_i2c(void)
{
    if (!wasm_runtime_register_natives("wendy",
                                       s_i2c_symbols,
                                       sizeof(s_i2c_symbols) / sizeof(s_i2c_symbols[0]))) {
        return -1;
    }
    return 0;
}
