// wasm_export.h — stub replacing WAMR's wasm_export.h in the WasmKit build.
//
// Existing component source files (wendy_uart.c, wendy_sys.c, etc.) include
// this header.  With WAMR removed, we provide the minimum type definitions so
// those files compile.  The WAMR-specific functions are stubbed out; they are
// only called from the now-unused WAMR registration paths.
//
// The public `wendy_*_guest_*` wrappers pass NULL as exec_env, so none of the
// translate/validate functions are reached at runtime.

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── Opaque handle types ───────────────────────────────────────────────────────

typedef void *wasm_module_t;
typedef void *wasm_module_inst_t;
typedef void *wasm_exec_env_t;
typedef void *wasm_function_inst_t;

// ── NativeSymbol (used in existing registration arrays) ───────────────────────

typedef struct NativeSymbol {
    const char *symbol;
    void       *func_ptr;
    const char *signature;
    void       *attachment;
} NativeSymbol;

// ── Stub API — all return false/NULL/0 ───────────────────────────────────────

static inline bool wasm_runtime_register_natives(
    const char *module_name, NativeSymbol *native_symbols, uint32_t n_native_symbols)
{
    (void)module_name; (void)native_symbols; (void)n_native_symbols;
    return true; // pretend success; registration is a no-op in WasmKit backend
}

static inline wasm_module_inst_t wasm_runtime_get_module_inst(wasm_exec_env_t exec_env)
{
    (void)exec_env;
    return NULL;
}

static inline bool wasm_runtime_validate_app_addr(
    wasm_module_inst_t module_inst, uint32_t app_offset, uint32_t size)
{
    (void)module_inst; (void)app_offset; (void)size;
    return true;
}

static inline void *wasm_runtime_addr_app_to_native(
    wasm_module_inst_t module_inst, uint32_t app_offset)
{
    (void)module_inst; (void)app_offset;
    return NULL; // caller must not use the result; WasmKit translates in Swift
}

static inline wasm_function_inst_t wasm_runtime_lookup_function(
    wasm_module_inst_t module_inst, const char *name)
{
    (void)module_inst; (void)name;
    return NULL;
}

static inline bool wasm_runtime_call_wasm(
    wasm_exec_env_t exec_env, wasm_function_inst_t func,
    uint32_t argc, uint32_t argv[])
{
    (void)exec_env; (void)func; (void)argc; (void)argv;
    return false;
}

static inline const char *wasm_runtime_get_exception(wasm_module_inst_t module_inst)
{
    (void)module_inst;
    return NULL;
}

static inline void wasm_runtime_clear_exception(wasm_module_inst_t module_inst)
{
    (void)module_inst;
}

static inline void wasm_runtime_terminate(wasm_module_inst_t module_inst)
{
    (void)module_inst;
}

static inline uint32_t wasm_runtime_module_malloc(
    wasm_module_inst_t module_inst, uint32_t size, void **p_native_addr)
{
    (void)module_inst; (void)size; (void)p_native_addr;
    return 0;
}

static inline void wasm_runtime_module_free(
    wasm_module_inst_t module_inst, uint32_t ptr)
{
    (void)module_inst; (void)ptr;
}

static inline void *wasm_runtime_malloc(uint32_t size) { (void)size; return NULL; }
static inline void  wasm_runtime_free(void *ptr) { (void)ptr; }

#ifdef __cplusplus
}
#endif
