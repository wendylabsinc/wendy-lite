#include "wendy_wasm.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "esp_log.h"
#include "esp_partition.h"
#include "esp_heap_caps.h"

#include "wasm_export.h"

static const char *TAG = "wendy_wasm";

/* ── Internal module handle ─────────────────────────────────────────── */

struct wendy_wasm_module {
    wasm_module_t          wasm_module;
    wasm_module_inst_t     module_inst;
    wasm_exec_env_t        exec_env;
    wendy_wasm_state_t     state;
    uint8_t               *wasm_buf;      /* owned copy of WASM binary */
    uint32_t               wasm_len;
};

/* ── Runtime-global state ───────────────────────────────────────────── */

static bool s_initialized = false;
static wendy_wasm_config_t s_config;

/* ── Pre-allocated memory pool ─────────────────────────────────────── */

static uint8_t *s_pool_buf  = NULL;
static uint32_t s_pool_size = 0;

/* ── Current module tracking (for host functions) ──────────────────── */

static wendy_wasm_module_handle_t s_current_module_handle;

/* True between wendy_wasm_stop() and the matching wendy_wasm_run() returning.
 * Read by native dispatchers to avoid re-entering wasm after termination has
 * been requested. Re-entry would observe the "terminated by user" exception,
 * and if a dispatcher cleared it, the stop would be silently undone. */
static volatile bool s_terminate_requested = false;

bool wendy_wasm_is_terminating(void)
{
    return s_terminate_requested;
}

wendy_wasm_module_handle_t wendy_wasm_get_current_module(void)
{
    return s_current_module_handle;
}

void *wendy_wasm_get_current_exec_env(void)
{
    if (s_current_module_handle) {
        return s_current_module_handle->exec_env;
    }
    return NULL;
}

void *wendy_wasm_get_current_module_inst(void)
{
    if (s_current_module_handle) {
        return s_current_module_handle->module_inst;
    }
    return NULL;
}

/* ── Pre-allocate pool (call before WiFi/BLE init) ─────────────────── */

esp_err_t wendy_wasm_prealloc_pool(uint32_t pool_size)
{
    if (pool_size == 0) {
        // Caller opted out of pre-allocation. wendy_wasm_init() will fall
        // through to Alloc_With_System_Allocator, letting WAMR and the rest
        // of the system share the heap dynamically. This trades the hard
        // ceiling on guest memory for not pre-reserving a fixed chunk that
        // can starve the wifi DMA pool.
        ESP_LOGI(TAG, "pool prealloc skipped (pool_size=0); using system allocator");
        return ESP_OK;
    }

    if (s_pool_buf) {
        ESP_LOGW(TAG, "pool already allocated");
        return ESP_OK;
    }

#if CONFIG_SPIRAM && CONFIG_WENDY_WASM_USE_PSRAM
    const uint32_t caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
    const char *where = "PSRAM";
#else
    const uint32_t caps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
    const char *where = "internal SRAM";
#endif

    s_pool_buf = heap_caps_aligned_alloc(8, pool_size, caps);
    if (!s_pool_buf) {
        ESP_LOGE(TAG, "failed to pre-allocate %lu byte pool from %s",
                 (unsigned long)pool_size, where);
        return ESP_ERR_NO_MEM;
    }

    s_pool_size = pool_size;
    ESP_LOGI(TAG, "pre-allocated %lu byte WAMR pool from %s",
             (unsigned long)pool_size, where);
    return ESP_OK;
}

/* ── stdout / stderr redirect ───────────────────────────────────────── */

static wendy_wasm_output_cb_t s_output_cb;
static void *s_output_ctx;

/*
 * Native helper: WASM apps call this to write to stdout.
 * WAMR signature "*~" means the runtime auto-converts the pointer
 * and passes the buffer length, so buf is already a native pointer.
 */
static int wendy_print_wrapper(wasm_exec_env_t exec_env,
                                const char *buf, int len)
{
    if (!buf || len <= 0) {
        return -1;
    }
    if (s_output_cb) {
        s_output_cb(buf, (uint32_t)len, s_output_ctx);
    } else {
        fwrite(buf, 1, len, stdout);
        fflush(stdout);
    }
    return len;
}

static NativeSymbol s_builtin_symbols[] = {
    { "wendy_print", (void *)wendy_print_wrapper, "(*~)i", NULL },
};

/*
 * Stub for __stack_chk_fail – emitted by compilers with stack-smashing
 * protection (e.g. Swift Embedded).  Inside the WASM sandbox a stack
 * overflow is already contained, so we just trap.
 */
static void stack_chk_fail_wrapper(wasm_exec_env_t exec_env)
{
    ESP_LOGE(TAG, "WASM __stack_chk_fail – stack smashing detected, trapping");
    wasm_runtime_set_exception(wasm_runtime_get_module_inst(exec_env),
                               "stack smashing detected");
}

static int posix_memalign_wrapper(wasm_exec_env_t exec_env,
                                   void **memptr, int32_t align, int32_t size)
{
    /* 'memptr' is auto-translated by WAMR: it's a native ptr to a uint32_t
     * slot in WASM linear memory where we store the allocated WASM app addr.
     * Over-allocate by (align-1) to guarantee alignment. */
    if (align < (int32_t)sizeof(void *) || (align & (align - 1)) != 0)
        return 22; /* EINVAL */
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    void *native_ptr = NULL;
    uint32_t wasm_addr = wasm_runtime_module_malloc(
        inst, (uint32_t)size + (uint32_t)(align - 1), &native_ptr);
    if (wasm_addr == 0 || !native_ptr)
        return 12; /* ENOMEM */
    uintptr_t raw     = (uintptr_t)native_ptr;
    uintptr_t aligned = (raw + (uintptr_t)(align - 1)) & ~(uintptr_t)(align - 1);
    *(uint32_t *)memptr = wasm_addr + (uint32_t)(aligned - raw);
    return 0;
}

static NativeSymbol s_env_symbols[] = {
    { "__stack_chk_fail", (void *)stack_chk_fail_wrapper,  "()",     NULL },
    { "posix_memalign",   (void *)posix_memalign_wrapper,  "(*ii)i", NULL },
};

/* ── Public API ─────────────────────────────────────────────────────── */

esp_err_t wendy_wasm_init(const wendy_wasm_config_t *config)
{
    if (s_initialized) {
        ESP_LOGW(TAG, "already initialized");
        return ESP_OK;
    }

    s_config = *config;
    s_output_cb  = config->output_cb;
    s_output_ctx = config->output_ctx;

    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(init_args));

    if (s_pool_buf) {
        init_args.mem_alloc_type = Alloc_With_Pool;
        init_args.mem_alloc_option.pool.heap_buf  = s_pool_buf;
        init_args.mem_alloc_option.pool.heap_size = s_pool_size;
    } else {
        ESP_LOGI(TAG, "using system allocator (no pre-allocated pool)");
        init_args.mem_alloc_type = Alloc_With_System_Allocator;
    }

    if (!wasm_runtime_full_init(&init_args)) {
        ESP_LOGE(TAG, "wasm_runtime_full_init failed");
        return ESP_FAIL;
    }

    /* Register wendy_print via the same path as all other natives */
    if (!wasm_runtime_register_natives("wendy",
                                       s_builtin_symbols,
                                       sizeof(s_builtin_symbols) / sizeof(s_builtin_symbols[0]))) {
        ESP_LOGE(TAG, "failed to register builtin natives");
        return ESP_FAIL;
    }

    /* Register "env" module stubs (e.g. __stack_chk_fail for Swift Embedded) */
    if (!wasm_runtime_register_natives("env",
                                       s_env_symbols,
                                       sizeof(s_env_symbols) / sizeof(s_env_symbols[0]))) {
        ESP_LOGE(TAG, "failed to register env natives");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "WAMR runtime initialized (stack=%lu heap=%lu psram=%d)",
             (unsigned long)config->stack_size,
             (unsigned long)config->heap_size,
             config->use_psram);

    s_initialized = true;
    return ESP_OK;
}

esp_err_t wendy_wasm_load(const uint8_t *wasm_buf, uint32_t wasm_len,
                          wendy_wasm_module_handle_t *out)
{
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!wasm_buf || !wasm_len || !out) {
        return ESP_ERR_INVALID_ARG;
    }

    struct wendy_wasm_module *mod = calloc(1, sizeof(*mod));
    if (!mod) {
        return ESP_ERR_NO_MEM;
    }

    /* WAMR may modify the buffer, so keep an owned copy */
    mod->wasm_buf = wasm_runtime_malloc(wasm_len);
    if (!mod->wasm_buf) {
        free(mod);
        return ESP_ERR_NO_MEM;
    }
    memcpy(mod->wasm_buf, wasm_buf, wasm_len);
    mod->wasm_len = wasm_len;

    char error_buf[128] = { 0 };

    /* Load module */
    mod->wasm_module = wasm_runtime_load(mod->wasm_buf, wasm_len,
                                          error_buf, sizeof(error_buf));
    if (!mod->wasm_module) {
        ESP_LOGE(TAG, "load failed: %s", error_buf);
        wasm_runtime_free(mod->wasm_buf);
        free(mod);
        return ESP_FAIL;
    }

    /* Instantiate */
    ESP_LOGI(TAG, "free heap before instantiate: %lu internal, %lu total",
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_8BIT));
    mod->module_inst = wasm_runtime_instantiate(mod->wasm_module,
                                                 s_config.stack_size,
                                                 s_config.heap_size,
                                                 error_buf, sizeof(error_buf));
    if (!mod->module_inst) {
        ESP_LOGE(TAG, "instantiate failed: %s", error_buf);
        wasm_runtime_unload(mod->wasm_module);
        wasm_runtime_free(mod->wasm_buf);
        free(mod);
        return ESP_FAIL;
    }

    /* Create execution environment */
    mod->exec_env = wasm_runtime_create_exec_env(mod->module_inst,
                                                  s_config.stack_size);
    if (!mod->exec_env) {
        ESP_LOGE(TAG, "create exec_env failed");
        wasm_runtime_deinstantiate(mod->module_inst);
        wasm_runtime_unload(mod->wasm_module);
        wasm_runtime_free(mod->wasm_buf);
        free(mod);
        return ESP_FAIL;
    }

    mod->state = WENDY_WASM_STATE_LOADED;
    *out = mod;

    ESP_LOGI(TAG, "WASM module loaded (%lu bytes)", (unsigned long)wasm_len);
    return ESP_OK;
}

esp_err_t wendy_wasm_load_from_partition(const char *partition_label,
                                         wendy_wasm_module_handle_t *out)
{
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!out) {
        return ESP_ERR_INVALID_ARG;
    }

    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, 0x80, partition_label);
    if (!part) {
        part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x81, partition_label);
    }
    if (!part) {
        ESP_LOGE(TAG, "partition '%s' not found", partition_label);
        return ESP_ERR_NOT_FOUND;
    }

    /* Read the first 4 bytes to get the stored size */
    uint32_t wasm_len = 0;
    esp_err_t err = esp_partition_read(part, 0, &wasm_len, sizeof(wasm_len));
    if (err != ESP_OK || wasm_len == 0 || wasm_len > part->size - 4) {
        ESP_LOGE(TAG, "invalid WASM binary in partition (len=%lu)", (unsigned long)wasm_len);
        return ESP_ERR_INVALID_SIZE;
    }

    /* Allocate module handle and read directly into its wasm_buf
     * to avoid a temporary double-buffer (saves ~13KB on ESP32). */
    struct wendy_wasm_module *mod = calloc(1, sizeof(*mod));
    if (!mod) {
        return ESP_ERR_NO_MEM;
    }

    mod->wasm_buf = wasm_runtime_malloc(wasm_len);
    if (!mod->wasm_buf) {
        free(mod);
        return ESP_ERR_NO_MEM;
    }
    mod->wasm_len = wasm_len;

    err = esp_partition_read(part, 4, mod->wasm_buf, wasm_len);
    if (err != ESP_OK) {
        wasm_runtime_free(mod->wasm_buf);
        free(mod);
        return err;
    }

    char error_buf[128] = { 0 };

    mod->wasm_module = wasm_runtime_load(mod->wasm_buf, wasm_len,
                                          error_buf, sizeof(error_buf));
    if (!mod->wasm_module) {
        ESP_LOGE(TAG, "load failed: %s", error_buf);
        wasm_runtime_free(mod->wasm_buf);
        free(mod);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "free heap before instantiate: %lu internal, %lu total",
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_8BIT));
    mod->module_inst = wasm_runtime_instantiate(mod->wasm_module,
                                                 s_config.stack_size,
                                                 s_config.heap_size,
                                                 error_buf, sizeof(error_buf));
    if (!mod->module_inst) {
        ESP_LOGE(TAG, "instantiate failed: %s", error_buf);
        wasm_runtime_unload(mod->wasm_module);
        wasm_runtime_free(mod->wasm_buf);
        free(mod);
        return ESP_FAIL;
    }

    mod->exec_env = wasm_runtime_create_exec_env(mod->module_inst,
                                                  s_config.stack_size);
    if (!mod->exec_env) {
        ESP_LOGE(TAG, "create exec_env failed");
        wasm_runtime_deinstantiate(mod->module_inst);
        wasm_runtime_unload(mod->wasm_module);
        wasm_runtime_free(mod->wasm_buf);
        free(mod);
        return ESP_FAIL;
    }

    mod->state = WENDY_WASM_STATE_LOADED;
    *out = mod;

    ESP_LOGI(TAG, "WASM module loaded from partition '%s' (%lu bytes)",
             partition_label, (unsigned long)wasm_len);
    return ESP_OK;
}

esp_err_t wendy_wasm_run(wendy_wasm_module_handle_t module)
{
    if (!module || module->state != WENDY_WASM_STATE_LOADED) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Look for _start (WASI) or main */
    wasm_function_inst_t func = wasm_runtime_lookup_function(
        module->module_inst, "_start");
    if (!func) {
        func = wasm_runtime_lookup_function(module->module_inst, "main");
    }
    if (!func) {
        ESP_LOGE(TAG, "no _start or main function found");
        module->state = WENDY_WASM_STATE_ERROR;
        return ESP_ERR_NOT_FOUND;
    }

    /* Track current module for host function access */
    s_current_module_handle = module;
    s_terminate_requested = false;

    module->state = WENDY_WASM_STATE_RUNNING;
    ESP_LOGI(TAG, "executing WASM module...");

    if (!wasm_runtime_call_wasm(module->exec_env, func, 0, NULL)) {
        const char *exc = wasm_runtime_get_exception(module->module_inst);
        ESP_LOGE(TAG, "execution failed: %s", exc ? exc : "unknown");
        module->state = WENDY_WASM_STATE_ERROR;
        s_current_module_handle = NULL;
        return ESP_FAIL;
    }

    s_current_module_handle = NULL;
    module->state = WENDY_WASM_STATE_STOPPED;
    ESP_LOGI(TAG, "WASM module finished");
    return ESP_OK;
}

esp_err_t wendy_wasm_stop(wendy_wasm_module_handle_t module)
{
    if (!module) {
        return ESP_ERR_INVALID_ARG;
    }
    if (module->state == WENDY_WASM_STATE_RUNNING) {
        // Set the flag before issuing terminate so any dispatcher that wakes
        // between these two calls already knows not to enter wasm.
        s_terminate_requested = true;
        wasm_runtime_terminate(module->module_inst);
        module->state = WENDY_WASM_STATE_STOPPED;
    }
    return ESP_OK;
}

void wendy_wasm_unload(wendy_wasm_module_handle_t module)
{
    if (!module) {
        return;
    }
    if (module->state == WENDY_WASM_STATE_RUNNING) {
        wendy_wasm_stop(module);
    }
    if (s_current_module_handle == module) {
        s_current_module_handle = NULL;
    }
    if (module->exec_env) {
        wasm_runtime_destroy_exec_env(module->exec_env);
    }
    if (module->module_inst) {
        wasm_runtime_deinstantiate(module->module_inst);
    }
    if (module->wasm_module) {
        wasm_runtime_unload(module->wasm_module);
    }
    if (module->wasm_buf) {
        wasm_runtime_free(module->wasm_buf);
    }
    free(module);
}

wendy_wasm_state_t wendy_wasm_get_state(wendy_wasm_module_handle_t module)
{
    return module ? module->state : WENDY_WASM_STATE_IDLE;
}

esp_err_t wendy_wasm_get_mem_stats(wendy_wasm_module_handle_t module,
                                    wendy_wasm_mem_stats_t *stats)
{
    if (!module || !stats || !module->module_inst) {
        return ESP_ERR_INVALID_ARG;
    }

    /* WAMR doesn't expose per-module heap usage via public API.
     * Report the configured sizes as baseline. */
    stats->heap_total = s_config.heap_size;
    stats->heap_used  = 0;
    stats->stack_peak = 0;

    return ESP_OK;
}

void wendy_wasm_deinit(void)
{
    if (s_initialized) {
        s_current_module_handle = NULL;
        wasm_runtime_destroy();
        s_initialized = false;
        ESP_LOGI(TAG, "WAMR runtime destroyed");
    }
}

esp_err_t wendy_wasm_reinit(void)
{
    wendy_wasm_deinit();
    return wendy_wasm_init(&s_config);
}
