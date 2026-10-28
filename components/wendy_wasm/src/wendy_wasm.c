#include "wendy_wasm.h"
#include "memory_limit.h"
#include "linear_replacement.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "esp_log.h"
#include "esp_partition.h"
#include "esp_heap_caps.h"

#include "wasm_export.h"

#ifndef CONFIG_WENDY_WASM_MAX_MEMORY_PAGES
#define CONFIG_WENDY_WASM_MAX_MEMORY_PAGES 0
#endif


static const char *TAG = "wendy_wasm";

/* ── Internal module handle ─────────────────────────────────────────── */

struct wendy_wasm_module {
    wasm_module_t          wasm_module;
    wasm_module_inst_t     module_inst;
    wasm_exec_env_t        exec_env;
    wendy_wasm_state_t     state;
    uint8_t               *wasm_buf;      /* owned binary or mapped AOT XIP */
    uint32_t               wasm_len;
    esp_partition_mmap_handle_t flash_mapping;
    bool                   mapped;
};

static void release_module_bytes(struct wendy_wasm_module *mod)
{
    if(mod->mapped)esp_partition_munmap(mod->flash_mapping);
    else if(mod->wasm_buf)wasm_runtime_free(mod->wasm_buf);
    mod->wasm_buf=NULL;mod->mapped=false;
}

/* ── Runtime-global state ───────────────────────────────────────────── */

static bool s_initialized = false;
static wendy_wasm_config_t s_config;

#if CONFIG_SPIRAM && CONFIG_WENDY_WASM_USE_PSRAM
/* Small per-function metadata must follow the guest into PSRAM too. The
 * system allocator's size threshold otherwise leaves it in scarce SRAM. */
static void *psram_preferred_malloc(unsigned int size)
{
    return heap_caps_malloc_prefer(size,2,MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                   MALLOC_CAP_8BIT);
}
static void *psram_preferred_realloc(void *pointer,unsigned int size)
{
    return heap_caps_realloc_prefer(pointer,size,2,
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,MALLOC_CAP_8BIT);
}
#elif CONFIG_WENDY_WASM_PREFER_RTC_RAM
/* Interpreter code, operand stacks and metadata do not require DMA. The SDK
 * default allocator uses main SRAM first, even when the RTC heap is idle.
 * Preserve ordinary realloc/free semantics and fall back for larger blocks. */
static void *rtc_preferred_malloc(unsigned int size)
{
    return heap_caps_malloc_prefer(size,2,MALLOC_CAP_RTCRAM | MALLOC_CAP_8BIT,
                                   MALLOC_CAP_8BIT);
}
static void *rtc_preferred_realloc(void *pointer,unsigned int size)
{
    return heap_caps_realloc_prefer(pointer,size,2,
        MALLOC_CAP_RTCRAM | MALLOC_CAP_8BIT,MALLOC_CAP_8BIT);
}
#endif

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

/* Translate 64 KiB policy units to WAMR's actual memory dimensions. AOT can
 * coalesce fixed linear storage into one large page, and instantiate_ex alone
 * floors a too-small page override back to the module's initial size. */
static wasm_module_inst_t instantiate(struct wendy_wasm_module *mod,
                                     char *error,uint32_t error_size)
{
    uint32_t max_pages;
    if(!wendy_wasm_memory_limit(mod->wasm_buf,mod->wasm_len,
        CONFIG_WENDY_WASM_MAX_MEMORY_PAGES,s_config.heap_size,&max_pages,error,error_size))return NULL;
    InstantiationArgs args={.default_stack_size=s_config.stack_size,
        .host_managed_heap_size=s_config.heap_size,.max_memory_pages=max_pages};
    wasm_module_inst_t instance=wasm_runtime_instantiate_ex(mod->wasm_module,&args,error,error_size);
    if(instance && CONFIG_WENDY_WASM_MAX_MEMORY_PAGES){
        uint64_t cap=(uint64_t)CONFIG_WENDY_WASM_MAX_MEMORY_PAGES*65536;
        uint64_t initial=0,maximum=0;
        for(uint32_t i=0;;i++){
            wasm_memory_inst_t memory=wasm_runtime_get_memory(instance,i);if(!memory)break;
            uint64_t page_bytes=wasm_memory_get_bytes_per_page(memory);
            initial+=page_bytes*wasm_memory_get_cur_page_count(memory);
            maximum+=page_bytes*wasm_memory_get_max_page_count(memory);
        }
        if(initial>cap || maximum>cap){
            snprintf(error,error_size,"runtime linear memory exceeds configured limit");
            wasm_runtime_deinstantiate(instance);return NULL;
        }
        ESP_LOGI(TAG,"linear memory bound: initial=%llu max=%llu cap=%llu bytes",
            (unsigned long long)initial,(unsigned long long)maximum,(unsigned long long)cap);
    }
    return instance;
}

/* Reuse is scoped to an explicitly stopped single main-module replacement.
 * It holds no allocation at boot, while idle or after an APP_START result. */
uint32_t wendy_wasm_replacement_begin(wendy_wasm_module_handle_t module)
{
#if CONFIG_SPIRAM && CONFIG_WENDY_WASM_USE_PSRAM && !CONFIG_WAMR_ENABLE_MULTI_MODULE
    if (!s_config.use_psram || s_pool_buf || !module || !module->module_inst ||
        module->state == WENDY_WASM_STATE_RUNNING ||
        wasm_runtime_get_memory(module->module_inst, 1)) return 0;
    wasm_memory_inst_t memory = wasm_runtime_get_memory(module->module_inst, 0);
    if (!memory || wasm_memory_get_shared(memory)) return 0;
    return wwlr_begin(wasm_memory_get_base_address(memory));
#else
    (void)module;
    return 0;
#endif
}

void wendy_wasm_replacement_finish(uint32_t generation)
{
    wwlr_finish(generation);
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

static NativeSymbol s_env_symbols[] = {
    { "__stack_chk_fail", (void *)stack_chk_fail_wrapper, "()", NULL },
};

/* ── Public API ─────────────────────────────────────────────────────── */

esp_err_t wendy_wasm_init(const wendy_wasm_config_t *config)
{
    if (s_initialized) {
        ESP_LOGW(TAG, "already initialized");
        return ESP_OK;
    }

#if CONFIG_WENDY_WASM_MAX_MEMORY_PAGES && CONFIG_WAMR_ENABLE_MULTI_MODULE
    /* WAMR forwards one per-memory limit to each dependency, not a shared
     * aggregate budget. This product has no bounded submodule allocator yet. */
    ESP_LOGE(TAG,"bounded linear memory requires multi-module support disabled");
    return ESP_ERR_NOT_SUPPORTED;
#endif
    if (!config) return ESP_ERR_INVALID_ARG;
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
#if CONFIG_SPIRAM && CONFIG_WENDY_WASM_USE_PSRAM
        init_args.mem_alloc_type = s_config.use_psram ? Alloc_With_Allocator
                                                    : Alloc_With_System_Allocator;
        init_args.mem_alloc_option.allocator.malloc_func = psram_preferred_malloc;
        init_args.mem_alloc_option.allocator.realloc_func = psram_preferred_realloc;
        init_args.mem_alloc_option.allocator.free_func = heap_caps_free;
        ESP_LOGI(TAG, "using %s runtime allocator: internal_free=%u",
            s_config.use_psram ? "PSRAM-preferred" : "system",
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
#elif CONFIG_WENDY_WASM_PREFER_RTC_RAM
        init_args.mem_alloc_type = Alloc_With_Allocator;
        init_args.mem_alloc_option.allocator.malloc_func = rtc_preferred_malloc;
        init_args.mem_alloc_option.allocator.realloc_func = rtc_preferred_realloc;
        init_args.mem_alloc_option.allocator.free_func = heap_caps_free;
        ESP_LOGI(TAG,"using RTC-preferred runtime allocator: rtc_free=%u dma_free=%u",
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_RTCRAM | MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA));
#else
        ESP_LOGI(TAG, "using system allocator (no pre-allocated pool)");
        init_args.mem_alloc_type = Alloc_With_System_Allocator;
#endif
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
        release_module_bytes(mod);
        free(mod);
        return ESP_FAIL;
    }

    /* Instantiate */
    ESP_LOGI(TAG, "free heap before instantiate: %lu internal, %lu total, %lu largest",
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_8BIT),
             (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    mod->module_inst = instantiate(mod,error_buf,sizeof error_buf);
    if (!mod->module_inst) {
        ESP_LOGE(TAG, "instantiate failed: %s", error_buf);
        wasm_runtime_unload(mod->wasm_module);
        release_module_bytes(mod);
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
        release_module_bytes(mod);
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

    if (part->size < sizeof(uint32_t)) return ESP_ERR_INVALID_SIZE;

    /* Read the first 4 bytes to get the stored size */
    uint32_t wasm_len = 0;
    esp_err_t err = esp_partition_read(part, 0, &wasm_len, sizeof(wasm_len));
    if (err != ESP_OK || part->size < 4 || wasm_len == 0 || wasm_len > part->size - 4) {
        ESP_LOGE(TAG, "invalid WASM binary in partition (len=%lu)", (unsigned long)wasm_len);
        return ESP_ERR_INVALID_SIZE;
    }

    /* Allocate module handle and read directly into its wasm_buf
     * to avoid a temporary double-buffer (saves ~13KB on ESP32). */
    struct wendy_wasm_module *mod = calloc(1, sizeof(*mod));
    if (!mod) {
        return ESP_ERR_NO_MEM;
    }

    mod->wasm_len = wasm_len;
#if CONFIG_WENDY_WASM_AOT_XIP
    const void *mapping=NULL;
    err=esp_partition_mmap(part,0,wasm_len+4,ESP_PARTITION_MMAP_INST,
                           &mapping,&mod->flash_mapping);
    if (err == ESP_OK) {
        mod->mapped = true;
        mod->wasm_buf = (uint8_t *)mapping + 4;
        if (!wasm_runtime_is_xip_file(mod->wasm_buf, wasm_len))
            release_module_bytes(mod);
        else
            ESP_LOGI(TAG, "AOT XIP module mapped from flash: bytes=%lu address=%p",
                     (unsigned long)wasm_len, mod->wasm_buf);
    }
    /* Mapping may be unavailable (or the guest may be bytecode). Preserve the
     * writable partition loader in either case. */
#endif
    if(!mod->mapped){
        mod->wasm_buf=wasm_runtime_malloc(wasm_len);
        if(!mod->wasm_buf){free(mod);return ESP_ERR_NO_MEM;}
        err=esp_partition_read(part,4,mod->wasm_buf,wasm_len);
        if(err!=ESP_OK){release_module_bytes(mod);free(mod);return err;}
    }

    char error_buf[128] = { 0 };

    mod->wasm_module = wasm_runtime_load(mod->wasm_buf, wasm_len,
                                          error_buf, sizeof(error_buf));
    if (!mod->wasm_module) {
        ESP_LOGE(TAG, "load failed: %s", error_buf);
        release_module_bytes(mod);
        free(mod);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "free heap before instantiate: %lu internal, %lu total, %lu largest",
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_8BIT),
             (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    mod->module_inst = instantiate(mod,error_buf,sizeof error_buf);
    if (!mod->module_inst) {
        ESP_LOGE(TAG, "instantiate failed: %s", error_buf);
        wasm_runtime_unload(mod->wasm_module);
        release_module_bytes(mod);
        free(mod);
        return ESP_FAIL;
    }

    mod->exec_env = wasm_runtime_create_exec_env(mod->module_inst,
                                                  s_config.stack_size);
    if (!mod->exec_env) {
        ESP_LOGE(TAG, "create exec_env failed");
        wasm_runtime_deinstantiate(mod->module_inst);
        wasm_runtime_unload(mod->wasm_module);
        release_module_bytes(mod);
        free(mod);
        return ESP_FAIL;
    }

    mod->state = WENDY_WASM_STATE_LOADED;
    *out = mod;

    ESP_LOGI(TAG, "WASM module loaded from partition '%s' (%lu bytes)",
             partition_label, (unsigned long)wasm_len);
#if CONFIG_WENDY_WASM_PREFER_RTC_RAM
    ESP_LOGI(TAG,"runtime placement: rtc_free=%u dma_free=%u largest_dma=%u",
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_RTCRAM | MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA));
#endif
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
        release_module_bytes(module);
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
