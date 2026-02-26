#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * WASM application state.
 */
typedef enum {
    WENDY_WASM_STATE_IDLE,
    WENDY_WASM_STATE_LOADED,
    WENDY_WASM_STATE_RUNNING,
    WENDY_WASM_STATE_STOPPED,
    WENDY_WASM_STATE_ERROR,
} wendy_wasm_state_t;

/**
 * Callback for WASM stdout/stderr output.
 */
typedef void (*wendy_wasm_output_cb_t)(const char *data, uint32_t len, void *ctx);

/**
 * WASM runtime configuration.
 */
typedef struct {
    uint32_t stack_size;        /**< WASM execution stack size */
    uint32_t heap_size;         /**< WASM application heap size */
    bool use_psram;             /**< Allocate heap from PSRAM when available */
    wendy_wasm_output_cb_t output_cb;  /**< stdout/stderr callback */
    void *output_ctx;           /**< Context passed to output callback */
} wendy_wasm_config_t;

/**
 * Handle to a loaded WASM module.
 */
typedef struct wendy_wasm_module *wendy_wasm_module_handle_t;

/**
 * Default configuration macro.
 */
#define WENDY_WASM_CONFIG_DEFAULT() { \
    .stack_size = CONFIG_WENDY_WASM_STACK_SIZE, \
    .heap_size  = CONFIG_WENDY_WASM_HEAP_SIZE, \
    .use_psram  = true, \
    .output_cb  = NULL, \
    .output_ctx = NULL, \
}

/**
 * Initialize the WASM runtime. Must be called once at boot.
 */
esp_err_t wendy_wasm_init(const wendy_wasm_config_t *config);

/**
 * Load a WASM binary from a buffer.
 *
 * @param wasm_buf  Pointer to the WASM binary data
 * @param wasm_len  Length of the WASM binary
 * @param out       Handle to the loaded module
 * @return ESP_OK on success
 */
esp_err_t wendy_wasm_load(const uint8_t *wasm_buf, uint32_t wasm_len,
                          wendy_wasm_module_handle_t *out);

/**
 * Load a WASM binary from a flash partition.
 *
 * @param partition_label  NVS partition label (e.g., "wasm_a")
 * @param out              Handle to the loaded module
 * @return ESP_OK on success
 */
esp_err_t wendy_wasm_load_from_partition(const char *partition_label,
                                         wendy_wasm_module_handle_t *out);

/**
 * Run a loaded WASM module. Blocks until the module's main() returns or
 * wendy_wasm_stop() is called from another task.
 *
 * @param module  Handle from wendy_wasm_load()
 * @return ESP_OK if main() returned 0
 */
esp_err_t wendy_wasm_run(wendy_wasm_module_handle_t module);

/**
 * Stop a running WASM module.
 */
esp_err_t wendy_wasm_stop(wendy_wasm_module_handle_t module);

/**
 * Unload a WASM module and free all associated resources.
 */
void wendy_wasm_unload(wendy_wasm_module_handle_t module);

/**
 * Query the current state of a module.
 */
wendy_wasm_state_t wendy_wasm_get_state(wendy_wasm_module_handle_t module);

/**
 * Get runtime memory statistics.
 */
typedef struct {
    uint32_t heap_total;
    uint32_t heap_used;
    uint32_t stack_peak;
} wendy_wasm_mem_stats_t;

esp_err_t wendy_wasm_get_mem_stats(wendy_wasm_module_handle_t module,
                                    wendy_wasm_mem_stats_t *stats);

/**
 * Get the currently running WASM module handle.
 * Returns NULL if no module is running.
 */
wendy_wasm_module_handle_t wendy_wasm_get_current_module(void);

/**
 * Get the current WAMR execution environment (wasm_exec_env_t).
 * Returns NULL if no module is running. Cast to wasm_exec_env_t.
 */
void *wendy_wasm_get_current_exec_env(void);

/**
 * Get the current WAMR module instance (wasm_module_inst_t).
 * Returns NULL if no module is running. Cast to wasm_module_inst_t.
 */
void *wendy_wasm_get_current_module_inst(void);

/**
 * Shut down the WASM runtime entirely.
 */
void wendy_wasm_deinit(void);

/**
 * Destroy and reinitialize the WASM runtime.
 * Clears all internal WAMR state. Native symbols must be re-registered after.
 */
esp_err_t wendy_wasm_reinit(void);

#ifdef __cplusplus
}
#endif
