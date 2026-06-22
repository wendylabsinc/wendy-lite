// wendy_wasm_stub.c — no-op WASM runtime used when WasmKit / Swift are absent.
//
// Compiled instead of the Swift runtime when:
//   • the build target is not esp32c6, or
//   • WasmKit sources are not present at WASMKIT_ROOT, or
//   • no Swift compiler is found.
//
// All wendy_wasm_* functions return ESP_ERR_NOT_SUPPORTED (or safe no-ops) so
// the rest of the firmware links and boots normally; WASM apps simply won't run.

#include "wendy_wasm.h"
#include "esp_log.h"

static const char *TAG = "wendy_wasm";

esp_err_t wendy_wasm_prealloc_pool(uint32_t pool_size)   { return ESP_OK; }

esp_err_t wendy_wasm_init(const wendy_wasm_config_t *config) {
    ESP_LOGW(TAG, "WASM runtime not available (WasmKit/Swift not built)");
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t wendy_wasm_load(const uint8_t *buf, uint32_t len,
                          wendy_wasm_module_handle_t *out) {
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t wendy_wasm_load_from_partition(const char *label,
                                         wendy_wasm_module_handle_t *out) {
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t wendy_wasm_run(wendy_wasm_module_handle_t module)  { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t wendy_wasm_stop(wendy_wasm_module_handle_t module) { return ESP_OK; }
bool      wendy_wasm_is_terminating(void)                    { return false; }
void      wendy_wasm_unload(wendy_wasm_module_handle_t module) {}

wendy_wasm_state_t wendy_wasm_get_state(wendy_wasm_module_handle_t module) {
    return WENDY_WASM_STATE_IDLE;
}

esp_err_t wendy_wasm_get_mem_stats(wendy_wasm_module_handle_t module,
                                    wendy_wasm_mem_stats_t *stats) {
    if (stats) { stats->heap_total = 0; stats->heap_used = 0; stats->stack_peak = 0; }
    return ESP_ERR_NOT_SUPPORTED;
}

wendy_wasm_module_handle_t wendy_wasm_get_current_module(void)   { return NULL; }
void *wendy_wasm_get_current_exec_env(void)                      { return NULL; }
void *wendy_wasm_get_current_module_inst(void)                   { return NULL; }
void  wendy_wasm_deinit(void)                                    {}
esp_err_t wendy_wasm_reinit(void)                                { return ESP_ERR_NOT_SUPPORTED; }
