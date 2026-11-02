/* Exercise the production owned and partition loaders with the real WAMR
 * loader, including its in-place import-name edits. No device SDK required. */
#include "wasm_export.h"
#include "memory_limit.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int esp_err_t;
typedef unsigned wendy_wasm_state_t;
typedef unsigned esp_partition_mmap_handle_t;
typedef struct {
    uint32_t size;
} esp_partition_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_STATE -2
#define ESP_ERR_INVALID_ARG -3
#define ESP_ERR_NOT_FOUND -4
#define ESP_ERR_INVALID_SIZE -5
#define ESP_ERR_NO_MEM -6
#define ESP_PARTITION_TYPE_DATA 1
#define CONFIG_WENDY_WASM_AOT_XIP 0
#define CONFIG_WENDY_WASM_PREFER_RTC_RAM 0
#define CONFIG_WENDY_WASM_MAX_MEMORY_PAGES 2
#define MALLOC_CAP_INTERNAL 1
#define MALLOC_CAP_8BIT 2
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define WENDY_WASM_STATE_LOADED 1

#include "module_admission_struct.inc"
typedef struct wendy_wasm_module *wendy_wasm_module_handle_t;
static bool s_initialized = true;
static struct {
    uint32_t stack_size, heap_size;
} s_config = {.stack_size = 16384};
/* (module (import "test" "noop" (func)) (memory 1 2)
 *   (func (export "grow_by") (param i32) (result i32)
 *     local.get 0 memory.grow)) */
static const uint8_t fixture[] = {
    0,   0x61, 0x73, 0x6d, 1, 0, 0,   0,   1,   9,   2, 0x60, 0,   0,    0x60, 1,   0x7f,
    1,   0x7f, 2,    13,   1, 4, 't', 'e', 's', 't', 4, 'n',  'o', 'o',  'p',  0,   0,
    3,   2,    1,    1,    5, 4, 1,   1,   1,   2,   7, 11,   1,   7,    'g',  'r', 'o',
    'w', '_',  'b',  'y',  0, 1, 10,  8,   1,   6,   0, 0x20, 0,   0x40, 0,    0x0b};
static uint8_t stored[sizeof(uint32_t) + sizeof fixture];
static esp_partition_t partition = {.size = sizeof stored};
static void store(const uint8_t *bytes)
{
    uint32_t size = sizeof fixture;
    memcpy(stored, &size, sizeof size);
    memcpy(stored + sizeof size, bytes, size);
}
static const esp_partition_t *esp_partition_find_first(int type, int subtype, const char *label)
{
    (void)subtype;
    assert(type == ESP_PARTITION_TYPE_DATA);
    return label ? &partition : NULL;
}
static esp_err_t esp_partition_read(const esp_partition_t *part, unsigned offset, void *out,
                                    size_t size)
{
    assert(part == &partition && offset + size <= sizeof stored);
    memcpy(out, stored + offset, size);
    return ESP_OK;
}
static void esp_partition_munmap(unsigned handle)
{
    (void)handle;
    assert(!"test has no mapped partition");
}
#include "module_admission_production.inc"

static void noop(wasm_exec_env_t execution)
{
    (void)execution;
}
static void drain(wendy_wasm_module_handle_t module)
{
    wasm_runtime_destroy_exec_env(module->exec_env);
    wasm_runtime_deinstantiate(module->module_inst);
    wasm_runtime_unload(module->wasm_module);
    release_module_bytes(module);
    free(module);
}
static void exercise(wendy_wasm_module_handle_t module)
{
    wasm_memory_inst_t memory = wasm_runtime_get_memory(module->module_inst, 0);
    assert(memory && !wasm_runtime_get_memory(module->module_inst, 1));
    assert(wasm_memory_get_cur_page_count(memory) == 1);
    assert(wasm_memory_get_max_page_count(memory) == 2);
    wasm_function_inst_t grow = wasm_runtime_lookup_function(module->module_inst, "grow_by");
    assert(grow);
    uint32_t parameter[] = {1};
    assert(wasm_runtime_call_wasm(module->exec_env, grow, 1, parameter) && parameter[0] == 1);
    parameter[0] = 1;
    assert(wasm_runtime_call_wasm(module->exec_env, grow, 1, parameter) &&
           parameter[0] == UINT32_MAX);
    assert(wasm_memory_get_cur_page_count(memory) == 2);
    drain(module);
}
int main(void)
{
    RuntimeInitArgs initialization = {.mem_alloc_type = Alloc_With_System_Allocator};
    assert(wasm_runtime_full_init(&initialization));
    NativeSymbol symbol = {"noop", noop, "()", NULL};
    assert(wasm_runtime_register_natives("test", &symbol, 1));
    /* Demonstrate why parsing a loaded byte buffer cannot enforce admission. */
    uint8_t changed[sizeof fixture];
    memcpy(changed, fixture, sizeof fixture);
    uint32_t pages;
    char error[128] = {0};
    assert(wendy_wasm_memory_limit(changed, sizeof changed, 2, 0, &pages, error, sizeof error));
    wasm_module_t raw = wasm_runtime_load(changed, sizeof changed, error, sizeof error);
    assert(raw && memcmp(changed, fixture, sizeof fixture));
    assert(!wendy_wasm_memory_limit(changed, sizeof changed, 2, 0, &pages, error, sizeof error));
    wasm_runtime_unload(raw);
    /* Both production APIs must cache admission before those loader edits. */
    for (unsigned iteration = 0; iteration < 20; iteration++) {
        wendy_wasm_module_handle_t module = NULL;
        assert(wendy_wasm_load(fixture, sizeof fixture, &module) == ESP_OK && module);
        exercise(module);
        store(fixture);
        module = NULL;
        assert(wendy_wasm_load_from_partition("wasm_a", &module) == ESP_OK && module);
        exercise(module);
        assert(!memcmp(stored + sizeof(uint32_t), fixture, sizeof fixture));
    }
    /* Pre-load admission still rejects a module whose initial memory is over
     * the cap, with neither API publishing a partially loaded handle. */
    uint8_t overlarge[sizeof fixture];
    memcpy(overlarge, fixture, sizeof fixture);
    for (size_t i = 0; i + 5 < sizeof overlarge; i++)
        if (!memcmp(overlarge + i, (uint8_t[]){5, 4, 1, 1, 1, 2}, 6)) {
            overlarge[i + 4] = overlarge[i + 5] = 3;
            break;
        }
    assert(
        !wendy_wasm_memory_limit(overlarge, sizeof overlarge, 2, 0, &pages, error, sizeof error));
    wendy_wasm_module_handle_t rejected = NULL;
    assert(wendy_wasm_load(overlarge, sizeof overlarge, &rejected) == ESP_FAIL && !rejected);
    store(overlarge);
    assert(wendy_wasm_load_from_partition("wasm_a", &rejected) == ESP_FAIL && !rejected);
    wasm_runtime_destroy();
    puts("Actual WAMR production loads preserve bytecode admission and memory.grow caps");
}
