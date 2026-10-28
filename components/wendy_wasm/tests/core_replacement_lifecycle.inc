/* Actual core Stop/PushBegin/APP_START call paths, with finite real linear
 * mappings and lifecycle-only firmware/loader edges. No radio or flash I/O. */
#define CONFIG_SPIRAM 1
#define CONFIG_WENDY_WASM_USE_PSRAM 1
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define esp_err_to_name(code) "fixture"
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL (-1)
#define ESP_ERR_TIMEOUT (-2)
#define ESP_ERR_NO_MEM (-3)
enum {WENDY_WASM_STATE_LOADED,WENDY_WASM_STATE_RUNNING,WENDY_WASM_STATE_STOPPED};
struct wendy_wasm_module {WASMMemoryInstance *module_inst;unsigned state;};
typedef struct wendy_wasm_module *wendy_wasm_module_handle_t;
typedef WASMMemoryInstance *wasm_memory_inst_t;
typedef struct {
    bool use_psram;
    void (*output_cb)(const char *,uint32_t,void *);
    void *output_ctx;
} wendy_wasm_config_t;
#define WENDY_WASM_CONFIG_DEFAULT() ((wendy_wasm_config_t){.use_psram=true})
static wendy_wasm_config_t s_config={.use_psram=true};
static void *s_pool_buf;
static wendy_wasm_module_handle_t s_current_module;
static bool s_wasm_active,s_current_module_flash_backed,s_wasm_flash_busy;
static bool load_failed;
static unsigned starts;
static void *wasm_runtime_get_memory(WASMMemoryInstance *instance,unsigned index)
{return index ? NULL:instance;}
static bool wasm_memory_get_shared(WASMMemoryInstance *memory)
{(void)memory;return false;}
static void *wasm_memory_get_base_address(WASMMemoryInstance *memory)
{return memory->memory_data;}
static esp_err_t wendy_wasm_stop(wendy_wasm_module_handle_t module)
{
    assert(module && module==s_current_module);
    module->state=WENDY_WASM_STATE_STOPPED;s_wasm_active=false;return ESP_OK;
}
static bool wait_for_wasm_inactive(uint32_t timeout)
{assert(timeout==5000);return !s_wasm_active;}
static void reset_guest_resources(void) {assert(!s_wasm_active);}
static void wendy_wasm_unload(wendy_wasm_module_handle_t module)
{
    assert(module && !s_wasm_active);dispose(module->module_inst);
    free(module->module_inst);free(module);
}
static esp_err_t wendy_wasm_init(const wendy_wasm_config_t *config)
{s_config=*config;return ESP_OK;}
static esp_err_t wendy_wasm_reinit(void) {return ESP_OK;}
static esp_err_t wendy_hal_export_init(void) {return ESP_OK;}
static void wasm_output_cb(const char *bytes,uint32_t size,void *context)
{(void)bytes;(void)size;(void)context;}
static const char *partition_label_for(uint8_t slot)
{assert(!slot);return "wasm_a";}
static esp_err_t load_wasm_module_from_flash(const char *label,wendy_wasm_module_handle_t *out)
{
    assert(!strcmp(label,"wasm_a"));if(load_failed)return ESP_FAIL;
    struct wendy_wasm_module *module=calloc(1,sizeof *module);assert(module);
    module->module_inst=calloc(1,sizeof *module->module_inst);assert(module->module_inst);
    /* Runtime/module loading allocates ordinary metadata before linear memory. */
    void *metadata=heap_caps_malloc(2048,1);assert(metadata);
    *module->module_inst=mapping(5*1024*1024);fixture_free(metadata);
    module->state=WENDY_WASM_STATE_LOADED;*out=module;return ESP_OK;
}
static bool start_loaded_wasm_module(void)
{
    assert(s_current_module);s_current_module->state=WENDY_WASM_STATE_RUNNING;
    s_wasm_active=true;starts++;return true;
}
#include "linear_core_production.inc"

static void core_replacement_lifecycle(void)
{
    unsigned before=allocations,freed=releases;
    assert(!wasm_app_start_on_control_thread(0) && s_current_module && s_wasm_active);
    assert(allocations==before+2 && releases==freed+1); /* mapping+metadata */
    void *previous=s_current_module->module_inst->memory_data;
    memset(previous,0x8b,5*1024*1024);
    /* Normal fixed client: PushBegin stops execution; APP_START still sees the
     * existing instance and opens the one-use replacement transaction. */
    assert(!wasm_app_stop_for_flash_on_control_thread());
    assert(s_current_module && !s_wasm_active && s_current_module->module_inst->memory_data==previous);
    before=allocations;freed=releases;
    assert(!wasm_app_start_on_control_thread(0));
    assert(s_current_module->module_inst->memory_data==previous);
    assert(allocations==before+1 && releases==freed+1); /* metadata only */
    for(size_t i=0;i<5*1024*1024;i++)assert(((uint8_t *)previous)[i]==0);

    /* Explicit Stop keeps its established release contract. The old client
     * sent this command before PushBegin and therefore bypassed reuse. */
    freed=releases;assert(!wasm_app_stop_on_control_thread(NULL));
    assert(!s_current_module && !s_wasm_active && releases==freed+1);
    assert(!wasm_app_stop_for_flash_on_control_thread());
    before=allocations;assert(!wasm_app_start_on_control_thread(0));
    assert(allocations==before+2); /* Fresh mapping required after Stop. */

    /* Failed replacement load releases the retained mapping at APP_START exit. */
    assert(!wasm_app_stop_for_flash_on_control_thread());
    load_failed=true;freed=releases;
    assert(wasm_app_start_on_control_thread(0)==ESP_FAIL);
    assert(!s_current_module && !s_wasm_active && releases==freed+1);
    load_failed=false;
    assert(!wasm_app_start_on_control_thread(0) && starts==4);
    assert(!wasm_app_stop_on_control_thread(NULL));
    assert(!s_current_module && allocations==releases);
    puts("core lifecycle PASS: PushBegin->Start reuses; explicit Stop releases; failed Start and final Stop drain");
}
