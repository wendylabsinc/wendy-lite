#include "wendy_net_task.h"
#include "wendy_net_alloc.h"

#if CONFIG_WENDY_NET_PEER
#include "esp_freertos_hooks.h"
#include "freertos/semphr.h"
#if CONFIG_FREERTOS_THREAD_LOCAL_STORAGE_POINTERS < 2 || !CONFIG_FREERTOS_TLSP_DELETION_CALLBACKS
#error "Accounted mesh tasks require dedicated TLSP slot1 and deletion callbacks"
#endif
#if !configSUPPORT_STATIC_ALLOCATION
#error "Accounted mesh tasks require static semaphore support"
#endif
struct owned_task {
    TaskFunction_t function;
    void *argument;
    SemaphoreHandle_t started;
    wendy_net_memory_reservation_t reservation;
    struct owned_task *next;
    bool explicit_delete;
};
static portMUX_TYPE reap_lock = portMUX_INITIALIZER_UNLOCKED;
static struct owned_task *pending[CONFIG_FREERTOS_NUMBER_OF_CORES];
static bool hooks_registered;

static void release(struct owned_task *task)
{
    wendy_net_memory_release(&task->reservation);
    wendy_net_free(task);
}

/* IDF invokes TLSP callbacks before freeing the task's stack and TCB. For
 * idle-reaped tasks the next hook on that pinned idle CPU follows those frees.
 * External deletion uses our explicit synchronous delete path instead. */
static bool retire_tasks(void)
{
    unsigned core = xPortGetCoreID();
    portENTER_CRITICAL(&reap_lock);
    struct owned_task *task = pending[core];
    pending[core] = NULL;
    portEXIT_CRITICAL(&reap_lock);
    while (task) {
        struct owned_task *next = task->next;
        release(task);
        task = next;
    }
    return true;
}

static bool register_hooks(void)
{
    portENTER_CRITICAL(&reap_lock);
    if (!hooks_registered) {
        unsigned core;
        for (core = 0; core < CONFIG_FREERTOS_NUMBER_OF_CORES; ++core) {
            if (esp_register_freertos_idle_hook_for_cpu(retire_tasks, core) != ESP_OK)
                break;
        }
        hooks_registered = core == CONFIG_FREERTOS_NUMBER_OF_CORES;
        if (!hooks_registered) {
            while (core) esp_deregister_freertos_idle_hook_for_cpu(retire_tasks, --core);
        }
    }
    bool ready = hooks_registered;
    portEXIT_CRITICAL(&reap_lock);
    return ready;
}

static void reaped(int slot,void *context)
{
    (void)slot;
    struct owned_task *task=context;
    if (task->explicit_delete) return;
    unsigned core = xPortGetCoreID();
    bool idle = xTaskGetCurrentTaskHandle() == xTaskGetIdleTaskHandleForCore(core);
    /* Raw synchronous vTaskDelete by another task is outside this ownership
     * API: retaining the charge is safer than premature admission/reopen. */
    configASSERT(idle);
    if (!idle) return;
    portENTER_CRITICAL(&reap_lock);
    task->next = pending[core];
    pending[core] = task;
    portEXIT_CRITICAL(&reap_lock);
}
static void enter(void *context)
{
    struct owned_task *task=context;
    TaskFunction_t function=task->function;
    void *argument=task->argument;
    SemaphoreHandle_t started=task->started;
    vTaskSetThreadLocalStoragePointerAndDelCallback(NULL,1,task,reaped);
    xSemaphoreGive(started);
    function(argument);
    vTaskDelete(NULL);
}
BaseType_t wendy_net_task_create(TaskFunction_t function,const char *name,
    uint32_t stack_bytes,void *argument,UBaseType_t priority,TaskHandle_t *handle)
{
    if(!function || !stack_bytes || !register_hooks())return errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY;
    struct owned_task *task=wendy_net_internal_calloc(1,sizeof *task);
    if(!task)return errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY;
    /* Public static-TCB bound plus 64 bytes for SDK allocation bookkeeping. */
    size_t charge=(size_t)stack_bytes+sizeof(StaticTask_t)+64;
    if(charge<stack_bytes || !wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),
        &task->reservation,charge,WENDY_NET_MEMORY_INTERNAL)){
        wendy_net_free(task);return errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY;
    }
    StaticSemaphore_t started_storage;
    SemaphoreHandle_t started=xSemaphoreCreateBinaryStatic(&started_storage);
    task->function=function;task->argument=argument;task->started=started;
    TaskHandle_t created;
    BaseType_t result=xTaskCreate(enter,name,stack_bytes,task,priority,&created);
    if(result!=pdPASS)release(task);
    else {
        /* Publish the handle only after its deletion callback is installed.
         * This also permits callers to delete a lower-priority task safely. */
        xSemaphoreTake(started,portMAX_DELAY);
        if(handle)*handle=created;
    }
    vSemaphoreDelete(started);
    return result;
}

void wendy_net_task_delete(TaskHandle_t handle)
{
    if (!handle || handle == xTaskGetCurrentTaskHandle()) {
        vTaskDelete(NULL);
        return;
    }
    struct owned_task *task = pvTaskGetThreadLocalStoragePointer(handle,1);
    configASSERT(task);
    if (!task) return;
    /* Match IDF's WithCaps deletion: ensure vTaskDelete takes its synchronous
     * cleanup path rather than leaving stack/TCB frees to a later idle pass. */
    vTaskSuspend(handle);
    for (;;) {
        bool running = false;
        for (unsigned core = 0; core < CONFIG_FREERTOS_NUMBER_OF_CORES; ++core)
            if (xTaskGetCurrentTaskHandleForCore(core) == handle) running = true;
        if (!running) break;
        taskYIELD();
    }
    task->explicit_delete = true;
    vTaskDelete(handle);
    release(task);
}
#else
BaseType_t wendy_net_task_create(TaskFunction_t function,const char *name,
    uint32_t stack_bytes,void *argument,UBaseType_t priority,TaskHandle_t *task)
{
    return xTaskCreate(function,name,stack_bytes,argument,priority,task);
}
void wendy_net_task_delete(TaskHandle_t task)
{
    vTaskDelete(task);
}
#endif
