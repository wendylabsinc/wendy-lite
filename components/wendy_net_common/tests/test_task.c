#include "wendy_net_task.h"
#include "wendy_net_alloc.h"
#include "freertos/semphr.h"
#include "esp_freertos_hooks.h"
#include <assert.h>
#include <stdio.h>
#include <setjmp.h>

struct mock_task { void *context; void (*deleted)(int, void *); };
static struct mock_task child;
static struct mock_task idle_tasks[CONFIG_FREERTOS_NUMBER_OF_CORES], parent;
static TaskHandle_t current = &parent;
static jmp_buf dispatch;
static bool (*idle[CONFIG_FREERTOS_NUMBER_OF_CORES])(void);
static unsigned core, calls, registrations;
static bool fail_creation, fail_registration;
static bool keep_running;
static TaskHandle_t *published_handle;

unsigned xPortGetCoreID(void) { return core; }
TaskHandle_t xTaskGetCurrentTaskHandle(void) { return current; }
TaskHandle_t xTaskGetCurrentTaskHandleForCore(BaseType_t cpu) { return &idle_tasks[cpu]; }
TaskHandle_t xTaskGetIdleTaskHandleForCore(BaseType_t cpu) { return &idle_tasks[cpu]; }
void *pvTaskGetThreadLocalStoragePointer(TaskHandle_t task, BaseType_t slot)
{
    assert(task == &child && slot == 1);
    return task->context;
}
void vTaskSuspend(TaskHandle_t task) { assert(task == &child); }
int esp_register_freertos_idle_hook_for_cpu(bool (*hook)(void), UBaseType_t cpu)
{
    if (fail_registration && cpu == 1) return -1;
    assert(!idle[cpu]);
    idle[cpu] = hook;
    ++registrations;
    return ESP_OK;
}
void esp_deregister_freertos_idle_hook_for_cpu(bool (*hook)(void), UBaseType_t cpu)
{
    assert(idle[cpu] == hook);
    idle[cpu] = NULL;
}
SemaphoreHandle_t xSemaphoreCreateBinaryStatic(StaticSemaphore_t *storage)
{
    storage->count = 0;
    return storage;
}
BaseType_t xSemaphoreGive(SemaphoreHandle_t semaphore)
{
    assert(child.deleted && !*published_handle);
    semaphore->count = 1;
    return pdPASS;
}
BaseType_t xSemaphoreTake(SemaphoreHandle_t semaphore, uint32_t timeout)
{
    assert(timeout == portMAX_DELAY && semaphore->count);
    semaphore->count = 0;
    return pdPASS;
}
void vSemaphoreDelete(SemaphoreHandle_t semaphore) { assert(!semaphore->count); }
void vTaskSetThreadLocalStoragePointerAndDelCallback(TaskHandle_t task, BaseType_t slot,
    void *context, void (*deleted)(int, void *))
{
    assert(!task && slot == 1);
    child.context = context;
    child.deleted = deleted;
}
void vTaskDelete(TaskHandle_t task)
{
    assert((!task || task == &child) && child.deleted);
    if (!task) current = &idle_tasks[core];
    child.deleted(1, child.context);
    /* Match the SDK order: callback first, stack and TCB cleanup afterward. */
    assert(!wendy_net_runtime_memory_drained());
    child.deleted = NULL;
    current = &parent;
}
BaseType_t xTaskCreate(TaskFunction_t function, const char *name, uint32_t bytes,
    void *argument, UBaseType_t priority, TaskHandle_t *handle)
{
    (void)name; (void)priority;
    assert(bytes == 4096 && !*published_handle);
    if (fail_creation) return pdFAIL;
    *handle = &child;
    current = &child;
    if (!setjmp(dispatch)) function(argument);
    current = &parent;
    return pdPASS;
}
static void work(void *argument)
{
    assert(argument == &calls && child.deleted);
    ++calls;
    if (keep_running) longjmp(dispatch,1);
}
int main(void)
{
    TaskHandle_t handle = NULL;
    published_handle = &handle;
    assert(wendy_net_runtime_memory_open());
    fail_registration = true;
    assert(wendy_net_task_create(work,"owned",4096,&calls,1,&handle) != pdPASS);
    assert(!idle[0] && !idle[1] && wendy_net_runtime_memory_drained());
    fail_registration = false;
    fail_creation = true;
    assert(wendy_net_task_create(work,"owned",4096,&calls,1,&handle) != pdPASS);
    assert(wendy_net_runtime_memory_drained());
    fail_creation = false;
    for (core = 0; core < CONFIG_FREERTOS_NUMBER_OF_CORES; ++core) {
        handle = NULL;
        assert(wendy_net_task_create(work,"owned",4096,&calls,1,&handle) == pdPASS);
        assert(handle == &child && !wendy_net_runtime_memory_drained());
        wendy_net_memory_snapshot_t state;
        wendy_net_runtime_memory_snapshot(&state);
        assert(state.reservation_count == 1 && state.reservation_bytes >= 4096);
        unsigned deleting_core = core;
        core = 1 - core;
        assert(idle[core]());
        assert(!wendy_net_runtime_memory_drained());
        core = deleting_core;
        wendy_net_runtime_memory_close();
        assert(!wendy_net_runtime_memory_open());
        assert(idle[core]());
        assert(wendy_net_runtime_memory_drained());
        assert(wendy_net_runtime_memory_open());
    }
    core = 0;
    handle = NULL;
    keep_running = true;
    assert(wendy_net_task_create(work,"owned",4096,&calls,1,&handle) == pdPASS);
    assert(!wendy_net_runtime_memory_drained());
    wendy_net_task_delete(handle);
    assert(wendy_net_runtime_memory_drained());
    assert(calls == 3 && registrations == 3);
    wendy_net_runtime_memory_close();
    puts("Owned tasks retain reservations through deletion and same-core idle cleanup");
    return 0;
}
