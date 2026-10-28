#include "wendy_net_task.h"
#include "wendy_net_alloc.h"

#if CONFIG_WENDY_NET_PEER
#if CONFIG_FREERTOS_THREAD_LOCAL_STORAGE_POINTERS < 2 || !CONFIG_FREERTOS_TLSP_DELETION_CALLBACKS
#error "Accounted mesh tasks require dedicated TLSP slot1 and deletion callbacks"
#endif
struct owned_task {
    TaskFunction_t function;
    void *argument;
    wendy_net_memory_reservation_t reservation;
};
static void reaped(int slot,void *context)
{
    (void)slot;
    struct owned_task *task=context;
    wendy_net_memory_release(&task->reservation);
    wendy_net_free(task);
}
static void enter(void *context)
{
    struct owned_task *task=context;
    TaskFunction_t function=task->function;
    void *argument=task->argument;
    vTaskSetThreadLocalStoragePointerAndDelCallback(NULL,1,task,reaped);
    function(argument);
    vTaskDelete(NULL);
}
BaseType_t wendy_net_task_create(TaskFunction_t function,const char *name,
    uint32_t stack_bytes,void *argument,UBaseType_t priority,TaskHandle_t *handle)
{
    if(!function || !stack_bytes)return errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY;
    struct owned_task *task=wendy_net_internal_calloc(1,sizeof *task);
    if(!task)return errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY;
    /* Public static-TCB bound plus64 bytes for SDK allocation bookkeeping. */
    size_t charge=(size_t)stack_bytes+sizeof(StaticTask_t)+64;
    if(charge<stack_bytes || !wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),
        &task->reservation,charge,WENDY_NET_MEMORY_INTERNAL)){
        wendy_net_free(task);return errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY;
    }
    task->function=function;task->argument=argument;
    BaseType_t result=xTaskCreate(enter,name,stack_bytes,task,priority,handle);
    if(result!=pdPASS)reaped(1,task);
    return result;
}
#else
BaseType_t wendy_net_task_create(TaskFunction_t function,const char *name,
    uint32_t stack_bytes,void *argument,UBaseType_t priority,TaskHandle_t *task)
{
    return xTaskCreate(function,name,stack_bytes,argument,priority,task);
}
#endif
