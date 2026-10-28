#include "wendy_pki_work.h"
#include "wendy_net_memory.h"
#include "wendy_net_alloc.h"
#include <pthread.h>
#include <stddef.h>
#if ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wendy_net_task.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
static TaskHandle_t worker;
static TaskHandle_t mesh_actor;
static void (*notify_completion)(void);
#endif

static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static bool available,running;
#if ESP_PLATFORM
static TaskHandle_t callback_task;
#else
static pthread_t callback_thread;
#endif
static void (*pending)(void *);
static void *argument;
static wendy_net_memory_scope_t pending_scope;
static struct wendy_pki_work_metrics metrics;
static unsigned synchronous_waiters;
static bool stopping;

void wendy_pki_work_enable(void)
{
    pthread_mutex_lock(&lock);available=true;pthread_mutex_unlock(&lock);
}
bool wendy_pki_work_is_current(void)
{
    pthread_mutex_lock(&lock);
#if ESP_PLATFORM
    bool current=running && callback_task==xTaskGetCurrentTaskHandle();
#else
    bool current=running && pthread_equal(callback_thread,pthread_self());
#endif
    pthread_mutex_unlock(&lock);return current;
}
bool wendy_pki_work_available(void)
{
    pthread_mutex_lock(&lock);bool ready=available;pthread_mutex_unlock(&lock);return ready;
}
static bool submit(void (*callback)(void *),void *context,bool synchronous)
{
    pthread_mutex_lock(&lock);
    bool accepted=available && callback && !pending && !stopping && (synchronous || !synchronous_waiters);
    if(accepted){pending=callback;argument=context;pending_scope=wendy_net_memory_scope_current();
#if ESP_PLATFORM
        if(worker)xTaskNotifyGive(worker);
#endif
    }
    pthread_mutex_unlock(&lock);return accepted;
}
bool wendy_pki_work_submit(void (*callback)(void *),void *context)
{return submit(callback,context,false);}
bool wendy_pki_work_poll(void)
{
#if ESP_PLATFORM
    if(worker && xTaskGetCurrentTaskHandle()!=worker)return false;
#endif
    pthread_mutex_lock(&lock);
    if(!pending || running){pthread_mutex_unlock(&lock);return false;}
    void (*callback)(void *)=pending;void *context=argument;
    wendy_net_memory_scope_t scope=pending_scope;running=true;
#if ESP_PLATFORM
    callback_task=xTaskGetCurrentTaskHandle();
#else
    callback_thread=pthread_self();
#endif
    pthread_mutex_unlock(&lock);
#if ESP_PLATFORM
    int64_t started=esp_timer_get_time();
#endif
    wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(scope.owner,scope.placement);
    callback(context);
    wendy_net_memory_scope_leave(previous);
    pthread_mutex_lock(&lock);
#if ESP_PLATFORM
    uint64_t elapsed=(uint64_t)(esp_timer_get_time()-started);
    metrics.jobs++;metrics.total_us+=elapsed;if(elapsed>metrics.max_us)metrics.max_us=elapsed;
    if(worker && xTaskGetCurrentTaskHandle()==worker)metrics.stack_free=(unsigned)uxTaskGetStackHighWaterMark(NULL);
#endif
    pending=NULL;argument=NULL;running=false;
    pthread_mutex_unlock(&lock);
#if ESP_PLATFORM
    if(notify_completion)notify_completion();
#endif
    return true;
}

#if ESP_PLATFORM
static void run_crypto(void *unused)
{
    (void)unused;
    uint64_t completed_wall_us=0;
    for(;;){
        ulTaskNotifyTake(pdTRUE,portMAX_DELAY);
        for(;;){
            int64_t started=esp_timer_get_time();
            if(!wendy_pki_work_poll())break;
            completed_wall_us+=(uint64_t)(esp_timer_get_time()-started);
            /* Completion may immediately wake the higher-priority actor and
             * refill our one-item slot. Yielding only to ready higher-priority
             * tasks can therefore starve IDLE indefinitely during catch-up.
             * Carry completed-job wall across empty slots/notifications: a
             * stale or brief notification wait is not an idle allowance.
             * Quiet waits are not charged; preemption during a job is. Finish
             * every call intact, then bound accumulated service conservatively.
             * Two ticks keep this worker blocked through a full tick even
             * near a boundary; other higher-priority tasks can still occupy
             * the CPU. This is cooperation, not an IDLE runtime guarantee. */
            if(completed_wall_us>=UINT64_C(100000)){
                vTaskDelay(2);
                completed_wall_us=0;
            }
        }
        pthread_mutex_lock(&lock);
        bool finish=stopping && !pending;
        if(finish){worker=NULL;mesh_actor=NULL;stopping=false;}
        pthread_mutex_unlock(&lock);
        if(finish){if(notify_completion)notify_completion();vTaskDelete(NULL);return;}
    }
}
#endif
bool wendy_pki_work_start(void (*wake)(void))
{
#if ESP_PLATFORM
    pthread_mutex_lock(&lock);
    bool ok=worker!=NULL;
    if(!ok){
        notify_completion=wake;stopping=false;
#ifndef CONFIG_WENDY_NET_CRYPTO_TASK_STACK_SIZE
#define CONFIG_WENDY_NET_CRYPTO_TASK_STACK_SIZE 10240
#endif
#ifndef CONFIG_WENDY_NET_TASK_PRIORITY
#define CONFIG_WENDY_NET_TASK_PRIORITY 4
#endif
        ok=wendy_net_task_create(run_crypto,"net-crypto",CONFIG_WENDY_NET_CRYPTO_TASK_STACK_SIZE,NULL,CONFIG_WENDY_NET_TASK_PRIORITY-1,&worker)==pdPASS;
    }
    if(ok){available=true;if(pending)xTaskNotifyGive(worker);}
    pthread_mutex_unlock(&lock);return ok;
#else
    (void)wake;wendy_pki_work_enable();return true;
#endif
}
bool wendy_pki_work_stop(void)
{
#if ESP_PLATFORM
    pthread_mutex_lock(&lock);
    bool done=worker==NULL;
    if(!done){stopping=true;xTaskNotifyGive(worker);}
    pthread_mutex_unlock(&lock);return done;
#else
    return true;
#endif
}

bool wendy_pki_work_idle(void)
{pthread_mutex_lock(&lock);bool idle=available && !pending && !stopping && !synchronous_waiters;pthread_mutex_unlock(&lock);return idle;}

void wendy_pki_work_metrics(struct wendy_pki_work_metrics *out)
{pthread_mutex_lock(&lock);*out=metrics;out->running=running;pthread_mutex_unlock(&lock);}

static void (*io_pending)(void *);
static void *io_argument;
static wendy_net_memory_scope_t io_scope;
static bool io_running;
bool wendy_pki_io_work_submit(void (*callback)(void *),void *context)
{
    pthread_mutex_lock(&lock);bool ok=available && callback && !io_pending;
    if(ok){io_pending=callback;io_argument=context;io_scope=wendy_net_memory_scope_current();}
    pthread_mutex_unlock(&lock);return ok;
}
bool wendy_pki_io_work_poll(void)
{
    pthread_mutex_lock(&lock);
    if(!io_pending || io_running){pthread_mutex_unlock(&lock);return false;}
    void (*callback)(void *)=io_pending;void *context=io_argument;io_running=true;
    wendy_net_memory_scope_t scope=io_scope;
    pthread_mutex_unlock(&lock);
    wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(scope.owner,scope.placement);
    callback(context);
    wendy_net_memory_scope_leave(previous);
    pthread_mutex_lock(&lock);
    io_pending=NULL;io_argument=NULL;io_running=false;pthread_mutex_unlock(&lock);
#if ESP_PLATFORM
    if(notify_completion)notify_completion();
#endif
    return true;
}
bool wendy_pki_io_work_idle(void)
{pthread_mutex_lock(&lock);bool idle=io_pending==NULL;pthread_mutex_unlock(&lock);return idle;}
#include <stdatomic.h>
/* Retained TLS allocation admission, independent of the single CPU queue.
 * PSRAM has two mesh slots plus one slot reserved for baseline callers;
 * baseline callers prefer that reserved slot, then may use idle shared slots.
 * SRAM keeps exactly one shared owner. No table storage is allocated at OFF. */
static _Atomic(void *) handshake_owners[3];
static bool handshake_psram(void)
{
#if ESP_PLATFORM
    return heap_caps_get_total_size(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT)!=0;
#else
    wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);
    return memory.external_enabled;
#endif
}
unsigned wendy_pki_handshake_mesh_limit(void){return handshake_psram() ? 2:1;}
static unsigned handshake_slots(unsigned order[3])
{
    unsigned mesh=wendy_pki_handshake_mesh_limit();
    if(mesh==1){order[0]=0;return 1;}
    if(wendy_net_memory_scope_current().owner){order[0]=0;order[1]=1;return 2;}
    order[0]=2;order[1]=0;order[2]=1;return 3;
}
bool wendy_pki_handshake_claim(void *owner)
{
    if(!owner)return false;
    for(unsigned i=0;i<3;i++)if(atomic_load(&handshake_owners[i])==owner)return true;
    unsigned order[3],count=handshake_slots(order);
    for(unsigned i=0;i<count;i++){
        void *expected=NULL;
        if(atomic_compare_exchange_strong(&handshake_owners[order[i]],&expected,owner) || expected==owner)return true;
    }
    return false;
}
bool wendy_pki_handshake_owned(void *owner)
{
    if(!owner)return false;
    for(unsigned i=0;i<3;i++)if(atomic_load(&handshake_owners[i])==owner)return true;
    return false;
}
bool wendy_pki_handshake_transfer(void *from,void *to)
{
    if(!from || !to)return false;
    if(from!=to)for(unsigned i=0;i<3;i++)if(atomic_load(&handshake_owners[i])==to)return false;
    for(unsigned i=0;i<3;i++){
        void *expected=from;
        if(atomic_compare_exchange_strong(&handshake_owners[i],&expected,to))return true;
    }
    return false;
}
void wendy_pki_handshake_release(void *owner)
{
    if(!owner)return;
    for(unsigned i=0;i<3;i++){
        void *expected=owner;
        if(atomic_compare_exchange_strong(&handshake_owners[i],&expected,NULL))return;
    }
}
bool wendy_pki_handshake_available(void)
{
    unsigned order[3],count=handshake_slots(order);
    for(unsigned i=0;i<count;i++)if(!atomic_load(&handshake_owners[order[i]]))return true;
    return false;
}
bool wendy_pki_handshake_busy(void)
{for(unsigned i=0;i<3;i++)if(atomic_load(&handshake_owners[i]))return true;return false;}
#if ESP_PLATFORM
#include "freertos/semphr.h"
struct cpu_call {void (*callback)(void *);void *argument;SemaphoreHandle_t done;};
static void execute_call(void *context)
{
    struct cpu_call *call=context;
    call->callback(call->argument);
    /* The caller may preempt immediately on give. Keep the completion object
     * alive until give has returned, even for a stack-allocated semaphore. */
    pthread_mutex_lock(&lock);
    xSemaphoreGive(call->done);
    pthread_mutex_unlock(&lock);
}
#endif
void wendy_pki_work_bind_actor(void)
{
#if ESP_PLATFORM
    mesh_actor=xTaskGetCurrentTaskHandle();
#endif
}
int wendy_pki_work_run(void (*callback)(void *),void *context)
{
#if ESP_PLATFORM
    TaskHandle_t caller=xTaskGetCurrentTaskHandle();
    if(worker && caller!=worker){
        if(caller==mesh_actor)return -1; /* A core/actor must submit a future. */
        StaticSemaphore_t storage;
        struct cpu_call call={.callback=callback,.argument=context,.done=xSemaphoreCreateBinaryStatic(&storage)};
        if(!call.done)return -1;
        /* An actor woken by each completion must not repeatedly take the
         * next slot ahead of a management caller sleeping until its tick. */
        pthread_mutex_lock(&lock);synchronous_waiters++;pthread_mutex_unlock(&lock);
        while(!submit(execute_call,&call,true)){
            pthread_mutex_lock(&lock);
            bool inline_now=worker==NULL;
            if(inline_now)synchronous_waiters--;
            pthread_mutex_unlock(&lock);
            if(inline_now){vSemaphoreDelete(call.done);callback(context);return 0;}
            vTaskDelay(1);
        }
        pthread_mutex_lock(&lock);synchronous_waiters--;pthread_mutex_unlock(&lock);
        xSemaphoreTake(call.done,portMAX_DELAY);
        pthread_mutex_lock(&lock);pthread_mutex_unlock(&lock);
        vSemaphoreDelete(call.done);return 0;
    }
#endif
    callback(context);return 0;
}
