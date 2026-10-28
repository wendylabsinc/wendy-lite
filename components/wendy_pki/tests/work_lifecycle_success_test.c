/* Ordinary FreeRTOS dispatcher lifecycle with a pthread-backed outer driver.
 * Compile the production ESP branch: only scheduler/platform primitives are
 * substituted. No radio, certificates or artificial input corpus. */
#include <assert.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../src/wendy_pki_work.c"

struct task {
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t ready;
    unsigned notifications;
    TaskFunction_t entry;
    void *argument;
    atomic_bool deleted;
};
static struct task driver;
static struct task *created;
static _Thread_local struct task *current;
static _Thread_local wendy_net_memory_scope_t allocation_scope;
static atomic_bool fail_create,external_ram;
static atomic_uint wakes,other_wakes,executing,total;

static void pause_tick(void)
{struct timespec duration={0,1000000};assert(!nanosleep(&duration,NULL));}
static void wait_flag(atomic_bool *flag)
{for(unsigned i=0;i<5000 && !atomic_load(flag);i++)pause_tick();assert(atomic_load(flag));}
static void wake(void){atomic_fetch_add(&wakes,1);}
static void other_wake(void){atomic_fetch_add(&other_wakes,1);}
static void count(void *context)
{
    if(context)(*(unsigned *)context)++;
    assert(!atomic_fetch_add(&executing,1));
    assert(wendy_pki_work_is_current());
    atomic_fetch_add(&total,1);
    assert(atomic_fetch_sub(&executing,1)==1);
}
static void inline_count(void *context){(*(unsigned *)context)++;}
static void nested(void *context)
{assert(wendy_pki_work_is_current());assert(!wendy_pki_work_run(count,context));}
struct held {atomic_bool entered,release;wendy_net_memory_t *owner;};
static void hold(void *context)
{
    struct held *held=context;
    assert(wendy_net_memory_scope_current().owner==held->owner);
    atomic_store(&held->entered,true);
    while(!atomic_load(&held->release))pause_tick();
}
static void *task_entry(void *context)
{current=context;current->entry(current->argument);return NULL;}
TaskHandle_t xTaskGetCurrentTaskHandle(void)
{return current ? current:&driver;}
BaseType_t xTaskNotifyGive(TaskHandle_t handle)
{
    struct task *task=handle;assert(task);
    pthread_mutex_lock(&task->lock);task->notifications++;
    pthread_cond_signal(&task->ready);pthread_mutex_unlock(&task->lock);return pdPASS;
}
uint32_t ulTaskNotifyTake(BaseType_t clear,TickType_t ticks)
{
    assert(current && clear==pdTRUE && ticks==portMAX_DELAY);
    pthread_mutex_lock(&current->lock);
    while(!current->notifications)pthread_cond_wait(&current->ready,&current->lock);
    unsigned count=current->notifications;current->notifications=0;
    pthread_mutex_unlock(&current->lock);return count;
}
UBaseType_t uxTaskGetStackHighWaterMark(TaskHandle_t task)
{assert(!task);return 2048;}
void vTaskDelay(TickType_t ticks)
{assert(ticks==1 || ticks==2);pause_tick();}
void vTaskDelete(TaskHandle_t task)
{assert(!task && current);atomic_store(&current->deleted,true);}
BaseType_t wendy_net_task_create(TaskFunction_t entry,const char *name,uint32_t stack,
    void *argument,UBaseType_t priority,TaskHandle_t *out)
{
    assert(!strcmp(name,"net-crypto") && stack==10240 && priority==3 && !argument);
    if(atomic_load(&fail_create))return 0;
    assert(!created);created=calloc(1,sizeof *created);assert(created);
    assert(!pthread_mutex_init(&created->lock,NULL));assert(!pthread_cond_init(&created->ready,NULL));
    created->entry=entry;created->argument=argument;*out=created;
    assert(!pthread_create(&created->thread,NULL,task_entry,created));return pdPASS;
}
static void reap(void)
{
    assert(created);assert(!pthread_join(created->thread,NULL));assert(atomic_load(&created->deleted));
    pthread_cond_destroy(&created->ready);pthread_mutex_destroy(&created->lock);free(created);created=NULL;
}
static void stop(void)
{
    bool stopped=false;
    for(unsigned i=0;i<5000 && !(stopped=wendy_pki_work_stop());i++)pause_tick();
    assert(stopped);reap();
}
int64_t esp_timer_get_time(void)
{struct timespec now;assert(!clock_gettime(CLOCK_MONOTONIC,&now));return now.tv_sec*INT64_C(1000000)+now.tv_nsec/1000;}
size_t heap_caps_get_total_size(unsigned caps)
{assert(caps==(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));return atomic_load(&external_ram) ? 1024*1024:0;}
wendy_net_memory_scope_t wendy_net_memory_scope_current(void){return allocation_scope;}
wendy_net_memory_scope_t wendy_net_memory_scope_enter(wendy_net_memory_t *owner,wendy_net_memory_placement_t placement)
{wendy_net_memory_scope_t old=allocation_scope;allocation_scope=(wendy_net_memory_scope_t){owner,placement};return old;}
void wendy_net_memory_scope_leave(wendy_net_memory_scope_t previous){allocation_scope=previous;}
SemaphoreHandle_t xSemaphoreCreateBinaryStatic(StaticSemaphore_t *storage)
{
    storage->value=0;assert(!pthread_mutex_init(&storage->lock,NULL));
    assert(!pthread_cond_init(&storage->ready,NULL));return storage;
}
BaseType_t xSemaphoreGive(SemaphoreHandle_t handle)
{
    StaticSemaphore_t *s=handle;pthread_mutex_lock(&s->lock);s->value++;
    pthread_cond_signal(&s->ready);pthread_mutex_unlock(&s->lock);
    /* The waiting caller can now preempt; its storage must remain alive until
     * this producer has completely returned, including this ordinary yield. */
    sched_yield();return pdTRUE;
}
BaseType_t xSemaphoreTake(SemaphoreHandle_t handle,TickType_t ticks)
{
    StaticSemaphore_t *s=handle;assert(ticks==portMAX_DELAY);pthread_mutex_lock(&s->lock);
    while(!s->value)pthread_cond_wait(&s->ready,&s->lock);
    s->value--;pthread_mutex_unlock(&s->lock);return pdTRUE;
}
void vSemaphoreDelete(SemaphoreHandle_t handle)
{StaticSemaphore_t *s=handle;assert(!pthread_cond_destroy(&s->ready));assert(!pthread_mutex_destroy(&s->lock));}
struct caller {struct task task;unsigned calls;struct held *held;wendy_net_memory_t *owner;};
static void scoped_count(void *context)
{
    struct caller *caller=context;
    assert(wendy_net_memory_scope_current().owner==caller->owner);
    count(&caller->calls);
}
static void *client(void *context)
{
    struct caller *caller=context;current=&caller->task;
    allocation_scope.owner=caller->owner;
    if(caller->held)assert(!wendy_pki_work_run(hold,caller->held));
    else for(unsigned i=0;i<100;i++)assert(!wendy_pki_work_run(scoped_count,caller));
    return NULL;
}
static void *io_client(void *context)
{struct caller *caller=context;current=&caller->task;assert(wendy_pki_io_work_poll());return NULL;}
static void *inline_client(void *context)
{struct caller *caller=context;current=&caller->task;assert(!wendy_pki_work_run(hold,caller->held));return NULL;}
static void handshake_capacity(void)
{
    unsigned owners[5];wendy_net_memory_t ledger={0};
    assert(wendy_pki_handshake_mesh_limit()==1);
    assert(wendy_pki_handshake_claim(&owners[0]));assert(!wendy_pki_handshake_claim(&owners[1]));
    assert(wendy_pki_handshake_transfer(&owners[0],&owners[1]));
    wendy_pki_handshake_release(&owners[0]);assert(wendy_pki_handshake_owned(&owners[1]));
    wendy_pki_handshake_release(&owners[1]);assert(!wendy_pki_handshake_busy());
    atomic_store(&external_ram,true);
    allocation_scope.owner=&ledger;
    assert(wendy_pki_handshake_mesh_limit()==2);
    assert(wendy_pki_handshake_claim(&owners[0]));assert(wendy_pki_handshake_claim(&owners[1]));
    assert(!wendy_pki_handshake_claim(&owners[2]));assert(!wendy_pki_handshake_available());
    allocation_scope.owner=NULL;
    assert(wendy_pki_handshake_claim(&owners[2]));assert(!wendy_pki_handshake_claim(&owners[3]));
    assert(!wendy_pki_handshake_transfer(&owners[0],&owners[2]));
    for(unsigned i=0;i<3;i++)wendy_pki_handshake_release(&owners[i]);
    assert(!wendy_pki_handshake_busy());atomic_store(&external_ram,false);
}
int main(void)
{
    unsigned calls=0;
    assert(wendy_pki_work_run(NULL,NULL)==-1);
    assert(!wendy_pki_work_submit(NULL,NULL));assert(!wendy_pki_io_work_submit(NULL,NULL));
    assert(!wendy_pki_work_available());assert(!wendy_pki_work_submit(count,&calls));
    assert(!wendy_pki_io_work_submit(inline_count,&calls));
    assert(!wendy_pki_work_run(inline_count,&calls) && calls==1);
    wendy_pki_work_metrics(NULL);
    handshake_capacity();

    /* Worker activation cannot overlap an existing inline CPU call. */
    struct held inline_held={0};struct caller inline_caller={.held=&inline_held};
    assert(!pthread_create(&inline_caller.task.thread,NULL,inline_client,&inline_caller));
    wait_flag(&inline_held.entered);assert(!wendy_pki_work_start(wake));
    atomic_store(&inline_held.release,true);assert(!pthread_join(inline_caller.task.thread,NULL));
    atomic_store(&fail_create,true);assert(!wendy_pki_work_start(wake));
    assert(!wendy_pki_work_available());atomic_store(&fail_create,false);

    /* No hidden I/O provider appears just because crypto has a task. */
    assert(wendy_pki_work_start(wake));assert(wendy_pki_work_start(wake));
    assert(!wendy_pki_work_start(other_wake));
    assert(!wendy_pki_io_work_submit(inline_count,&calls));
    struct held held={0};assert(wendy_pki_work_submit(hold,&held));wait_flag(&held.entered);
    wendy_pki_work_bind_actor();
    assert(wendy_pki_work_run(inline_count,&calls)==-1);assert(!wendy_pki_work_poll());
    assert(!wendy_pki_work_stop());assert(!wendy_pki_work_available());
    assert(!wendy_pki_work_submit(count,&calls));assert(!wendy_pki_work_start(wake));
    atomic_store(&held.release,true);stop();
    assert(!wendy_pki_work_available());assert(!wendy_pki_work_submit(count,&calls));

    /* Existing baseline callers use the same CPU worker, with no concurrent
     * CPU callback and no semaphore storage surviving its initiating call. */
    assert(wendy_pki_work_start(wake));wendy_pki_work_enable();
    struct caller callers[4]={0};wendy_net_memory_t ledgers[4]={0};
    for(unsigned i=0;i<4;i++)callers[i].owner=&ledgers[i];
    for(unsigned i=0;i<4;i++)assert(!pthread_create(&callers[i].task.thread,NULL,client,&callers[i]));
    for(unsigned i=0;i<4;i++){assert(!pthread_join(callers[i].task.thread,NULL));assert(callers[i].calls==100);}
    assert(atomic_load(&total)==400);
    unsigned nested_calls=0;
    while(!wendy_pki_work_submit(nested,&nested_calls))pause_tick();
    while(!wendy_pki_work_idle())pause_tick();
    assert(nested_calls==1 && atomic_load(&total)==401);

    /* Draining also waits for the separate provider's already accepted I/O.
     * The actor/crypto tasks themselves are forbidden from polling I/O. */
    wendy_pki_work_bind_actor();struct held io_held={.owner=&ledgers[0]};
    allocation_scope.owner=io_held.owner;
    assert(wendy_pki_io_work_submit(hold,&io_held));assert(!wendy_pki_io_work_poll());
    allocation_scope.owner=NULL;
    struct caller io_caller={0};assert(!pthread_create(&io_caller.task.thread,NULL,io_client,&io_caller));
    wait_flag(&io_held.entered);assert(!wendy_pki_work_stop());
    assert(!wendy_pki_io_work_submit(inline_count,&calls));
    atomic_store(&io_held.release,true);assert(!pthread_join(io_caller.task.thread,NULL));stop();
    unsigned retired_wakes=atomic_load(&wakes);
    for(unsigned i=0;i<4;i++)pause_tick();
    assert(atomic_load(&wakes)==retired_wakes);
    assert(wendy_pki_work_available()); /* Registered baseline polling remains. */
    assert(wendy_pki_work_submit(count,&calls));assert(wendy_pki_work_poll());
    assert(wendy_pki_work_idle());assert(!wendy_pki_work_poll());
    assert(wendy_pki_io_work_submit(inline_count,&calls));assert(wendy_pki_io_work_poll());

    assert(wendy_pki_work_start(other_wake));
    assert(wendy_pki_work_submit(count,&calls));while(!wendy_pki_work_idle())pause_tick();stop();
    assert(atomic_load(&other_wakes)==1);assert(atomic_load(&wakes)==retired_wakes);
    struct wendy_pki_work_metrics metrics;wendy_pki_work_metrics(&metrics);
    assert(!metrics.running && metrics.jobs>=404 && metrics.stack_free==2048);
    assert(!created && !wendy_pki_handshake_busy() && !wendy_pki_work_is_current());
    return 0;
}
