/* Real ESP dispatcher, deterministic finite scheduler/clock. No TLS or radio
 * inputs. Exercise the notification/empty-slot boundary rather than a second
 * implementation of the service-budget calculation. */
#include <assert.h>
#include <string.h>
#include "../src/wendy_pki_work.c"

enum mode { GAPPED, REFILLED, QUIET, WHOLE_LONG, OFF_AFTER_JOB, OFF_WHILE_WAITING };
static enum mode fixture_mode;
static TaskFunction_t fixture_entry;
static int64_t fixture_now;
static unsigned fixture_notifications,fixture_submitted,fixture_completed,
    fixture_target,fixture_delays,fixture_deleted,fixture_stale;
static bool fixture_in_job;
static void fixture_job(void *unused);
static void fixture_submit(void)
{assert(wendy_pki_work_submit(fixture_job,NULL));fixture_submitted++;}
static void fixture_job(void *unused)
{
    (void)unused;assert(!fixture_in_job);fixture_in_job=true;
    unsigned before=fixture_delays;
    fixture_now+=fixture_mode==WHOLE_LONG ? 150000:fixture_mode==OFF_AFTER_JOB ? 60000:20000;
    assert(fixture_delays==before); /* Whole call is never split by allowance. */
    fixture_completed++;fixture_in_job=false;
}
static void fixture_complete(void)
{
    if(!worker)return; /* Final cooperative task-retirement notification. */
    if(fixture_mode==REFILLED && fixture_submitted<fixture_target)fixture_submit();
    if(fixture_mode==OFF_AFTER_JOB && fixture_completed==fixture_target)
        assert(!wendy_pki_work_stop());
}
TaskHandle_t xTaskGetCurrentTaskHandle(void){return (void *)1;}
BaseType_t xTaskNotifyGive(TaskHandle_t task)
{assert(task==(void *)1);fixture_notifications++;return pdPASS;}
uint32_t ulTaskNotifyTake(BaseType_t clear,TickType_t ticks)
{
    assert(clear==pdTRUE && ticks==portMAX_DELAY && !fixture_in_job);
    if(!fixture_notifications){
        if(fixture_submitted<fixture_target){
            fixture_now+=fixture_mode==QUIET ? 10000000:100;
            fixture_submit();
        }else assert(!wendy_pki_work_stop());
    }
    assert(fixture_notifications);
    unsigned result=fixture_notifications;fixture_notifications=0;
    if(wendy_pki_work_idle())fixture_stale++;
    return result;
}
UBaseType_t uxTaskGetStackHighWaterMark(TaskHandle_t task)
{assert(!task || task==(void *)1);return 2048;}
void vTaskDelay(TickType_t ticks)
{
    assert(ticks==2 && !fixture_in_job && fixture_completed);
    fixture_delays++;fixture_now+=20000;
}
void vTaskDelete(TaskHandle_t task){assert(!task);fixture_deleted++;}
BaseType_t wendy_net_task_create(TaskFunction_t fn,const char *name,uint32_t stack,
    void *argument,UBaseType_t priority,TaskHandle_t *task)
{
    assert(!strcmp(name,"net-crypto") && stack==10240 && !argument && priority==3);
    fixture_entry=fn;*task=(void *)1;return pdPASS;
}
int64_t esp_timer_get_time(void){return fixture_now;}
size_t heap_caps_get_total_size(unsigned caps){(void)caps;return 0;}
wendy_net_memory_scope_t wendy_net_memory_scope_current(void)
{return (wendy_net_memory_scope_t){0};}
wendy_net_memory_scope_t wendy_net_memory_scope_enter(wendy_net_memory_t *owner,
    wendy_net_memory_placement_t placement)
{(void)owner;(void)placement;return (wendy_net_memory_scope_t){0};}
void wendy_net_memory_scope_leave(wendy_net_memory_scope_t previous){(void)previous;}
SemaphoreHandle_t xSemaphoreCreateBinaryStatic(StaticSemaphore_t *s){return s;}
BaseType_t xSemaphoreGive(SemaphoreHandle_t s){assert(s);return pdTRUE;}
BaseType_t xSemaphoreTake(SemaphoreHandle_t s,TickType_t t){(void)s;(void)t;assert(0);return 0;}
void vSemaphoreDelete(SemaphoreHandle_t s){(void)s;}
static void fixture_run(enum mode mode,unsigned jobs,unsigned delays)
{
    fixture_mode=mode;fixture_now=0;fixture_notifications=fixture_submitted=fixture_completed=0;
    fixture_delays=fixture_deleted=fixture_stale=0;fixture_target=jobs;fixture_in_job=false;
    assert(wendy_pki_work_start(fixture_complete));
    if(jobs)fixture_submit();
    fixture_entry(NULL);
    assert(fixture_deleted==1 && fixture_completed==jobs && fixture_delays==delays);
    assert(wendy_pki_work_stop());
    if(mode==REFILLED)assert(fixture_stale); /* Notifications for inner-loop work. */
}
int main(void)
{
    fixture_run(GAPPED,6,1);       /* Six20ms jobs across brief empty slots. */
    fixture_run(REFILLED,6,1);     /* Same work, accumulated stale notifications. */
    fixture_run(QUIET,2,0);       /* Ten-second no-job wait is never charged. */
    fixture_run(WHOLE_LONG,1,1);   /* One whole150ms call, yield after completion. */
    fixture_run(OFF_AFTER_JOB,2,1);/* OFF drains work and the between-job delay. */
    fixture_run(OFF_WHILE_WAITING,0,0);
    return 0;
}
