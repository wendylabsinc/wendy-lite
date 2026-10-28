/* Execute the production lifecycle function with ordinary outer-driver states. */
#include <assert.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include "esp_err.h"
#include "esp_log.h"
#include "wendy_com_msg.pb.h"
typedef void *TaskHandle_t;
#define pdPASS 1
static atomic_bool starting,settings_ready,stopping;
static _Atomic(void *) state,identity_task;
static atomic_uint runtime_state,runtime_error;
static pthread_mutex_t state_lock=PTHREAD_MUTEX_INITIALIZER;
static WendyComNetConfig applied_config,desired;
static bool pending,restarting,restart_due,drained=true,open_ok=true,apply_now;
static unsigned polls,stop_requests,restarts,closed,opened,tasks;
static const char *TAG="lifecycle-test";
static void wn_settings_poll(bool network_drained)
{assert(network_drained);polls++;if(apply_now){pending=false;atomic_store(&stopping,true);stop_requests++;}}
static bool wn_settings_pending(void){return pending;}
static bool wn_settings_restarting(void){return restarting;}
static bool wn_settings_restart_due(void){return restart_due;}
static void esp_restart(void){restarts++;}
static bool wendy_net_runtime_memory_drained(void){return drained;}
static WendyComNetConfig wn_settings_get(void){return desired;}
static void wendy_net_runtime_memory_close(void){closed++;}
static bool wendy_net_runtime_memory_open(void){opened++;return open_ok;}
static void await_identity(void *p){(void)p;}
static int wendy_net_task_create(void(*fn)(void*),const char*n,unsigned s,void*a,unsigned pr,TaskHandle_t*out)
{(void)n;(void)s;(void)a;(void)pr;(void)out;assert(fn==await_identity);tasks++;return pdPASS;}
#include "lifecycle_poll.inc"
int main(void)
{
 (void)TAG;atomic_store(&settings_ready,true);
 /* The identity waiter has no actor/queues yet: OFF must still pass the reply
  * fence and cancel startup rather than remain pending until enrollment. */
 atomic_store(&starting,true);atomic_store(&identity_task,(void*)1);pending=true;
 lifecycle_poll();assert(polls==1&&!stop_requests&&!tasks);
 apply_now=true;lifecycle_poll();assert(polls==2&&stop_requests==1&&atomic_load(&stopping));
 assert(!pending&&!tasks);apply_now=false;
 /* A live actor owns the output queue sample; baseline must not claim empty. */
 atomic_store(&state,(void*)1);pending=true;lifecycle_poll();assert(polls==2);
 atomic_store(&state,NULL);atomic_store(&identity_task,NULL);atomic_store(&starting,false);pending=false;
 desired=(WendyComNetConfig){.enabled=false};lifecycle_poll();assert(closed==1&&runtime_state==WendyComNetState_WENDY_COM_NET_OFF);
 desired.enabled=true;drained=false;lifecycle_poll();assert(!opened&&!tasks);
 drained=true;lifecycle_poll();assert(opened==1&&tasks==1&&applied_config.enabled&&starting);
 /* Restart waits actual old tasks and ledger retirement after its reply. */
 restarting=restart_due=true;atomic_store(&starting,false);drained=false;lifecycle_poll();assert(!restarts);
 drained=true;lifecycle_poll();assert(restarts==1);
}
