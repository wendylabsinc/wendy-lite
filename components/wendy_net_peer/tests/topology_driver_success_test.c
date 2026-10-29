/* Ordinary management/actor scheduling with the exact production functions. */
#include "topology_query.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
typedef void *TaskHandle_t;
struct wnrs {unsigned id;};
struct wnrs_node {unsigned unused;};
struct peer_state {struct wnrs_node *router_node;struct wnrs *router;struct peer_state *next;struct {unsigned medium;} candidate;};
static _Atomic(struct peer_state *) state;
static atomic_bool stopping;
static pthread_mutex_t state_lock=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local TaskHandle_t task_id=(void *)2;
static atomic_llong clock_us;
static atomic_uint wakes;
static atomic_bool picked,hold,finish;
static TaskHandle_t xTaskGetCurrentTaskHandle(void){return task_id;}
static int64_t esp_timer_get_time(void){return atomic_load(&clock_us);}
static void tick(void){struct timespec wait={.tv_nsec=1000000};nanosleep(&wait,NULL);}
static void vTaskDelay(unsigned ticks){assert(ticks==1);atomic_fetch_add(&clock_us,10000);tick();}
static void wnad_wake(void){atomic_fetch_add(&wakes,1);}
static void wendy_conf_enrollment_identity(char tenant[37],char device[65])
{strcpy(tenant,"11111111-1111-4111-8111-111111111111");strcpy(device,"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");}
static int wn_uuid_parse(const char *text,uint8_t out[16])
{assert(strlen(text)==36);memset(out,text[0],16);return 0;}
static uint64_t wnrs_link_id(const struct wnrs *link){return link->id;}
static int wnrs_topology(struct wnrs_node *node,uint32_t cursor,uint64_t generation,WendyComNetTopologyPage *page)
{
 (void)node;(void)cursor;(void)generation;atomic_store(&picked,true);
 while(atomic_load(&hold)&&!atomic_load(&finish))tick();
 const char *principal="spiffe://wendy.sh/tenant/11111111-1111-4111-8111-111111111111/operator/Alice";
 struct wnt_record_view view={.record=WendyComNetTopologyRecord_init_zero,.principal=principal,.principal_size=strlen(principal)};
 view.record.kind=3;view.record.owner_role=WNT_TOPOLOGY_OPERATOR;view.record.owner_instance.size=16;
 memset(view.record.owner_instance.bytes,0xaa,16);page->runtime_available=true;return wnt_record_copy(page,&view);
}
#include "topology_driver.inc"
static void *project(void *argument)
{task_id=(void *)1;service_topology_query(argument);return NULL;}
struct read {WendyComNetTopologyParams params;WendyComNetTopologyPage page;WendyComResult result;};
static void *read_page(void *argument)
{struct read *read=argument;read->result=wn_peer_topology(&read->params,&read->page);return NULL;}
static void queued(void)
{
 for(unsigned i=0;i<1000;i++){
  pthread_mutex_lock(&state_lock);bool ready=topology_query!=NULL;pthread_mutex_unlock(&state_lock);
  if(ready)return;tick();
 }
 assert(!"caller did not submit its bounded query");
}
static void assert_empty(void)
{wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);assert(!memory.current_bytes&&!memory.allocation_count&&!topology_query);}
int main(void)
{
 struct read read={0};
 /* OFF reads only identity/status: the closed ledger stays closed and empty. */
 assert(wn_peer_topology(&read.params,&read.page)==WendyComResult_WENDY_COM_RESULT_OK);
 assert_empty();assert(!atomic_load(&wakes));
 struct wnrs_node node={0};struct peer_state root={.router_node=&node};atomic_store(&state,&root);
 assert(wendy_net_runtime_memory_open());atomic_store(&topology_actor,(void *)1);
 task_id=(void *)1;assert(wn_peer_topology(&read.params,&read.page)==WendyComResult_WENDY_COM_RESULT_BUSY);task_id=(void *)2;assert_empty();
 /* Normal completion transfers exactly one selected row beyond actor lifetime. */
 pthread_t caller,actor;assert(!pthread_create(&caller,NULL,read_page,&read));queued();
 assert(!pthread_create(&actor,NULL,project,&root));pthread_join(actor,NULL);pthread_join(caller,NULL);
 assert(read.result==WendyComResult_WENDY_COM_RESULT_OK&&read.page.has_record);
 wendy_net_runtime_memory_close();assert(!wendy_net_runtime_memory_drained());
 wnt_page_release(&read.page);assert(wendy_net_runtime_memory_drained());assert_empty();
 assert(wendy_net_runtime_memory_open());
 /* Timeout before pickup removes both leases without an actor touching it. */
 read=(struct read){0};assert(wn_peer_topology(&read.params,&read.page)==WendyComResult_WENDY_COM_RESULT_BUSY);assert_empty();
 /* A timed-out caller cannot free a picked-up actor's immutable row owner. */
 read=(struct read){0};atomic_store(&hold,true);atomic_store(&finish,false);atomic_store(&picked,false);
 assert(!pthread_create(&caller,NULL,read_page,&read));queued();assert(!pthread_create(&actor,NULL,project,&root));
 while(!atomic_load(&picked))tick();pthread_join(caller,NULL);assert(read.result==WendyComResult_WENDY_COM_RESULT_BUSY);
 assert(topology_query);atomic_store(&finish,true);pthread_join(actor,NULL);assert_empty();
 /* OFF cancels queued work before waiting for management/context retirement. */
 read=(struct read){0};assert(!pthread_create(&caller,NULL,read_page,&read));queued();
 pthread_mutex_lock(&state_lock);wnqt_abort(&topology_query,wendy_net_free);pthread_mutex_unlock(&state_lock);
 pthread_join(caller,NULL);assert(read.result==WendyComResult_WENDY_COM_RESULT_BUSY);assert_empty();
 atomic_store(&state,NULL);wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
 printf("PASS production topology caller/actor/OFF: fixed page=%zu mailbox=%zu, row lease drains ledger\n",sizeof read.page,sizeof(struct topology_query));
}
