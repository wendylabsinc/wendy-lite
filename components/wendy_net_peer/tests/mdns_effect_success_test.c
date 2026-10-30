#include "mdns_effect.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void (*queued)(void *);
static void *argument;
static bool busy,worker,advertised,delete_busy;
static unsigned adds,removes,queries,frees,deletes,polls;
static mdns_search_once_t *active;
static char published[106];
bool wendy_pki_io_work_submit(void (*callback)(void *),void *context)
{if(busy || queued)return false;queued=callback;argument=context;return true;}
static void run(void)
{assert(queued);void (*fn)(void *)=queued;void *ctx=argument;queued=NULL;worker=true;fn(ctx);worker=false;}
int mdns_service_add(const char *instance,const char *service,const char *protocol,uint16_t port,mdns_txt_item_t *txt,size_t count)
{
    assert(worker && instance && !strcmp(service,"_wendy-net") && !strcmp(protocol,"_tcp") && port==43024 && count==7);
    assert(!advertised);advertised=true;strcpy(published,txt[2].value);adds++;return ESP_OK;
}
int mdns_service_remove(const char *service,const char *protocol)
{assert(worker && !strcmp(service,"_wendy-net") && !strcmp(protocol,"_tcp"));assert(advertised);advertised=false;removes++;return ESP_OK;}
mdns_search_once_t *mdns_query_async_new(const char *name,const char *service,const char *protocol,uint16_t type,uint32_t timeout,size_t maximum,mdns_query_notify_t notify)
{
    assert(worker && !active && !name && service && protocol && type==MDNS_TYPE_PTR && timeout==1500 && maximum==8);(void)notify;
    active=calloc(1,sizeof *active);assert(active);queries++;return active;
}
bool mdns_query_async_get_results(mdns_search_once_t *search,uint32_t timeout,mdns_result_t **results,uint8_t *count)
{
    assert(worker && search==active && !timeout && !count);polls++;
    if(!search->finished)return false;
    *results=calloc(1,sizeof **results);assert(*results);(*results)->value=42;return true;
}
void mdns_query_results_free(mdns_result_t *results)
{assert(worker && results->value==42);free(results);frees++;}
int mdns_query_async_delete(mdns_search_once_t *search)
{
    assert(worker && search==active && search->finished);
    if(delete_busy){delete_busy=false;return ESP_ERR_INVALID_STATE;}
    active=NULL;free(search);deletes++;return ESP_OK;
}
static void step(struct wnm_owner *owner,const struct wnm_intent *intent,int64_t now)
{wnm_collect(owner);wnm_drive(owner,intent,now);if(queued){run();wnm_collect(owner);}}
int main(void)
{
    struct wnm_owner *o=wnm_open(NULL);assert(o);
    struct wnm_intent want={.browse=true,.advertisement={.enabled=true}};
    strcpy(want.tenant,"normal-tenant");strcpy(want.self,"normal-device");
    strcpy(want.advertisement.instance,"normal");strcpy(want.advertisement.principal,"original");
    busy=true;wnm_drive(o,&want,0);assert(!queued && wnm_deadline(o)==100000 && !adds && !queries);
    busy=false;wnm_drive(o,&want,99999);assert(!queued);wnm_drive(o,&want,100000);assert(queued);
    /* A delayed server command snapshots the old identity. Repeated newer
     * advertisement intents coalesce without mutating the borrowed command. */
    strcpy(want.advertisement.principal,"newer");wnm_drive(o,&want,100001);assert(!adds);
    run();wnm_collect(o);assert(adds==1 && !strcmp(published,"original") && queries==1);
    step(o,&want,200000);assert(adds==2 && removes==1 && !strcmp(published,"newer"));
    /* Ordinary delayed discovery is borrowed intact until actor ACK. */
    active->finished=true;step(o,&want,300000);
    mdns_result_t *result;const char *tenant,*self;
    assert(wnm_results(o,&result,&tenant,&self) && result->value==42 && !strcmp(tenant,"normal-tenant") && !strcmp(self,"normal-device"));
    wnm_drive(o,&want,400000);assert(!queued && !frees && !deletes);
    wnm_consumed(o);delete_busy=true;step(o,&want,400000);
    assert(frees==1 && !deletes && !wnm_close(o));
    step(o,&want,500000);assert(deletes==1 && !active && frees==1);
    /* OFF while another async query is active preserves its handle and polls
     * on the server. No deletion is attempted before normal completion. */
    step(o,&want,5200000);assert(active && queries==2);
    struct wnm_intent off={0};step(o,&off,5300000);
    assert(!advertised && removes==2 && active && !wnm_close(o));
    for(int64_t now=5400000;now<5600000;now+=100000){step(o,&off,now);assert(active && !wnm_close(o));}
    active->finished=true;step(o,&off,5600000);
    assert(!active && frees==2 && deletes==2 && wnm_idle(o) && wnm_close(o));
    /* OFF can also arrive while the server still owns its earlier immutable
     * enabled command. Its eventual newly-created query must drain normally. */
    o=wnm_open(NULL);assert(o);wnm_drive(o,&want,0);assert(queued);
    wnm_drive(o,&off,1);assert(!wnm_close(o));run();wnm_collect(o);
    assert(active && advertised);step(o,&off,100000);assert(active && !advertised && !wnm_close(o));
    active->finished=true;step(o,&off,200000);assert(!active && wnm_close(o));
    assert(polls && !queued);
    puts("mDNS SDK calls stay outer; snapshot coalescing, finite retry, result loans and active-query OFF cleanup succeed");return 0;
}
