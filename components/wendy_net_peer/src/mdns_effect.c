#include "mdns_effect.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_work.h"
#include <limits.h>
#include <stdatomic.h>
#include <string.h>
enum {POLL_US=100000,DISCOVERY_US=5000000};
struct wnm_owner {
    struct wnm_intent command;
    struct wnm_advertisement applied;
    mdns_search_once_t *search;
    mdns_result_t *results;
    mdns_query_notify_t notify;
    char query_tenant[37],query_self[65];
    int64_t command_at,retry_at,discover_at;
    atomic_bool done;
    bool lent,finished,ready,consumed;
};
static bool same_advertisement(const struct wnm_advertisement *a,const struct wnm_advertisement *b)
{return a->enabled==b->enabled && (!a->enabled || !memcmp(a,b,sizeof *a));}
/* This entire callback belongs to the existing outer server I/O slot. Every
 * SDK operation that can acquire the global mDNS mutex stays on this side. */
static void execute(void *context)
{
    struct wnm_owner *o=context;
    const struct wnm_advertisement *want=&o->command.advertisement;
    if(o->applied.enabled && !same_advertisement(&o->applied,want)){
        int result=mdns_service_remove("_wendy-net","_tcp");
        if(result==ESP_OK || result==ESP_ERR_NOT_FOUND || result==ESP_ERR_INVALID_ARG || result==ESP_ERR_INVALID_STATE)
            memset(&o->applied,0,sizeof o->applied);
    }
    if(want->enabled && !o->applied.enabled){
        mdns_txt_item_t txt[]={ {"version","1"},{"protocol","tls-v1"},
            {"principal",want->principal},{"mesh",want->mesh},{"role","embedded-router"},
            {"platform","Lite"},{"operator_router",want->operator_router ? "1":"0"},{"ble",want->radio},{"ble_psm",want->psm} };
        if(mdns_service_add(want->instance,"_wendy-net","_tcp",43024,txt,want->radio[0] ? 9:7)==ESP_OK)
            o->applied=*want;
    }
    if(o->search && !o->finished){
        if(mdns_query_async_get_results(o->search,0,&o->results,NULL)){
            o->finished=true;o->ready=true;
            if(!o->command.browse){o->consumed=true;o->ready=false;}
        }
    }
    if(o->search && o->finished && o->consumed){
        if(o->results){mdns_query_results_free(o->results);o->results=NULL;}
        /* INVALID_STATE is not deletion. Retain the exact handle and retry. */
        if(mdns_query_async_delete(o->search)==ESP_OK){
            o->search=NULL;o->finished=false;o->consumed=false;
        }
    }
    if(!o->search && o->command.browse && o->command_at>=o->discover_at){
        o->search=mdns_query_async_new(NULL,"_wendy-net","_tcp",MDNS_TYPE_PTR,1500,8,o->notify);
        if(o->search){
            memcpy(o->query_tenant,o->command.tenant,sizeof o->query_tenant);
            memcpy(o->query_self,o->command.self,sizeof o->query_self);
            o->discover_at=o->command_at+DISCOVERY_US;
        }
    }
    o->retry_at=o->command_at+POLL_US;
    /* The actor may collect immediately. No owner access after publication. */
    atomic_store_explicit(&o->done,true,memory_order_release);
}
struct wnm_owner *wnm_open(mdns_query_notify_t notify)
{
    struct wnm_owner *o=wendy_net_calloc(1,sizeof *o);
    if(o){o->notify=notify;atomic_init(&o->done,false);}return o;
}
void wnm_collect(struct wnm_owner *o)
{
    if(o && o->lent && atomic_load_explicit(&o->done,memory_order_acquire))o->lent=false;
}
bool wnm_results(struct wnm_owner *o,mdns_result_t **results,const char **tenant,const char **self)
{
    if(!o || o->lent || !o->ready)return false;
    *results=o->results;*tenant=o->query_tenant;*self=o->query_self;return true;
}
void wnm_consumed(struct wnm_owner *o)
{if(o && !o->lent && o->ready){o->ready=false;o->consumed=true;}}
void wnm_drive(struct wnm_owner *o,const struct wnm_intent *intent,int64_t now)
{
    if(!o || o->lent || o->ready)return;
    bool changed=!same_advertisement(&o->applied,&intent->advertisement);
    bool cleanup=o->search!=NULL;
    bool query=intent->browse && now>=o->discover_at;
    if(!changed && !cleanup && !query)return;
    if(now<o->retry_at)return;
    o->command=*intent;o->command_at=now;
    atomic_store_explicit(&o->done,false,memory_order_relaxed);
    if(wendy_pki_io_work_submit(execute,o))o->lent=true;
    else o->retry_at=now+POLL_US;
}
int64_t wnm_deadline(const struct wnm_owner *o)
{
    if(!o || o->lent || o->ready)return INT64_MAX;
    if(o->search || !same_advertisement(&o->applied,&o->command.advertisement))return o->retry_at;
    if(!o->command.browse)return INT64_MAX;
    return o->discover_at>o->retry_at ? o->discover_at:o->retry_at;
}
bool wnm_idle(const struct wnm_owner *o)
{return !o || (!o->lent && !o->search && !o->results && !o->applied.enabled);}
bool wnm_close(struct wnm_owner *o)
{if(!wnm_idle(o))return false;wendy_net_free(o);return true;}
