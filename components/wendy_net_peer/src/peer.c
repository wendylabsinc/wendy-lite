#include "wendy_net_alloc.h"
#include "wendy_net_task.h"
#include "wendy_net_profile.h"
/* SPDX-License-Identifier: Apache-2.0 */
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/netif.h"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/tcpip.h"
#include "mdns.h"
#include "wendy_conf.h"
#include "wendy_net_peer.h"
#include "wendy_net_peer_protocol.h"
#include "wendy_net_control.h"
#include "wendy_net_carrier.h"
#include "wendy_net_packet_queue.h"
#include "actor_driver.h"
#include "wendy_net_agent.h"
#if CONFIG_WENDY_NET
#include "wendy_net.h"
#endif
#include "crypto_job.h"
#include "settings.h"
#include "esp_vfs.h"
#include "netif_lifetime.h"
#include "netif_effect.h"
#include "mdns_effect.h"
#if CONFIG_WENDY_NET_BLE
#include "wendy_ble_mesh.h"
#include "wendy_net_ble_protocol.h"
#endif
#include "router_session.h"
#include "wendy_pki_mesh.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_verify.h"
#include "time_control.h"
#include "wendy_pki_work.h"
#include "lwip/sockets.h"
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include "wendy_wifi.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifndef CONFIG_WENDY_NET_PACKET_QUEUE
#define CONFIG_WENDY_NET_PACKET_QUEUE 4
#endif
#define PEER_QUEUE CONFIG_WENDY_NET_PACKET_QUEUE
#define PEER_CONTROL_BYTES WN_DATAGRAM_MAX
#ifndef CONFIG_WENDY_NET_ROUTING_QUEUE_FRAMES
#define CONFIG_WENDY_NET_ROUTING_QUEUE_FRAMES 4
#endif
#define FRESH_TIME_US INT64_C(300000000)
#define REFRESH_INTERVAL_US INT64_C(240000000)
#ifndef CONFIG_WENDY_NET_CONSTRAINED_PROFILE
#define CONFIG_WENDY_NET_CONSTRAINED_PROFILE 0
#endif
struct time_bootstrap_job {
    struct wble_mesh_pipe *pipe;
    struct wendy_pki_stream stream;
    atomic_bool done;
    bool server,submitted;
    esp_err_t result;
    int64_t started;
};
#if CONFIG_WENDY_NET_BLE
struct ble_seen {
    uint8_t address[6],type,hint[4];
    uint16_t psm;
    uint8_t capabilities;
    int64_t seen_ms;
};
#endif
struct queued_packet
{
    uint16_t size;
    uint8_t bytes[WN_MTU];
};
struct service_query {
    atomic_uint references;
    unsigned operation;
    size_t input_size,capacity;
    char *output;
    bool processing,complete;
    int result;
    char input[];
};
struct peer_state
{
    WendyComNetConfig config;
    uint64_t attachment;
    struct {
        enum {CLOCK_EMPTY,CLOCK_QUEUED,CLOCK_RUNNING,CLOCK_DONE} phase;
        uint64_t attachment;
        int64_t started_us;
        esp_err_t result;
        struct wendy_pki_mesh_identity identity;
        char relay_host[64];
    } clock;
    struct netif netif;
    struct wn_selection *selection;
    int candidate_index;
    struct wn_assembler assembler;
    struct wendy_pki_mesh_identity identity;
    wendy_pki_connection *connection;
    struct peer_state *owner,*next;
    atomic_bool node_active,setup_pending,setup_complete;
    atomic_uint carrier_count; /* Root-owned; independent of packet readiness. */
    struct wendy_pki_mesh_identity node_identity;
    struct wnnl address_lifetime;
    struct wn_candidate candidate;
    char authenticated_peer[37];
    struct wendy_pki_stream setup_stream;
    int setup_fd,setup_result;
    bool setup_have_stream,setup_server,setup_waiting,failed;
    bool setup_connecting,hello_started;
    struct wna_channel *tls_channel;
    struct wna_session tls_state;
    struct wendy_pki_net_setup *tls_setup;
    size_t hello_out,hello_in,hello_size;
    int64_t refresh_at,setup_at;
    struct wnm_owner *mdns;
    struct wnrs *router;
    struct wnrs_node *router_node;
    struct service_query *service_query;
#if CONFIG_WENDY_NET_RECLAIM_PAYLOADS_FOR_TLS
    struct {uint64_t serial;size_t released;bool owned,processing,complete;} reclaim;
#endif
    struct wnsc_registry *service_registry;
    int64_t service_update_at;
    struct wnt_job *time_request,*time_reply;
    atomic_uint transit_bytes,transit_packets;
    struct {
        uint64_t serial;
        uint8_t device[16];
        uint16_t port;
        bool owned, complete, found, agent;
    } app_query;
    struct wnpq *queue;
    uint8_t self[16];
    char *control;
    struct wnc_carrier carrier;
    bool framed,candidate_held;
#if CONFIG_WENDY_NET_RETAIN_TLS_INPUT
    bool input_workspace_active; /* Root-owned; shares existing alignment padding. */
#endif
    uint32_t packet_id;
    uint32_t pressure_drops;
    int64_t lease_us;
    bool added;
    int listener;
    atomic_bool active;
#if CONFIG_WENDY_NET_BLE
    struct wn_ble_scope ble_scope;
    QueueHandle_t ble_reports;
    wendy_net_memory_reservation_t ble_reports_charge;
    struct wble_mesh_pipe *ble_pipe;
    uint8_t ble_advertisement[WN_BLE_ADVERTISEMENT_SIZE];
    bool ble_initialized,ble_published;
    unsigned ble_bootstrap_cursor;
#endif
    bool clock_ready;
    int64_t clock_check_at,time_bootstrap_at;
    struct time_bootstrap_job *bootstrap_time;
    struct wnne_effect netif_effect;
    atomic_bool crypto_cleanup_done;
    bool crypto_cleanup_submitted;
};
static _Atomic(struct peer_state *) state;
static atomic_bool starting;
static atomic_bool stopping,settings_ready;
static _Atomic(TaskHandle_t) identity_task;
static atomic_uint runtime_state=WendyComNetState_WENDY_COM_NET_OFF;
static atomic_uint runtime_error;
static WendyComNetConfig applied_config;
static void lifecycle_poll(void);
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static const char *TAG = "wendy_net_peer";
#if CONFIG_WENDY_NET_BLE
static void delete_ble_reports(struct peer_state *s)
{
    if(s->ble_reports){vQueueDelete(s->ble_reports);s->ble_reports=NULL;}
    wendy_net_memory_release(&s->ble_reports_charge);
}
#endif
static bool identity_live(struct peer_state *, int64_t now);
static bool node_live(struct peer_state *,int64_t now);
static esp_err_t control_clock(struct peer_state *s,struct wendy_pki_mesh_identity *identity)
{
    uint8_t nonce[32],query[128];uint64_t id;
    esp_fill_random(nonce,sizeof nonce);esp_fill_random(&id,sizeof id);id|=1;
    size_t size=wendy_pki_time_request(query,nonce);int64_t started=esp_timer_get_time();
    struct wnt_job *job=wnt_new(id,query,size,started+INT64_C(30000000));
    if(!job)return ESP_ERR_NO_MEM;
    pthread_mutex_lock(&state_lock);
    if(s->time_request || !atomic_load(&s->active)){
        pthread_mutex_unlock(&state_lock);wnt_release(job);return ESP_ERR_INVALID_STATE;
    }
    wnt_retain(job);s->time_request=job;pthread_mutex_unlock(&state_lock);
    while(!atomic_load(&job->done) && esp_timer_get_time()<job->deadline)
        vTaskDelay(1); /* One actual tick; a 5ms delay rounds to zero at100Hz. */
    pthread_mutex_lock(&state_lock);
    if(s->time_request==job){s->time_request=NULL;wnt_release(job);}
    pthread_mutex_unlock(&state_lock);
    esp_err_t result=atomic_load(&job->done) && !job->result ?
        wendy_pki_net_time_reply(identity,nonce,job->reply,job->size,started):ESP_FAIL;
    ESP_LOGI(TAG,"existing-carrier signed-time renewal: result=%s bytes=%u ms=%u",
        esp_err_to_name(result),(unsigned)job->size,(unsigned)((esp_timer_get_time()-started)/1000));
    wnt_release(job);return result;
}
static struct peer_state *node_root(struct peer_state *s)
{
    return s->owner ? s->owner:s;
}
/* Slot identity is lent to a physical setup/carrier until close. The actor
 * serializes discovery and these transitions; hold the new slot before
 * releasing an old one so a remembered index can never name another hint. */
static int reserve_candidate(struct peer_state *s,const struct wn_candidate *hint)
{
    struct wn_selection *selection=node_root(s)->selection;
    int index=wn_candidate_seen(selection,hint,esp_timer_get_time()/1000);
    if(index<0)return -1;
    if(s->candidate_held && s->candidate_index==index)return index;
    if(wn_candidate_hold(selection,(unsigned)index))return -1;
    if(s->candidate_held)wn_candidate_release(selection,(unsigned)s->candidate_index);
    s->candidate_index=index;s->candidate_held=true;return index;
}
static void release_candidate(struct peer_state *s)
{
    if(s->candidate_held)
        wn_candidate_release(node_root(s)->selection,(unsigned)s->candidate_index);
    s->candidate_held=false;s->candidate_index=-1;
}
static struct wnrs *any_router(struct peer_state *s)
{
    for(;s;s=s->next)if(atomic_load(&s->active) && s->router)return s->router;
    return NULL;
}
/* Queue payloads get first choice of RTC space. When they cannot fit, use
 * the remaining small RTC blocks for per-carrier non-DMA receive scratch. */
static bool allocate_control(struct peer_state *s)
{
#if CONFIG_WENDY_NET_PREFER_RTC_PACKET_QUEUE
    s->control=wendy_net_rtc_malloc(PEER_CONTROL_BYTES);
    if(!s->control)s->control=wendy_net_malloc(PEER_CONTROL_BYTES);
#else
    s->control=wendy_net_malloc(PEER_CONTROL_BYTES);
#endif
    return s->control!=NULL;
}
static void *allocate_packet(size_t bytes)
{
#if CONFIG_WENDY_NET_PREFER_RTC_PACKET_QUEUE
    void *packet=wendy_net_rtc_malloc(bytes);
    if(packet)return packet;
#endif
    return wendy_net_malloc(bytes);
}
static void create_packet_queue(struct peer_state *s)
{
    s->queue=wendy_net_malloc(sizeof *s->queue);
    if(s->queue)wnpq_init(s->queue,PEER_QUEUE,allocate_packet,wendy_net_free);
}
static void reset_packet_queue(struct peer_state *s)
{
    pthread_mutex_lock(&state_lock);if(s->queue)wnpq_reset(s->queue);pthread_mutex_unlock(&state_lock);
}
static void delete_packet_queue(struct peer_state *s)
{
    reset_packet_queue(s);wendy_net_free(s->queue);s->queue=NULL;
}
void wendy_net_peer_maintain(void)
{
    lifecycle_poll();
    pthread_mutex_lock(&state_lock);
    struct peer_state *s=state;
    if(!s || atomic_load(&stopping)){pthread_mutex_unlock(&state_lock);return;}
    while(s && s->clock.phase!=CLOCK_QUEUED)s=s->next;
    if(!s){pthread_mutex_unlock(&state_lock);return;}
    struct wendy_pki_mesh_identity fresh=s->clock.identity;
    char relay[sizeof s->clock.relay_host];memcpy(relay,s->clock.relay_host,sizeof relay);
    s->clock.phase=CLOCK_RUNNING;
    pthread_mutex_unlock(&state_lock);
    wendy_net_memory_scope_t previous=wendy_net_runtime_scope_enter();
    esp_err_t result;
    if(!wendy_wifi_is_connected())result=control_clock(s,&fresh);
    else
        result=wendy_pki_net_refresh_time(&fresh,relay[0] ? relay:NULL);
    ESP_LOGI(TAG,"signed time worker finished: result=%s stackfree=%u",
             esp_err_to_name(result),(unsigned)uxTaskGetStackHighWaterMark(NULL));
    pthread_mutex_lock(&state_lock);
    s->clock.identity=fresh;s->clock.result=result;s->clock.phase=CLOCK_DONE;
    pthread_mutex_unlock(&state_lock);
    wendy_net_memory_scope_leave(previous);
}
/* Actor-only completion. A retired attachment never lends its result to a
 * replacement connection. Original expiry checks continue while work waits. */
static void finish_clock(struct peer_state *s,int64_t *refresh_at)
{
    pthread_mutex_lock(&state_lock);
    if(s->clock.phase!=CLOCK_DONE){pthread_mutex_unlock(&state_lock);return;}
    if(s->clock.attachment!=s->attachment || !s->connection || !refresh_at){
        s->clock.phase=CLOCK_EMPTY;pthread_mutex_unlock(&state_lock);return;
    }
    struct wendy_pki_mesh_identity fresh=s->clock.identity;
    esp_err_t result=s->clock.result;
    int64_t started=s->clock.started_us;
    pthread_mutex_unlock(&state_lock);
    if(result==ESP_OK){
        result=wendy_pki_net_apply_time(s->connection,&fresh);
        if(result==ESP_ERR_TIMEOUT)return;
    }
    int64_t finished=esp_timer_get_time();
    pthread_mutex_lock(&state_lock);
    s->clock.phase=CLOCK_EMPTY;
    if(result==ESP_OK)s->identity=fresh;
    pthread_mutex_unlock(&state_lock);
    if(result==ESP_OK){
        wnrs_refresh(s->router,&fresh);
        *refresh_at=fresh.verified_monotonic_us+REFRESH_INTERVAL_US;
        ESP_LOGI(TAG,"signed time refreshed without pausing carrier: ms=%u heap=%u largest=%u",
            (unsigned)((finished-started)/1000),
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    }else{
        *refresh_at=finished+INT64_C(15000000);
        ESP_LOGW(TAG,"signed time refresh failed; original deadline remains in force");
    }
}
static void queue_clock(struct peer_state *s,const char *relay_host)
{
    pthread_mutex_lock(&state_lock);
    if(s->clock.phase==CLOCK_EMPTY){
        s->clock.identity=s->identity;s->clock.attachment=s->attachment;
        s->clock.started_us=esp_timer_get_time();
        snprintf(s->clock.relay_host,sizeof s->clock.relay_host,"%s",relay_host);
        s->clock.phase=CLOCK_QUEUED;
        ESP_LOGI(TAG,"signed time refresh queued; packet actor continues");
    }
    pthread_mutex_unlock(&state_lock);
}

static int planned_candidate(struct peer_state *s,struct wn_candidate *hint,
                             const char *self,const uint8_t peer_hint[4],int64_t now)
{
    (void)self;(void)peer_hint;
    /* Discovery never assigns a UUID-based passive role. Like WendyOS, both
     * peers may dial; authenticated duplicates converge in wn_link_replaces. */
    hint->passive=false;
    return wn_candidate_seen(s->selection,hint,now);
}
#if CONFIG_WENDY_NET_BLE
static void ble_report(void *context,const uint8_t address[6],uint8_t type,
                        const void *bytes,size_t size,int rssi)
{
    (void)rssi;
    struct peer_state *s=context;
    struct wn_ble_scope scope;
    pthread_mutex_lock(&state_lock);scope=s->ble_scope;pthread_mutex_unlock(&state_lock);
    struct wn_ble_hint hint;
    if(!wn_ble_adv_read(&scope,bytes,size,&hint))return;
    struct ble_seen seen={.type=type,.psm=hint.psm,.capabilities=hint.capabilities,.seen_ms=esp_timer_get_time()/1000};
    memcpy(seen.address,address,6);memcpy(seen.hint,hint.device_hint,4);
    (void)xQueueSend(s->ble_reports,&seen,0);wnad_wake();
}
static void ble_address(char out[64],const uint8_t address[6],uint8_t type)
{
    snprintf(out,64,"ble:%u:%02x:%02x:%02x:%02x:%02x:%02x",type,
        address[5],address[4],address[3],address[2],address[1],address[0]);
}
static int ble_dial(const struct wn_candidate *candidate)
{
    unsigned type,bytes[6];uint8_t address[6];
    if(sscanf(candidate->address,"ble:%u:%2x:%2x:%2x:%2x:%2x:%2x",&type,
        bytes,bytes+1,bytes+2,bytes+3,bytes+4,bytes+5)!=7 || type>3)return -1;
    for(unsigned i=0;i<6;i++)address[i]=(uint8_t)bytes[5-i];
    return wble_mesh_dial(address,(uint8_t)type,candidate->port)==ESP_OK ? 0:-1;
}
#endif
static void release_time_job(struct time_bootstrap_job *job)
{
#if CONFIG_WENDY_NET_BLE
    wble_mesh_release(job->pipe);
#endif
    wendy_net_free(job);
}
static void bootstrap_time_work(void *context)
{
    struct time_bootstrap_job *job=context;
    job->result=job->server ? wendy_pki_net_time_tunnel(&job->stream) :
                             wendy_pki_net_bootstrap_time(job->pipe ? &job->stream:NULL);
    atomic_store(&job->done,true);
}
#if CONFIG_WENDY_NET_BLE
/* Actor owns this short-lived pipe independently of native router slots. It
 * never waits for HTTPS, and releases it only after the shared worker returns. */
static void ble_time_take(struct peer_state *s,struct wble_mesh_pipe *pipe,bool server)
{
    if(s->bootstrap_time){wble_mesh_release(pipe);return;}
    struct time_bootstrap_job *job=wendy_net_calloc(1,sizeof *job);
    if(!job){wble_mesh_release(pipe);return;}
    job->pipe=pipe;job->stream=wble_mesh_stream(pipe);job->server=server;
    job->started=esp_timer_get_time();s->bootstrap_time=job;
}
#endif
/* Direct HTTPS time bootstrapping belongs to the mesh actor, independently of
 * which carrier is enabled. BLE is an optional fallback when LAN is absent. */
static void bootstrap_time_tick(struct peer_state *s,bool allow_dial)
{
    int64_t now=esp_timer_get_time();struct time_bootstrap_job *job=s->bootstrap_time;
    if(now>=s->clock_check_at){
        int ready=wendy_pki_net_time_status();
        if(ready>=0)s->clock_ready=ready>0;
        s->clock_check_at=now+INT64_C(1000000);
    }
    if(job){
        if(atomic_load(&job->done)){
            ESP_LOGI(TAG,"%s time %s finished: result=%s ms=%u heap=%u",
                job->pipe ? "BLE encrypted":"direct HTTPS",job->server ? "relay":"bootstrap",esp_err_to_name(job->result),
                (unsigned)((now-job->started)/1000),(unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
            release_time_job(job);s->bootstrap_time=NULL;
            s->clock_check_at=0;
        }else if(!job->submitted){
            if(now-job->started>INT64_C(30000000)){
                release_time_job(job);s->bootstrap_time=NULL;
            }else job->submitted=wendy_pki_io_work_submit(bootstrap_time_work,job);
        }
        return;
    }
    if(s->clock_ready || !allow_dial ||
       !wendy_conf_is_current() || wendy_pki_reset_in_progress() ||
       now<s->time_bootstrap_at || !wendy_pki_work_available())return;
    if(wendy_wifi_is_connected()){
        job=wendy_net_calloc(1,sizeof *job);
        if(job){
            job->started=now;s->bootstrap_time=job;
            s->time_bootstrap_at=now+INT64_C(15000000);
        }
        return;
    }
#if CONFIG_WENDY_NET_BLE
    if(!s->config.ble || !s->ble_initialized)return;
    int slot=wn_candidate_time(s->selection,now/1000,s->ble_bootstrap_cursor);
    if(slot>=0){
        struct wn_candidate target=s->selection->candidates[slot];target.port=WBLE_MESH_TIME_PSM;
        s->ble_bootstrap_cursor=((unsigned)slot+1)%WN_CANDIDATES;
        if(!ble_dial(&target)){
            ESP_LOGI(TAG,"dialing BLE encrypted time bootstrap: %s PSM=%u",target.address,target.port);
            s->time_bootstrap_at=now+INT64_C(10000000);
        }else s->time_bootstrap_at=now+INT64_C(1000000);
    }
#endif
}
#if CONFIG_WENDY_NET_BLE
static bool ble_admission_available(struct peer_state *root);
static void update_ble(struct peer_state *s,const char *tenant,const char *device)
{
    unsigned operation;int command_error=wble_mesh_poll_error(&operation);
    if(command_error)ESP_LOGW(TAG,"BLE host effect failed: operation=%u error=%d",operation,command_error);
    if(!s->ble_initialized){
        if(wble_mesh_init()!=ESP_OK)return;
        s->ble_initialized=true;
    }
    struct wn_ble_scope scope;uint8_t advertisement[WN_BLE_ADVERTISEMENT_SIZE];
    if(!wendy_conf_is_current() || wendy_pki_reset_in_progress() ||
        wn_ble_default_scope_init(&scope,tenant) ||
        wn_ble_adv_write_capabilities(&scope,device,CONFIG_WENDY_NET_BLE_PSM,
            (!s->bootstrap_time && wendy_wifi_is_connected() && wble_mesh_incoming_available() ? WN_BLE_TIME_RELAY:0) |
            (ble_admission_available(s) ? WN_BLE_NATIVE_ACCEPTING:0),advertisement)<0){
        if(s->ble_published)(void)wendy_ble_mesh_advertisement(NULL,0);
        s->ble_published=false;return;
    }
    pthread_mutex_lock(&state_lock);s->ble_scope=scope;pthread_mutex_unlock(&state_lock);
    /* Native admission is explicit; time discovery stays independently live
     * while cold/full. Physical management retains its own UUID/GATT service. */
    if(WENDY_NET_NON_TRANSIT){
        if(s->ble_published)(void)wendy_ble_mesh_advertisement(NULL,0);
        s->ble_published=false;
    }else if(!s->ble_published || memcmp(advertisement,s->ble_advertisement,sizeof advertisement)){
        if(wendy_ble_mesh_advertisement(advertisement,sizeof advertisement)!=ESP_OK)return;
        memcpy(s->ble_advertisement,advertisement,sizeof advertisement);s->ble_published=true;
        ESP_LOGI(TAG,"native BLE discovery published: tenant=%s PSM=%u",tenant,CONFIG_WENDY_NET_BLE_PSM);
    }
    (void)wble_mesh_scan(ble_report,s);
    struct ble_seen report;
    while(xQueueReceive(s->ble_reports,&report,0)==pdTRUE){
        struct wn_candidate hint={.medium=WN_BLE,.port=report.psm,.cost=WNR_BLE_COST,.ble_capabilities=report.capabilities};
        ble_address(hint.address,report.address,report.type);
        int slot=planned_candidate(s,&hint,device,report.hint,report.seen_ms);
        if(slot>=0 && !s->selection->candidates[slot].failures)
            ESP_LOGD(TAG,"native BLE candidate: %s PSM=%u",hint.address,hint.port);
    }
}
#endif

void wendy_net_peer_prepare_handshake(void)
{
#if CONFIG_WENDY_NET_ROUTER && CONFIG_WENDY_NET_RECLAIM_PAYLOADS_FOR_TLS
    if(heap_caps_get_free_size(MALLOC_CAP_8BIT)>=144*1024 ||
       heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)>=48*1024)return;
    pthread_mutex_lock(&state_lock);
    struct peer_state *s=state;
    if(!s || !node_live(s,esp_timer_get_time()) || s->reclaim.owned ||
       s->reclaim.serial==UINT64_MAX){pthread_mutex_unlock(&state_lock);return;}
    uint64_t serial=++s->reclaim.serial;
    s->reclaim.owned=true;s->reclaim.processing=s->reclaim.complete=false;
    s->reclaim.released=0;
    int64_t deadline=esp_timer_get_time()+INT64_C(2000000);
    while(!s->reclaim.complete && node_live(s,esp_timer_get_time()) &&
          esp_timer_get_time()<deadline){
        pthread_mutex_unlock(&state_lock);vTaskDelay(1);pthread_mutex_lock(&state_lock);
    }
    size_t released=s->reclaim.complete ? s->reclaim.released:0;
    if(s->reclaim.serial==serial)s->reclaim.owned=false;
    pthread_mutex_unlock(&state_lock);
    ESP_LOGI(TAG,"TLS handshake FIFO reclaim: bytes=%u heap=%u largest=%u",
        (unsigned)released,(unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
#endif
}
#if CONFIG_WENDY_NET_ROUTER && CONFIG_WENDY_NET_RECLAIM_PAYLOADS_FOR_TLS
static void service_reclaim(struct peer_state *s)
{
    pthread_mutex_lock(&state_lock);
    bool pending=s->reclaim.owned && !s->reclaim.processing && !s->reclaim.complete;
    uint64_t serial=s->reclaim.serial;
    if(pending)s->reclaim.processing=true;
    pthread_mutex_unlock(&state_lock);
    if(!pending)return;
    size_t released=wnrs_reclaim_payloads(s->router_node,12*1024);
    pthread_mutex_lock(&state_lock);
    if(s->reclaim.owned && s->reclaim.serial==serial){
        s->reclaim.released=released;s->reclaim.complete=true;
    }
    pthread_mutex_unlock(&state_lock);
}
#endif

static esp_err_t service_endpoint(const char *peer, uint8_t address[16], uint16_t *port, bool agent)
{
    uint8_t device[16];
    if (!peer || !address || !port || wn_uuid_parse(peer, device))
        return ESP_ERR_INVALID_ARG;
    *port = 0;
    pthread_mutex_lock(&state_lock);
    struct peer_state *s = state;
    if (!s || !node_live(s, esp_timer_get_time()) || s->app_query.owned ||
        s->app_query.serial == UINT64_MAX) {
        pthread_mutex_unlock(&state_lock);
        return ESP_ERR_INVALID_STATE;
    }
    uint64_t serial = ++s->app_query.serial;
    memcpy(s->app_query.device, device, 16);
    s->app_query.owned = true;
    s->app_query.agent = agent;
    s->app_query.complete = s->app_query.found = false;wnad_wake();
    int64_t deadline = esp_timer_get_time() + INT64_C(5000000);
    for (;;) {
        bool complete = s->app_query.complete;
        bool active = node_live(s, esp_timer_get_time());
        if (complete || !active || esp_timer_get_time() >= deadline) {
            bool found = complete && active && s->app_query.found;
            if (found) {
                *port = s->app_query.port;
                wn_address(device, address);
            }
            s->app_query.owned = false;
            pthread_mutex_unlock(&state_lock);
            return found ? ESP_OK : complete ? ESP_ERR_NOT_FOUND : ESP_ERR_TIMEOUT;
        }
        pthread_mutex_unlock(&state_lock);
        vTaskDelay(pdMS_TO_TICKS(10));
        pthread_mutex_lock(&state_lock);
        /* This owner retains the slot until consuming/cancelling it. */
        if (s->app_query.serial != serial) {
            pthread_mutex_unlock(&state_lock);
            return ESP_ERR_INVALID_STATE;
        }
    }
}
esp_err_t wendy_net_peer_app_endpoint(const char *peer, uint8_t address[16], uint16_t *port)
{
    return service_endpoint(peer, address, port, false);
}
esp_err_t wendy_net_peer_app_endpoint_now(const char *peer,uint8_t address[16],uint16_t *port)
{
    uint8_t uuid[16];struct peer_state *root=state;
    if(!root || wn_uuid_parse(peer,uuid))return ESP_ERR_INVALID_ARG;
    struct wnrs *router=any_router(root);
    if(!router || !wnrs_app_endpoint(router,uuid,port))return ESP_ERR_NOT_FOUND;
    wn_address(uuid,address);return ESP_OK;
}
esp_err_t wendy_net_peer_agent_endpoint(const char *peer, uint8_t address[16], uint16_t *port)
{
    return service_endpoint(peer, address, port, true);
}
esp_err_t wendy_net_peer_agent_endpoint_now(const char *peer,uint8_t address[16],uint16_t *port)
{
    uint8_t uuid[16];struct peer_state *root=state;
    if(!root || wn_uuid_parse(peer,uuid))return ESP_ERR_INVALID_ARG;
    struct wnrs *router=any_router(root);
    if(!router || !wnrs_agent_endpoint(router,uuid,port))return ESP_ERR_NOT_FOUND;
    wn_address(uuid,address);return ESP_OK;
}
static void service_app_query(struct peer_state *s)
{
    uint8_t device[16];
    pthread_mutex_lock(&state_lock);
    bool pending = s->app_query.owned && !s->app_query.complete;
    uint64_t serial = s->app_query.serial;
    bool agent = s->app_query.agent;
    memcpy(device, s->app_query.device, 16);
    pthread_mutex_unlock(&state_lock);
    if (!pending) return;
    uint16_t port = 0;
    struct wnrs *router=any_router(s);
    bool found=router && (agent ? wnrs_agent_endpoint(router,device,&port):
                                 wnrs_app_endpoint(router,device,&port));
    pthread_mutex_lock(&state_lock);
    if (s->app_query.owned && s->app_query.serial == serial) {
        s->app_query.port = port;
        s->app_query.found = found;
        s->app_query.complete = true;
    }
    pthread_mutex_unlock(&state_lock);
}

static void service_query_release(struct service_query *q)
{
    if(atomic_fetch_sub(&q->references,1)==1){wendy_net_free(q->output);wendy_net_free(q);}
}
static int guest_listener_owner(void *context,uint16_t port,bool datagram)
{
    (void)context;
#if CONFIG_WENDY_NET
    return wendy_net_guest_listener_owner(port,datagram);
#else
    (void)port;(void)datagram;return -1;
#endif
}
static void service_catalog_query(struct peer_state *s)
{
    pthread_mutex_lock(&state_lock);
    struct service_query *q=s->service_query;
    if(q)q->processing=true;
    pthread_mutex_unlock(&state_lock);
    if(q){
        int result=wnrs_service_action(any_router(s),&s->service_registry,q->operation,
            q->input,q->input_size,q->output,q->capacity,guest_listener_owner,NULL);
        /* An explicit edit is an event, not a periodic maintenance job. Apply
         * its latest intent in this actor turn; the manifest publisher alone
         * owns the one-second transmission limit. */
        if(!result && (q->operation==1 || q->operation==2))s->service_update_at=0;
        pthread_mutex_lock(&state_lock);
        if(s->service_query==q)s->service_query=NULL;
        q->result=result;q->complete=true;
        pthread_mutex_unlock(&state_lock);
        service_query_release(q);
    }
    int64_t now=esp_timer_get_time();
    if(now>=s->service_update_at){
        s->service_update_at=now+INT64_C(1000000);
        wnrs_service_maintain(any_router(s),&s->service_registry,guest_listener_owner,NULL);
    }
}
int wendy_net_peer_service_catalog(unsigned operation,const void *input,size_t size,char *out,size_t cap)
{
    if(operation>3 || !input || !size || size>8192 || cap>65536 || (!out && cap))return -1;
    struct service_query *q=wendy_net_calloc(1,sizeof *q+size+1);if(!q)return -2;
    atomic_init(&q->references,1);q->operation=operation;q->input_size=size;q->capacity=cap;
    memcpy(q->input,input,size);q->output=cap ? wendy_net_malloc(cap):NULL;
    if(cap && !q->output){service_query_release(q);return -2;}
    pthread_mutex_lock(&state_lock);struct peer_state *s=state;
    if(!s || atomic_load(&stopping) || !node_live(s,esp_timer_get_time()) || s->service_query){
        pthread_mutex_unlock(&state_lock);service_query_release(q);return -2;
    }
    atomic_fetch_add(&q->references,1);s->service_query=q;wnad_wake();
    int64_t deadline=esp_timer_get_time()+INT64_C(5000000);
    int result=-2;
    for(;;){
        if(q->complete){
            result=q->result;
            if(result>0 && (size_t)result<cap)memcpy(out,q->output,(size_t)result+1);
            break;
        }
        if(esp_timer_get_time()>=deadline){
            if(s->service_query==q && !q->processing){s->service_query=NULL;service_query_release(q);}
            break;
        }
        pthread_mutex_unlock(&state_lock);vTaskDelay(pdMS_TO_TICKS(10));pthread_mutex_lock(&state_lock);
    }
    pthread_mutex_unlock(&state_lock);service_query_release(q);return result;
}

/* Called with state_lock held when accessed from lwIP. The time snapshot and
 * certificate lifetime are independently bounded, including on idle links. */
static bool snapshot_live(const struct wendy_pki_mesh_identity *identity,int64_t now)
{
    int64_t elapsed=now-identity->verified_monotonic_us;
    return elapsed>=0 && elapsed<FRESH_TIME_US &&
        wendy_conf_snapshot_current(identity->config_generation) &&
        !wendy_pki_reset_in_progress() &&
        identity->verified_seconds+elapsed/1000000<identity->certificate_expires;
}
static bool identity_live(struct peer_state *s,int64_t now){return snapshot_live(&s->identity,now);}
static bool node_live(struct peer_state *s,int64_t now)
{
    return atomic_load(&s->node_active) && snapshot_live(&s->node_identity,now);
}
static bool node_address_live(struct peer_state *s,int64_t now)
{
    return wnnl_current(&s->address_lifetime,snapshot_live(&s->node_identity,now),now);
}

static err_t output(struct netif *netif, struct pbuf *p, const ip6_addr_t *destination)
{
    (void)destination;
    struct peer_state *s = state;
    struct queued_packet packet;
    if (!s || netif != &s->netif || p->tot_len < 40 || p->tot_len > WN_MTU)
        return ERR_RTE;
    packet.size = p->tot_len;
    if (pbuf_copy_partial(p, packet.bytes, packet.size, 0) != packet.size)
        return ERR_BUF;
    pthread_mutex_lock(&state_lock);
    int64_t now = esp_timer_get_time();
    bool allowed = node_address_live(s,now) &&
                   wn_ip_admits(s->self, packet.bytes, packet.size, false);
    /* The router actor checks current signed device routes when it
     * drains this bounded queue. This netif callback only admits local output. */
    /* A full bounded carrier queue is backpressure, not loss of the route.
     * ERR_RTE makes lwIP abort TCP during a multi-record certificate flight. */
    /* With no physical carrier, leave retransmission to TCP instead of
     * admitting packets into a queue that cannot currently make progress. */
    err_t result = !allowed ? ERR_RTE : !node_live(s,now) ? ERR_MEM :
        wnpq_push(s->queue,packet.bytes,packet.size)==0 ? ERR_OK : ERR_MEM;
    pthread_mutex_unlock(&state_lock);
    if(result==ERR_OK)wnad_wake();
    return result;
}
static err_t init_netif(struct netif *netif)
{
    netif->name[0] = 'w';
    netif->name[1] = 'n';
    netif->mtu = WN_MTU;
    netif->output_ip6 = output;
    /* esp_netif owns non-NULL state pointers on ESP-IDF. */
    netif->flags = 0;
    return ERR_OK;
}
struct netif_change
{
    struct tcpip_api_call_data call;
    struct peer_state *s;
    bool up, remove;
};
static err_t change_netif(struct tcpip_api_call_data *call)
{
    struct netif_change *change = (struct netif_change *)call;
    struct peer_state *s = change->s;
    if (change->remove)
    {
        if (s->added)
            netif_remove(&s->netif);
        s->added = false;
        return ERR_OK;
    }
    if (!s->added)
    {
        if (!netif_add_noaddr(&s->netif, NULL, init_netif, tcpip_input))
            return ERR_IF;
        s->added = true;
    }
    if (change->up)
    {
        ip6_addr_t address = {0};
        wn_address(s->self, (uint8_t *)address.addr);
        netif_ip6_addr_set(&s->netif, 0, &address);
        netif_ip6_addr_set_state(&s->netif, 0, IP6_ADDR_PREFERRED);
        netif_set_link_up(&s->netif);
        netif_set_up(&s->netif);
    }
    else
    {
        netif_set_down(&s->netif);
        netif_set_link_down(&s->netif);
        netif_ip6_addr_set_state(&s->netif, 0, IP6_ADDR_INVALID);
    }
    return ERR_OK;
}
static void netif_effect_complete(void *context)
{
    struct peer_state *root=context;
    struct netif_change change={.s=root,.up=root->netif_effect.submitted==WNNE_UP,
        .remove=root->netif_effect.submitted==WNNE_REMOVED};
    err_t result=change_netif(&change.call);
    /* This is the last access to root: acknowledgment may let OFF free it. */
    wnne_complete(&root->netif_effect,result);wnad_wake();
}
static void poll_netif_effect(struct peer_state *root)
{
    int64_t now=esp_timer_get_time();
    if(wnne_next(&root->netif_effect,now))
        wnne_submitted(&root->netif_effect,
            tcpip_try_callback(netif_effect_complete,root)==ERR_OK,now);
}
struct netif *lwip_hook_ip6_route(const ip6_addr_t *source, const ip6_addr_t *destination)
{
    (void)source;
    static const uint8_t prefix[] = {0xfd, 0x45, 0xb8, 0x91, 0x56};
    /* Return the rejecting interface while offline too: mesh traffic must not
     * fall through to an infrastructure default route. */
    static struct netif rejecting = {.mtu = WN_MTU, .output_ip6 = output};
    struct peer_state *s = state;
    const uint8_t *address=(const uint8_t *)destination->addr;
    bool mesh=!memcmp(address,prefix,sizeof prefix) && (address[5]==0x7f || address[5]==0x80);
    return mesh ? s ? &s->netif : &rejecting : NULL;
}
static int router_send(void *context,const void *data,size_t size,bool is_control)
{
    struct peer_state *s=context;
    return s->framed ? wnc_enqueue_priority(&s->carrier,data,size,is_control):-1;
}
static void time_backend(void *argument)
{
    struct wnt_job *job=argument;
    job->reply_external=true; /* HTTP result keeps its PKI/libc ownership ABI. */
    /* The HTTP response API returns raw storage. Reserve its enforced maximum
     * before requesting it, retaining that charge through the final consumer. */
    job->result=wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),
        &job->reply_charge,2*(65536+4096),WENDY_NET_MEMORY_INTERNAL) &&
        wendy_pki_time_query(job->query,job->query_size,&job->reply,&job->size)==ESP_OK ? 0:-1;
    atomic_store(&job->done,true);wnt_release(job);
}
static int time_receive(void *context,const struct wn_doc *doc,unsigned at)
{
    struct peer_state *s=context;int op=wn_doc_member(doc,at,"op");
    pthread_mutex_lock(&state_lock);
    if(wn_doc_equal(doc,op,"request")){
        if(!s->time_reply)s->time_reply=wnt_request_read(doc,at,esp_timer_get_time()+INT64_C(30000000));
    }else if(wn_doc_equal(doc,op,"next")){
        uint64_t id,offset;struct wnt_job *job=s->time_reply;
        if(job && !wn_doc_u64(doc,wn_doc_member(doc,at,"id"),&id) && id==job->id &&
           !wn_doc_u64(doc,wn_doc_member(doc,at,"offset"),&offset) && offset==job->offset)job->sent=false;
    }else if(s->time_request){
        if(wnt_reply_read(s->time_request,doc,at)){
            s->time_request->result=-1;atomic_store(&s->time_request->done,true);
        }
    }
    pthread_mutex_unlock(&state_lock);return 0;
}
static void time_tick(struct peer_state *s,int64_t now)
{
    char text[1600];
    pthread_mutex_lock(&state_lock);
    struct wnt_job *job=s->time_request;
    if(job && !job->sent && !atomic_load(&job->done)){
        int n=wnt_request_write(job,text,sizeof text);
        if(n>0 && !router_send(s,text,(size_t)n,true))job->sent=true;
    }
    job=s->time_reply;
    if(job && now>=job->deadline){s->time_reply=NULL;wnt_release(job);job=NULL;}
    if(job && !job->started){
        wnt_retain(job);
        if(wendy_pki_io_work_submit(time_backend,job))job->started=true;else wnt_release(job);
    }
    if(job && atomic_load(&job->done) && !job->sent && s->carrier.queued<=1024){
        int n=wnt_reply_write(job,text,sizeof text);
        if(n>0 && !router_send(s,text,(size_t)n,true)){
            size_t chunk=job->size-job->offset;if(chunk>1024)chunk=1024;
            job->offset+=chunk;job->sent=true;
            if(job->result || job->offset==job->size){s->time_reply=NULL;wnt_release(job);}
        }
    }
    pthread_mutex_unlock(&state_lock);
}
static ssize_t carrier_read(void *ctx,void *data,size_t size)
{
    struct peer_state *s=ctx;
    /* Router callbacks can lend this exact context during the current actor
     * pass, including while another link is being processed. */
    if(wncrypto_borrowed(s->connection))return -2;
    if(wnrs_receive_paused(s->router))return -2;
    return wendy_pki_read(s->connection,data,size);
}
static ssize_t carrier_write(void *ctx,const void *data,size_t size)
{
    struct peer_state *s=ctx;
    if(wncrypto_borrowed(s->connection))return -3;
    return wendy_pki_write(s->connection,data,size);
}
static struct peer_state *route_link(struct peer_state *root,uint64_t id)
{
    for(struct peer_state *link=root;link;link=link->next)
        if(atomic_load(&link->active) && link->router && wnrs_link_id(link->router)==id)
            return link;
    return NULL;
}
static int enqueue_ip(struct peer_state *root,struct peer_state *link,const void *bytes,size_t size)
{
    if(!link)return 0;
    int result=wnc_enqueue_packet(&link->carrier,bytes,size,++root->packet_id);
    if(result==WNC_NOMEM || result==WNC_LIMIT){
        if(++root->pressure_drops==1 || !(root->pressure_drops%16))
            ESP_LOGW(TAG,"IP packet dropped under pressure: drops=%u free=%u",
                (unsigned)root->pressure_drops,(unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
        return 0;
    }
    if(result)link->failed=true;
    return 0;
}
static int receive_frame(void *ctx,const void *data,size_t size,bool is_control)
{
    struct peer_state *s=ctx;
    if(is_control) {
        return wnrs_control(s->router,data,size);
    }
    const uint8_t *datagram=data;
    if(datagram[0]==2)return wnrs_routing(s->router,datagram+1,size-1);
    int n = wn_assemble(&s->assembler, datagram, size, esp_timer_get_time());
    if (n < 0) {
        ESP_LOGW(TAG,"invalid IP fragment: bytes=%u",(unsigned)size);
        return -1;
    }
    if (!n)
        return 0;
    if (!atomic_load(&s->active) || s->lease_us <= esp_timer_get_time())
        return -1;
    struct peer_state *root=node_root(s);uint64_t outgoing=0;
    int routed=wnrs_packet_route(s->router,s->assembler.packet,n,true,&outgoing);
    if(routed==1){
        unsigned packets=atomic_fetch_add(&root->transit_packets,1)+1;
        unsigned bytes=atomic_fetch_add(&root->transit_bytes,(unsigned)n)+(unsigned)n;
        if(packets==1 || !(packets%64))
            ESP_LOGI(TAG,"IPv6 transit: packets=%u bytes=%u in_link=%llu out_link=%llu",
                packets,bytes,
                (unsigned long long)wnrs_link_id(s->router),(unsigned long long)outgoing);
        return enqueue_ip(root,route_link(root,outgoing),s->assembler.packet,n);
    }
    if(routed)return 0;
    struct peer_state *destination=node_root(s);
    struct pbuf *packet = pbuf_alloc(PBUF_RAW, n, PBUF_RAM);
    if (packet)
    {
        if (pbuf_take(packet, s->assembler.packet, n) != ERR_OK ||
            destination->netif.input(packet, &destination->netif) != ERR_OK)
            pbuf_free(packet);
    }
    return 0;
}
/* One bounded TLS worker owns both directions. Extra incoming attempts are
 * closed while an attachment is active, rather than retaining idle handshakes. */
static void discovery_results(struct peer_state *s,const char *tenant,const char *self,mdns_result_t *results)
{
    for (mdns_result_t *r = results; r; r = r->next)
    {
        if (!r->ttl || !r->port)
            continue;
        const char *keys[] = {"version", "protocol", "principal", "role", "ble", "ble_psm"};
        const char *values[6] = {0};
        bool invalid = false;
        for (size_t i = 0; i < r->txt_count; i++)
            for (unsigned j = 0; j < 6; j++)
            {
                if (!r->txt[i].key || strcmp(r->txt[i].key, keys[j]))
                    continue;
                if (values[j] || !r->txt[i].value || !r->txt_value_len ||
                    strlen(r->txt[i].value) != r->txt_value_len[i])
                    invalid = true;
                values[j] = r->txt[i].value;
            }
        uint8_t device[16];
        if (invalid || !values[0] || strcmp(values[0], "1") || !values[1] ||
            strcmp(values[1], "tls-v1") || !values[2] ||
            wn_principal_device(values[2], tenant, device) || !values[3] ||
            (strcmp(values[3], "router") && strcmp(values[3], "embedded-router")))
            continue;
        struct wn_candidate candidate = {.medium = WN_LAN, .port = r->port, .cost = 128};
        wn_uuid_format(device, candidate.device);
        if (!strcmp(candidate.device, self))
            continue;
#if CONFIG_WENDY_NET_BLE
        if(values[4] && values[5]){
            unsigned type,bytes[6],psm;int end=0,port_end=0;
            if(sscanf(values[4],"ble:%u:%2x:%2x:%2x:%2x:%2x:%2x%n",&type,
                bytes,bytes+1,bytes+2,bytes+3,bytes+4,bytes+5,&end)==7 &&
               !values[4][end] && type<=1 &&
               sscanf(values[5],"%u%n",&psm,&port_end)==1 && !values[5][port_end] &&
               psm>=128 && psm<=255 && strlen(values[4])<sizeof candidate.address){
                struct wn_candidate radio={.medium=WN_BLE,.port=(uint16_t)psm,
                    .cost=WNR_BLE_COST,.passive=true};
                memcpy(radio.device,candidate.device,sizeof radio.device);
                strcpy(radio.address,values[4]);int64_t seen=0;
                /* Correlate discovery sources without inventing a radio
                 * sighting. A new placeholder stays passive until BLE reports
                 * this address; refreshes preserve its actual seen/cooldown. */
                for(unsigned i=0;i<WN_CANDIDATES;i++){
                    const struct wn_candidate *old=&s->selection->candidates[i];
                    if(old->medium==WN_BLE && old->port==radio.port &&
                       !strcmp(old->address,radio.address)){
                        seen=old->seen_ms;radio.passive=old->passive;break;
                    }
                }
                (void)wn_candidate_seen(s->selection,&radio,seen);
            }
        }
#endif
        for (mdns_ip_addr_t *a = r->addr; a; a = a->next)
        {
            if (a->addr.type != ESP_IPADDR_TYPE_V4)
                continue;
            const uint8_t *ip = (const uint8_t *)&a->addr.u_addr.ip4.addr;
            if (!ip[0] || ip[0] == 127 || ip[0] >= 224 || (ip[0] == 169 && ip[1] == 254))
                continue;
            snprintf(candidate.address, sizeof candidate.address, "%u.%u.%u.%u", ip[0], ip[1],
                     ip[2], ip[3]);
            planned_candidate(s,&candidate,self,device,esp_timer_get_time()/1000);
        }
    }
}

static void close_listener(struct peer_state *s)
{
    if(s->listener>=0) close(s->listener);
    s->listener=-1;
}
static int update_listener(struct peer_state *s,const char *tenant,const char *device)
{
    char principal[106];
    if(!s->config.infrastructure_wifi || wn_principal(tenant,device,principal)<0 || !wendy_wifi_is_connected() ||
        !wendy_conf_is_current() || wendy_pki_reset_in_progress()) {
        close_listener(s);return -1;
    }
    if(WENDY_NET_NON_TRANSIT){
        /* Availability still enables browsing and outgoing candidates. A
         * constrained attachment never publishes or accepts a carrier. */
        close_listener(s);return 0;
    }
    if(s->listener<0) {
        int fd=socket(AF_INET,SOCK_STREAM,0), yes=1;
        struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(43024),
            .sin_addr.s_addr=htonl(INADDR_ANY)};
        if(fd<0) return -1;
        if(fd>=FD_SETSIZE || setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) ||
            bind(fd,(struct sockaddr*)&addr,sizeof addr) || listen(fd,1) ||
            fcntl(fd,F_SETFL,O_NONBLOCK)<0) {close(fd);return -1;}
        s->listener=fd;
    }
    return 0;
}
static void close_session(struct peer_state *s,int candidate)
{
    candidate=s->candidate_held ? s->candidate_index:-1;
    /* Candidate failure history belongs to failed connection attempts. A
     * ready carrier retirement, duplicate skip, cancellation or net-off is not
     * evidence that its discovered endpoint failed. */
    bool failed_attempt=!s->framed && !atomic_load(&stopping);
    failed_attempt=failed_attempt && !s->tls_state.cancel;

    pthread_mutex_lock(&state_lock);
    ++s->attachment;
    if(s->clock.phase==CLOCK_QUEUED)s->clock.phase=CLOCK_EMPTY;
    if(s->time_request){s->time_request->result=-1;atomic_store(&s->time_request->done,true);
        wnt_release(s->time_request);s->time_request=NULL;}
    wnt_release(s->time_reply);s->time_reply=NULL;
    if(atomic_exchange(&s->active,false))
        atomic_fetch_sub(&node_root(s)->carrier_count,1);
    s->lease_us=0;
    pthread_mutex_unlock(&state_lock);
    wnc_deinit(&s->carrier);s->framed=false;
    wnrs_close(s->router);s->router=NULL;
    wendy_pki_close(s->connection);s->connection=NULL;
    wendy_net_free(s->tls_channel);s->tls_channel=NULL;
#if CONFIG_WENDY_NET_BLE
    if(s->ble_pipe){wble_mesh_release(s->ble_pipe);s->ble_pipe=NULL;}
#endif
    struct peer_state *root=node_root(s);
    memset(&s->assembler,0,sizeof s->assembler);
    if(candidate>=0){
        int64_t now=esp_timer_get_time()/1000;
        if(failed_attempt)wn_candidate_failed(root->selection,candidate,now);
        else root->selection->candidates[candidate].retry_ms=now+5000;
        if(root->selection->active==candidate)root->selection->active=-1;
    }
    release_candidate(s);
    ESP_LOGI(TAG,"attachment closed; stack free=%u",(unsigned)uxTaskGetStackHighWaterMark(NULL));
}
static bool clock_idle(struct peer_state *link)
{
    pthread_mutex_lock(&state_lock);bool idle=link->clock.phase==CLOCK_EMPTY;
    pthread_mutex_unlock(&state_lock);return idle;
}
static bool slot_free(struct peer_state *link)
{
    return !link->candidate_held && !atomic_load(&link->active) && !atomic_load(&link->setup_pending) &&
        !link->setup_waiting && !link->connection && clock_idle(link);
}
static bool capacity_available(struct peer_state *root)
{
    unsigned count=0;
    for(struct peer_state *link=root;link;link=link->next){
        count++;if(slot_free(link))return true;
    }
    return count<root->config.max_links;
}
static bool medium_available(struct peer_state *root,enum wn_medium medium)
{
    unsigned active=0,total=0;
    for(struct peer_state *s=root;s;s=s->next)if(!slot_free(s)){
        total++;if(s->candidate.medium==medium)active++;
    }
    if(total>=root->config.max_links)return false;
    if(medium==WN_BLE)return root->config.ble && active<root->config.ble_links;
    if(medium==WN_NAN)return false; /* No NAN runtime in this delivery. */
    return root->config.infrastructure_wifi && active<root->config.wifi_links;
}
#if CONFIG_WENDY_NET_BLE
static bool ble_discovery_available(struct peer_state *root)
{
    unsigned ble=0,total=0;
    /* Pending reservations do not close discovery: filling the final slot
     * must never invalidate an already submitted GAP dial. */
    for(struct peer_state *link=root;link;link=link->next)
        if(atomic_load(&link->active)){
            total++;if(link->candidate.medium==WN_BLE)ble++;
        }
    return ble<root->config.ble_links && total<root->config.max_links;
}
#endif
static struct peer_state *reserve_slot(struct peer_state *root)
{
    unsigned count=0;struct peer_state *last=NULL;
    for(struct peer_state *link=root;link;link=link->next){
        count++;last=link;if(slot_free(link))return link;
    }
    if(count>=root->config.max_links)return NULL;
    struct peer_state *link=wendy_net_calloc(1,sizeof *link);if(!link)return NULL;
    if(!allocate_control(link)){wendy_net_free(link);return NULL;}
    link->owner=root;link->queue=root->queue;link->selection=root->selection;link->listener=-1;link->setup_fd=-1;link->candidate_index=-1;
    pthread_mutex_lock(&state_lock);last->next=link;pthread_mutex_unlock(&state_lock);
    return link;
}
#if CONFIG_WENDY_NET_RETAIN_TLS_INPUT
static void update_input_workspace(struct peer_state *root,bool wanted)
{
    if(root->input_workspace_active==wanted){
        /* A baseline TLS allocation predating mesh startup may have delayed
         * the reserve. Refill only here, under the actor's allocation scope,
         * after that finite foreign loan has returned. */
        if(wanted)wendy_pki_input_workspace_active(true);
        return;
    }
    root->input_workspace_active=wanted;
    wendy_pki_input_workspace_active(wanted);
    ESP_LOGI(TAG,"TLS input workspace: active=%u cached=%u heap=%u largest=%u",
        (unsigned)wanted,(unsigned)wendy_pki_input_workspace_cached_bytes(),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}
#endif
static void update_node_status(struct peer_state *root)
{
    bool was=atomic_load(&root->node_active),up=false;
    pthread_mutex_lock(&state_lock);
    int64_t now=esp_timer_get_time();
    for(struct peer_state *link=root;link;link=link->next)
        if(atomic_load(&link->active) && identity_live(link,now)){
            if(!up || link->identity.verified_monotonic_us>root->node_identity.verified_monotonic_us)
                root->node_identity=link->identity;
            up=true;
        }
    atomic_store(&root->node_active,up);
    bool address_was=root->address_lifetime.up;
    bool address_up=wnnl_update(&root->address_lifetime,up,
        snapshot_live(&root->node_identity,now),now);
#if CONFIG_WENDY_NET_RETAIN_TLS_INPUT
    bool workspace_wanted=address_up;
    for(struct peer_state *link=root;link;link=link->next)
        if(link->setup_waiting || atomic_load(&link->setup_pending))workspace_wanted=true;
#endif
    if(!up && root->app_query.owned){root->app_query.found=false;root->app_query.complete=true;}
    pthread_mutex_unlock(&state_lock);
#if CONFIG_WENDY_NET_RETAIN_TLS_INPUT
    update_input_workspace(root,workspace_wanted);
#endif
    if(was!=up){
        if(!up)reset_packet_queue(root);
    }
    if(address_was!=address_up){
        wnne_desire(&root->netif_effect,address_up ? WNNE_UP:WNNE_DOWN);
    }
    poll_netif_effect(root);
    if(was!=up || address_was!=address_up)
        ESP_LOGI(TAG,"mesh address: up=%u carriers=%u recovery_ms=%u",
            (unsigned)address_up,(unsigned)up,
            (unsigned)(!up && address_up ? (root->address_lifetime.until-now)/1000:0));
}
/* A queued job can wait behind app/management work while heap use changes. */
#define NET_SETUP_DEFERRED INT_MIN
static bool setup_room(struct peer_state *root);
static void setup_work(void *context)
{
    struct peer_state *link=context;
    if(link->tls_state.phase==WNA_PREPARE){
        struct wendy_pki_stream bio={.context=link->tls_channel,
            .read=wna_read,.write=wna_write,.wait=wnad_no_wait};
        esp_err_t result=wendy_pki_net_begin(&bio,link->setup_server,
            link->candidate.device[0] ? link->candidate.device:NULL,false,&link->tls_setup);
        link->setup_result=result==ESP_OK ? 0:result==ESP_ERR_TIMEOUT ? 2:-1;
    }else link->setup_result=wendy_pki_net_step(link->tls_setup);
    atomic_store(&link->setup_complete,true);
}
/* Header and hello are ordinary resumable application bytes. A blocked peer
 * retains only this link's offsets, never the actor call stack. */
static int setup_hello(struct peer_state *link)
{
    if(link->framed)return 0;
    if(!link->hello_started){
        link->connection=wendy_pki_net_take(link->tls_setup,&link->identity);link->tls_setup=NULL;
        wnad_handshake_release(link);
        if(!link->connection || wn_uuid_parse(link->identity.device,link->self))return -1;
        memcpy(link->authenticated_peer,link->identity.peer,37);
        /* Remember the verified address binding before exchanging hello: a
         * peer can retire this redundant carrier during hello. Held discovery
         * rows intentionally ignore unauthenticated advertisement identities. */
        if(link->candidate_held && wn_candidate_authenticated(node_root(link)->selection,
                (unsigned)link->candidate_index,link->authenticated_peer))return -1;
        int n=wn_router_hello_write(link->identity.device,link->authenticated_peer,link->control+4,PEER_CONTROL_BYTES-4);
        if(n<0)return -1;
        wn_put32((uint8_t *)link->control,(uint32_t)n);link->hello_size=(size_t)n+4;
        link->hello_started=true;
    }
    if(link->hello_out<link->hello_size){
        ssize_t n=wendy_pki_write(link->connection,link->control+link->hello_out,link->hello_size-link->hello_out);
        if(n>0){link->hello_out+=(size_t)n;}
        else if(n!=-2 && n!=-3)return -1;
        return 1;
    }
    size_t wanted=link->hello_in<4 ? 4:4+wn_get32((uint8_t *)link->control);
    if(wanted>PEER_CONTROL_BYTES || wanted<4)return -1;
    if(link->hello_in<wanted){
        ssize_t n=wendy_pki_read(link->connection,link->control+link->hello_in,wanted-link->hello_in);
        if(n>0){link->hello_in+=(size_t)n;}
        else if(n!=-2 && n!=-3)return -1;
        return 1;
    }
    if(wanted==4 || wn_router_hello_check(link->control+4,wanted-4,link->identity.device,link->authenticated_peer))return -1;
    struct wnc_io io={.context=link,.read=carrier_read,.write=carrier_write};
    if(wnc_init(&link->carrier,&io,link->control,PEER_CONTROL_BYTES,8192,65536) ||
       wnc_fair_scheduler(&link->carrier,CONFIG_WENDY_NET_ROUTING_QUEUE_FRAMES))return -1;
    link->carrier.stall_timeout_us=INT64_C(30000000);
    link->carrier.frame_timeout_us=INT64_C(90000000);link->carrier.priority_reserve=2048;
    link->framed=true;return 0;
}
static int advance_setup(struct peer_state *link,int64_t now)
{
    if(link->tls_state.lent){
        if(!atomic_load(&link->setup_complete))return 1;
        atomic_store(&link->setup_pending,false);
        wna_completed(&link->tls_state,link->setup_result);
        if(link->setup_result==2){link->tls_state.retry_at=(uint64_t)now+50000;wnad_handshake_release(link);}
    }
    if(link->setup_connecting){
        int connected=wnad_connected(link->setup_fd);
        if(connected<=0)return connected ? -1:1;
        link->setup_connecting=false;
    }
    int moved=wnad_channel_io(link->tls_channel,link->setup_fd,
        link->setup_have_stream ? &link->setup_stream:NULL);
    if(moved<0)return -1;

    if(link->tls_state.phase==WNA_READY){
        if(link->tls_state.cancel || now>=(int64_t)link->tls_state.deadline)return -1;
        return setup_hello(link);
    }
    enum wna_effect effect=wna_next(&link->tls_state,(uint64_t)now,
        link->tls_channel->input.size || link->tls_channel->eof,wna_buffer_space(&link->tls_channel->output)!=0);
    if(effect==WNA_CLOSE)return -1;
    if(effect==WNA_CRYPTO_PREPARE && !wnad_handshake_claim(link))return 1;
    if(effect==WNA_CRYPTO_PREPARE || effect==WNA_CRYPTO_STEP){
        atomic_store(&link->setup_complete,false);
        /* Queue submission is an outer-driver effect. No ownership transfer
         * occurs if the one-slot worker rejects a busy submission. */
        if(wendy_pki_work_submit(setup_work,link)){
            wna_lend(&link->tls_state);atomic_store(&link->setup_pending,true);
        }
    }
    return 1;
}
static void begin_setup(struct peer_state *link,const struct wn_candidate *candidate,int fd)
{
    link->candidate=*candidate;link->authenticated_peer[0]=0;
    int index=reserve_candidate(link,candidate);
    link->tls_channel=index>=0 ? wendy_net_calloc(1,sizeof *link->tls_channel):NULL;
    link->tls_state=(struct wna_session){.phase=WNA_PREPARE,.deadline=(uint64_t)esp_timer_get_time()+UINT64_C(60000000)};
    link->hello_started=false;link->hello_in=link->hello_out=link->hello_size=0;
    link->setup_connecting=false;
    if(index>=0 && !link->setup_have_stream && fd<0)
        fd=wnad_connect(candidate->address,candidate->port,&link->setup_connecting);
    if(!link->setup_have_stream && fd>=0 && !wnad_prepare_socket(fd)){close(fd);fd=-1;}
    link->setup_fd=fd;
    if(!link->tls_channel || (!link->setup_have_stream && fd<0))link->tls_state.phase=WNA_FAILED;
    link->setup_waiting=true;link->setup_at=esp_timer_get_time();link->failed=false;
    atomic_store(&link->setup_complete,false);
#if CONFIG_WENDY_NET_RETAIN_TLS_INPUT
    /* Reserve before a worker can parse credentials or consume the first
     * flight. Its released input must remain reusable before admission too. */
    update_input_workspace(node_root(link),true);
#endif
}
static void retire_link(struct peer_state *link)
{
    if(link->tls_state.lent){link->tls_state.cancel=true;return;}
    if(wncrypto_borrowed(link->connection)){link->failed=true;return;}
    wendy_pki_net_dispose(link->tls_setup);link->tls_setup=NULL;
    wnad_handshake_release(link);
    if(link->setup_fd>=0){close(link->setup_fd);link->setup_fd=-1;}
    link->setup_waiting=false;atomic_store(&link->setup_pending,false);
    atomic_store(&link->setup_complete,false);
    close_session(link,link->candidate_index);link->candidate_index=-1;link->failed=false;
}
static bool cheaper_ip_carrier(struct peer_state *root,const char *peer,uint16_t cost)
{
#if !CONFIG_WENDY_NET_KEEP_REDUNDANT_BLE
    if(!peer[0])return false;
    for(struct peer_state *link=root;link;link=link->next)
        if(atomic_load(&link->active) && link->candidate.medium!=WN_BLE &&
           link->candidate.cost<cost && !strcmp(link->authenticated_peer,peer) &&
           identity_live(link,esp_timer_get_time()))return true;
#else
    (void)root;(void)peer;(void)cost;
#endif
    return false;
}
static int admit_link(struct peer_state *root,struct peer_state *link)
{
    if(wnrs_node_busy(root->router_node))return 1;
    if(link->setup_result || !identity_live(link,esp_timer_get_time()))return -1;
    memcpy(link->candidate.device,link->authenticated_peer,37);
    /* Remember a successfully authenticated radio even when an existing IP
     * path makes admission redundant. Repeated discovery can then skip it. */
    int index=reserve_candidate(link,&link->candidate);
    if(index<0)return -1;
    if(link->candidate.medium==WN_BLE &&
       cheaper_ip_carrier(root,link->authenticated_peer,link->candidate.cost)){
        ESP_LOGI(TAG,"keeping cheaper authenticated IP carrier: peer=%s",
                 link->authenticated_peer);
        return -1;
    }
    for(struct peer_state *other=root;other;other=other->next){
        if(other==link || !atomic_load(&other->active) ||
           other->candidate.medium!=link->candidate.medium ||
           strcmp(other->authenticated_peer,link->authenticated_peer))continue;
        if(!wn_link_replaces(link->identity.device,link->authenticated_peer,
                             other->setup_server,link->setup_server)){
            ESP_LOGI(TAG,"keeping authenticated incumbent: peer=%s medium=%u",
                     link->authenticated_peer,(unsigned)link->candidate.medium);
            return -1;
        }
    }
    if(wn_candidate_commit(root->selection,index,link->candidate.device))return -1;
    root->selection->active=-1;link->candidate_index=index;
    if(wnrs_open(&link->router,&root->router_node,link->connection,&link->identity,
                 link->candidate.device,link->candidate.cost,router_send,link))return -1;
    wnrs_time_handler(link->router,time_receive);
    pthread_mutex_lock(&state_lock);
    memcpy(root->self,link->self,16);link->lease_us=INT64_MAX;
    if(!atomic_exchange(&link->active,true))atomic_fetch_add(&root->carrier_count,1);
    pthread_mutex_unlock(&state_lock);
    link->refresh_at=link->identity.verified_monotonic_us+REFRESH_INTERVAL_US;
    /* Replace only after the new router session is usable. Redundant BLE
     * remains discoverable for a fresh dial after the cheaper IP link fails. */
    for(struct peer_state *other=root;other;other=other->next){
        if(other==link || !atomic_load(&other->active) ||
           strcmp(other->authenticated_peer,link->authenticated_peer))continue;
        bool replace=other->candidate.medium==link->candidate.medium;
#if !CONFIG_WENDY_NET_KEEP_REDUNDANT_BLE
        replace=replace || (other->candidate.medium==WN_BLE &&
            link->candidate.medium!=WN_BLE &&
            link->candidate.cost<other->candidate.cost);
#endif
        if(!replace)continue;
        ESP_LOGI(TAG,"retiring redundant authenticated carrier: peer=%s medium=%u",
                 link->authenticated_peer,(unsigned)other->candidate.medium);
        retire_link(other);
    }
    /* A retired duplicate may share the same discovery slot. */
    (void)wn_candidate_commit(root->selection,index,link->candidate.device);
    root->selection->active=-1;
    unsigned active=0;for(struct peer_state *p=root;p;p=p->next)if(atomic_load(&p->active))active++;
    ESP_LOGI(TAG,"authenticated carrier admitted: peer=%s medium=%s link=%llu active=%u",
        link->candidate.device,link->setup_have_stream ? "BLE":link->candidate.medium==WN_NAN ? "NAN":"LAN",
        (unsigned long long)wnrs_link_id(link->router),active);
    return 0;
}
static bool candidate_used(struct peer_state *root,const struct wn_candidate *candidate)
{
    if(candidate->medium==WN_BLE &&
       cheaper_ip_carrier(root,candidate->device,candidate->cost))return true;
    for(struct peer_state *link=root;link;link=link->next)
        if((atomic_load(&link->active) || atomic_load(&link->setup_pending) || link->setup_waiting) &&
           link->candidate.medium==candidate->medium &&
           ((link->candidate.port==candidate->port &&
             !strcmp(link->candidate.address,candidate->address)) ||
            (candidate->device[0] &&
             !strcmp(link->candidate.device,candidate->device))))return true;
    return false;
}
static int additional_candidate(struct peer_state *root,int64_t now,bool lan)
{
    int best=-1;unsigned order[WN_CANDIDATES];
    unsigned count=wn_candidate_order(root->selection,now,esp_random(),order);
    for(unsigned at=0;at<count;at++){
        unsigned i=order[at];
        const struct wn_candidate *candidate=&root->selection->candidates[i];
        if(!medium_available(root,candidate->medium))continue;
        if(candidate->passive || (candidate->medium==WN_LAN && !lan))continue;
        if(!candidate->address[0] || now<candidate->seen_ms || now-candidate->seen_ms>=30000 ||
            now<candidate->retry_ms || candidate_used(root,candidate))continue;
        if(best<0 || candidate->cost<root->selection->candidates[best].cost)best=(int)i;
    }
    return best;
}
static void discovery_ready(mdns_search_once_t *search){(void)search;wnad_wake();}
static void mdns_collect(struct peer_state *root,bool browse,const char *tenant,const char *device)
{
    wnm_collect(root->mdns);
    mdns_result_t *results;const char *query_tenant,*query_self;
    if(wnm_results(root->mdns,&results,&query_tenant,&query_self)){
        /* Only immutable finished results are borrowed; no SDK method runs
         * here. Copy into the existing bounded candidate table before ACK. */
        if(browse && !strcmp(tenant,query_tenant) && !strcmp(device,query_self))
            discovery_results(root,query_tenant,query_self,results);
        wnm_consumed(root->mdns);
    }
}
static void discover_async(struct peer_state *root,bool lan,const char *tenant,const char *device)
{
    struct wnm_intent intent={.browse=lan};
    snprintf(intent.tenant,sizeof intent.tenant,"%s",tenant);snprintf(intent.self,sizeof intent.self,"%s",device);
    mdns_collect(root,lan,tenant,device);
    struct wnm_advertisement *ad=&intent.advertisement;
    if(lan && root->listener>=0){
        char scope[64];uint8_t hash[32];
        int n=snprintf(scope,sizeof scope,"tenant:%s:default",tenant);
        if(n>0 && (size_t)n<sizeof scope && !wendy_pki_sha256((uint8_t*)scope,(size_t)n,hash) &&
           wn_principal(tenant,device,ad->principal)>0){
            for(unsigned i=0;i<8;i++)snprintf(ad->mesh+2*i,3,"%02x",hash[i]);
            snprintf(ad->instance,sizeof ad->instance,"wendy-net-tls-%.36s",device);ad->enabled=true;
#if CONFIG_WENDY_NET_BLE
            uint8_t address[6];
            if(root->config.ble && esp_read_mac(address,ESP_MAC_BT)==ESP_OK){
                snprintf(ad->radio,sizeof ad->radio,"ble:0:%02x:%02x:%02x:%02x:%02x:%02x",
                    address[0],address[1],address[2],address[3],address[4],address[5]);
                snprintf(ad->psm,sizeof ad->psm,"%u",CONFIG_WENDY_NET_BLE_PSM);
            }
#endif
        }
    }
    wnm_drive(root->mdns,&intent,esp_timer_get_time());
}
static void collect_slots(struct peer_state *root)
{
    pthread_mutex_lock(&state_lock);
    for(struct peer_state **at=&root->next;*at;){
        struct peer_state *link=*at;
        if(!atomic_load(&link->active) && !atomic_load(&link->setup_pending) &&
           !link->setup_waiting && !link->connection && link->clock.phase==CLOCK_EMPTY){
            *at=link->next;wendy_net_free(link->control);wendy_net_free(link);
        }else at=&link->next;
    }
    pthread_mutex_unlock(&state_lock);
}
static bool setup_room(struct peer_state *root)
{
#if CONFIG_WENDY_NET_SETUP_FREE_BYTES > 0
    size_t available=heap_caps_get_free_size(MALLOC_CAP_8BIT);
#if CONFIG_WENDY_NET_RETAIN_TLS_INPUT
    available+=wendy_pki_input_workspace_cached_bytes();
#endif
    return !atomic_load(&root->carrier_count) || available>=CONFIG_WENDY_NET_SETUP_FREE_BYTES;
#else
    (void)root;return true;
#endif
}
static bool setup_in_flight(struct peer_state *root)
{
    for(struct peer_state *link=root;link;link=link->next)
        if(link->setup_waiting || atomic_load(&link->setup_pending))return true;
    return false;
}
static bool setup_capacity_available(struct peer_state *root)
{
    unsigned pending=0;
    for(struct peer_state *link=root;link;link=link->next)
        if(link->setup_waiting || atomic_load(&link->setup_pending))pending++;
    return pending<wendy_pki_handshake_mesh_limit();
}
#if CONFIG_WENDY_NET_BLE
static bool ble_admission_available(struct peer_state *root)
{
    return !WENDY_NET_NON_TRANSIT && root->clock_ready &&
        setup_capacity_available(root) && medium_available(root,WN_BLE) && setup_room(root) &&
        wble_mesh_incoming_available();
}
#endif
static void router_run(struct peer_state *root)
{
    unsigned busy_loops=0;
    for(;;){
        if(atomic_load(&stopping))return;

        int64_t now=esp_timer_get_time();bool progress=false;
#if CONFIG_WENDY_NET_RECLAIM_PAYLOADS_FOR_TLS
        service_reclaim(root);
#endif
        bool lan_paused=false;
        char tenant[37],device[65];wendy_conf_get_enrolled_ids(tenant,device);
        /* Establish this boot's time before creating a native TLS setup. A
         * cold setup cannot authenticate yet and must not starve its bootstrap. */
        bootstrap_time_tick(root,!setup_in_flight(root));
#if CONFIG_WENDY_NET_BLE
        if(root->config.ble){
            wble_mesh_scan_interest(ble_discovery_available(root));
            update_ble(root,tenant,device);
        }
#endif
        if(lan_paused)close_listener(root);
        bool lan=!lan_paused && update_listener(root,tenant,device)==0;
        discover_async(root,lan,tenant,device);
        for(struct peer_state *link=root;link;link=link->next){
            bool active=atomic_load(&link->active);
            if(!wncrypto_borrowed(link->connection))finish_clock(link,active ? &link->refresh_at:NULL);
            /* The higher-priority clock worker can finish after the actor
             * sampled this loop's time. Compare the newly installed anchor
             * with a fresh monotonic sample, never that earlier snapshot. */
            now=esp_timer_get_time();
            if(link->setup_waiting){

                if(lan_paused && link->candidate.medium==WN_LAN)link->tls_state.cancel=true;
                int pending=advance_setup(link,now);
                if(pending<0){retire_link(link);progress=true;}
                else if(!pending){
                    link->setup_result=0;
                    int admitted=admit_link(root,link);
                    if(admitted<=0){link->setup_waiting=false;if(admitted<0)retire_link(link);progress=true;}
                }
                continue;
            }
            if(!active || wncrypto_borrowed(link->connection))continue;
            if(link->tls_channel){
                int io=wnad_channel_io(link->tls_channel,link->setup_fd,
                    link->setup_have_stream ? &link->setup_stream:NULL);
                if(io<0){
                    ESP_LOGW(TAG,"carrier socket ended: peer=%s eof=%u failed=%u errno=%d",
                        link->candidate.device,(unsigned)link->tls_channel->eof,
                        (unsigned)link->tls_channel->failed,errno);
                    retire_link(link);continue;
                }

                progress|=io>0;
            }
            bool lost=link->candidate.medium==WN_LAN && (lan_paused || !wendy_wifi_is_connected());
            bool live=identity_live(link,now);
            if(link->failed || !live || lost){
                ESP_LOGW(TAG,"carrier retired: peer=%s failed=%u identity_live=%u medium_lost=%u",
                    link->candidate.device,(unsigned)link->failed,(unsigned)live,(unsigned)lost);
                retire_link(link);continue;
            }

            if(wnrs_tick(link->router)){retire_link(link);continue;}
            /* Tick/publication callbacks may have just lent this connection.
             * The per-I/O guards also cover loans made by receive callbacks. */
            if(wncrypto_borrowed(link->connection))continue;
            time_tick(link,now);
            if(now>=link->refresh_at)queue_clock(link,link->candidate.address);

            int pumped=wnc_pump(&link->carrier,esp_timer_get_time(),receive_frame,link);
            if(pumped<0){
                struct wnc_timeout timeout;
                if(pumped==WNC_TIMEOUT && wnc_timeout_snapshot(&link->carrier,esp_timer_get_time(),&timeout))
                    ESP_LOGW(TAG,"carrier frame timeout: medium=%u writing=%u offset=%u size=%u idle_ms=%u age_ms=%u queued=%u heap=%u",
                        (unsigned)link->candidate.medium,(unsigned)timeout.writing,(unsigned)timeout.offset,
                        (unsigned)timeout.size,(unsigned)(timeout.idle_us/1000),(unsigned)(timeout.age_us/1000),
                        (unsigned)link->carrier.queued,(unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
                ESP_LOGW(TAG,"carrier ended: peer=%s result=%d",link->candidate.device,pumped);retire_link(link);
            }
            else if(pumped){progress=true;}
        }

        update_node_status(root);
        service_catalog_query(root);
        if(atomic_load(&root->node_active)){
            service_app_query(root);
            pthread_mutex_lock(&state_lock);
            size_t size=0;void *packet=wnpq_front(root->queue,&size);
            if(packet){
                struct wnrs *router=any_router(root);uint64_t outgoing=0;
                struct peer_state *link=NULL;int result=0;
                if(router && wnrs_packet_route(router,packet,size,false,&outgoing)==1)
                    link=route_link(root,outgoing);
                if(link){
                    result=wnc_enqueue_packet(&link->carrier,packet,size,++root->packet_id);
                }
                /* A fragmented UDP burst can fill the smaller carrier queue
                 * while TLS is waiting to write. Keep the head in the sparse
                 * IP FIFO until admitted instead of silently losing a fragment. */
                if(result!=WNC_NOMEM && result!=WNC_LIMIT){
                    if(result && link)link->failed=true;
                    wnpq_drop(root->queue);progress=true;
                }
            }
            pthread_mutex_unlock(&state_lock);
        }
        struct wn_candidate hint={.medium=WN_LAN,.port=43024,.cost=WNR_LAN_COST};
        bool accepted=false;
#if CONFIG_WENDY_NET_BLE
        struct wble_mesh_peer remote;struct wble_mesh_pipe *pipe=accepted || !root->config.ble ? NULL:wble_mesh_take(&remote);
        if(pipe && remote.psm==WBLE_MESH_TIME_PSM){
            accepted=true;ble_time_take(root,pipe,remote.server);pipe=NULL;
        }else if(pipe && !root->clock_ready){
            accepted=true;wble_mesh_release(pipe);pipe=NULL;
        }
        if(pipe){
            accepted=true;struct peer_state *link=setup_capacity_available(root) && setup_room(root) && medium_available(root,WN_BLE) ? reserve_slot(root):NULL;
            if(!link)wble_mesh_release(pipe);
            else{
                hint=(struct wn_candidate){.medium=WN_BLE,.port=remote.psm,.cost=WNR_BLE_COST};
                ble_address(hint.address,remote.address,remote.address_type);
                link->ble_pipe=pipe;link->setup_stream=wble_mesh_stream(pipe);
                link->setup_have_stream=true;link->setup_server=remote.server;
                begin_setup(link,&hint,-1);
            }
        }
#endif
        if(!accepted && lan && root->listener>=0 && root->clock_ready &&
           setup_capacity_available(root) && setup_room(root) && medium_available(root,WN_LAN)){
            struct sockaddr_in remote;socklen_t size=sizeof remote;
            int fd=accept(root->listener,(struct sockaddr*)&remote,&size);
            if(fd>=0){
                accepted=true;struct peer_state *link=setup_room(root) && medium_available(root,WN_LAN) ? reserve_slot(root):NULL;
                if(!link)close(fd);
                else{
                    inet_ntop(AF_INET,&remote.sin_addr,hint.address,sizeof hint.address);
                    link->setup_have_stream=false;link->setup_server=true;begin_setup(link,&hint,fd);
                }
            }
        }
        if(!accepted && root->clock_ready &&
           setup_capacity_available(root) && capacity_available(root) && setup_room(root)){
            int index=additional_candidate(root,esp_timer_get_time()/1000,lan);
            if(index>=0){
                hint=root->selection->candidates[index];
#if CONFIG_WENDY_NET_BLE
                if(hint.medium==WN_BLE){
                    if(root->clock_ready && !root->bootstrap_time && !ble_dial(&hint))ESP_LOGI(TAG,"dialing BLE candidate %s",hint.address);
                    root->selection->candidates[index].retry_ms=esp_timer_get_time()/1000+5000;
                }else
#endif
                {
                    struct peer_state *link=reserve_slot(root);
                    if(link){link->setup_have_stream=false;link->setup_server=false;begin_setup(link,&hint,-1);}
                }
            }
        }
        progress|=wendy_net_agent_poll()!=0;
        progress|=wendy_net_app_poll()!=0;
        progress|=wnrs_poll_effects(root->router_node)!=0;
        collect_slots(root);
        bool output_drained=true;
        pthread_mutex_lock(&state_lock);
        if(root->queue && root->queue->count)output_drained=false;
        pthread_mutex_unlock(&state_lock);
        for(struct peer_state *link=root;link;link=link->next){
            /* A worker may be writing the lent TLS BIO. The receipt barrier
             * conservatively waits instead of inspecting its borrowed state. */
            if(link->tls_state.lent || wncrypto_borrowed(link->connection)){
                output_drained=false;continue;
            }
            if(link->carrier.queued || (link->tls_channel && link->tls_channel->output.size))output_drained=false;
#if CONFIG_WENDY_NET_BLE
            /* A positive stream write may only have reached the BLE mailbox.
             * Preserve the reply until the host accepts that retained SDU. */
            if(link->ble_pipe && !wble_mesh_output_drained(link->ble_pipe))output_drained=false;
#endif
        }
        wn_settings_poll(output_drained);
#if CONFIG_WENDY_NET_BLE
        /* Apply the same actor admission decision before NimBLE allocates an
         * incoming native pipe. Full nodes otherwise churn through CoC setup
         * only for this loop to release it again. This is resource backpressure,
         * not a timer/window. Full profiles keep advertisements/time PSM live;
         * constrained profiles remain scan/dial only. */
        if(root->config.ble)wble_mesh_router_admission(ble_admission_available(root));
#endif

        ++busy_loops;
        if(!progress || busy_loops>=8){
            bool quota=busy_loops>=8;
            /* A ready descriptor/deadline can yield no protocol progress
             * (e.g. send ENOBUFS). Count those polls too: otherwise a zero
             * timeout loop can starve the lower-priority crypto worker. */
            if(quota){busy_loops=0;}

            fd_set rd,wr;FD_ZERO(&rd);FD_ZERO(&wr);
            int maximum=wnad_wake_fd();FD_SET(maximum,&rd);
            if(root->listener>=0 && root->clock_ready && setup_capacity_available(root) &&
               setup_room(root) && medium_available(root,WN_LAN)){
                FD_SET(root->listener,&rd);if(root->listener>maximum)maximum=root->listener;
            }
            int64_t deadline=esp_timer_get_time()+INT64_C(1000000);
            int64_t mdns_deadline=wnm_deadline(root->mdns);

            if(mdns_deadline<deadline)deadline=mdns_deadline;
#if CONFIG_WENDY_NET_BLE
            if(root->config.ble){int64_t retry=wble_mesh_retry_deadline();if(retry<deadline)deadline=retry;}
#endif
            int64_t netif_deadline=wnne_deadline(&root->netif_effect);

            if(netif_deadline<deadline)deadline=netif_deadline;
            for(struct peer_state *link=root;link;link=link->next){
                if(link->tls_state.lent || wncrypto_borrowed(link->connection))continue;
                int fd=link->setup_fd;
                if(fd>=0 && link->tls_channel){
                    if(wna_buffer_space(&link->tls_channel->input))FD_SET(fd,&rd);
                    if(link->setup_connecting || link->tls_channel->output.size)FD_SET(fd,&wr);
                    if(fd>maximum)maximum=fd;
                }
                if(link->setup_waiting && (int64_t)link->tls_state.deadline<deadline)deadline=(int64_t)link->tls_state.deadline;
                if(link->tls_state.retry_at>(uint64_t)esp_timer_get_time() &&
                   link->tls_state.retry_at<(uint64_t)deadline)deadline=(int64_t)link->tls_state.retry_at;
                bool can_read=link->setup_waiting || (link->router &&
                    !link->carrier.rx_paused && !wnrs_receive_paused(link->router));
                if(can_read && link->tls_state.phase==WNA_READY &&
                   ((link->tls_channel && link->tls_channel->input.size) ||
                    (link->connection && wendy_pki_pending(link->connection)))){



                    deadline=esp_timer_get_time();
                }
                if(link->router){int64_t next=wnrs_next_deadline(link->router);if(next<deadline)deadline=next;}
            }
            wendy_net_app_watch(&rd,&wr,&maximum,&deadline);
            wendy_net_agent_watch(&rd,&wr,&maximum,&deadline);
            int64_t left=deadline-esp_timer_get_time();if(left<0)left=0;
            /* Bounded batches must also let the lower-priority worker and
             * SDK idle tasks run under continuously ready traffic. */

            /* At a tick boundary a one-tick delay may unblock almost
             * immediately. Keep one whole tick available to lower priorities,
             * as the crypto worker already does between bounded batches. */
            if(quota)vTaskDelay(2);
            struct timeval timeout={.tv_sec=left/1000000,.tv_usec=left%1000000};
            (void)esp_vfs_select(maximum+1,&rd,&wr,NULL,&timeout);
            wnad_drain_wake();
        }
    }
}
/* Cooperatively relinquish every context loan before freeing its owner.
 * No worker cancellation or forced task deletion while library code runs. */
static void shutdown_crypto_cleanup(void *context)
{
    struct peer_state *root=context;
    wendy_pki_crypto_cleanup();
    atomic_store(&root->crypto_cleanup_done,true);
}
static bool shutdown_step(struct peer_state *root)
{
    bool waiting=!wendy_net_app_stop();
    waiting|=!wendy_net_agent_stop();
    wnne_desire(&root->netif_effect,WNNE_REMOVED);poll_netif_effect(root);
    waiting|=!wnne_idle(&root->netif_effect);
    close_listener(root);
    struct wnm_intent mdns_off={0};
    mdns_collect(root,false,"","");wnm_drive(root->mdns,&mdns_off,esp_timer_get_time());
    waiting|=!wnm_idle(root->mdns);
    if(root->bootstrap_time){
        struct time_bootstrap_job *job=root->bootstrap_time;
        if(job->submitted && !atomic_load(&job->done))waiting=true;
        else {release_time_job(job);root->bootstrap_time=NULL;}
    }
#if CONFIG_WENDY_NET_BLE
    if(root->config.ble)(void)wendy_ble_mesh_advertisement(NULL,0);
#endif
    for(struct peer_state *link=root;link;link=link->next){
        if(link->tls_state.lent){
            if(!atomic_load(&link->setup_complete)){waiting=true;continue;}
            wna_completed(&link->tls_state,link->setup_result);
        }
        if(wncrypto_borrowed(link->connection)){waiting=true;continue;}
        if(link->candidate_held || link->connection || link->tls_setup || link->tls_channel || link->setup_waiting ||
           atomic_load(&link->active))retire_link(link);
        pthread_mutex_lock(&state_lock);
        if(link->clock.phase==CLOCK_QUEUED || link->clock.phase==CLOCK_DONE)link->clock.phase=CLOCK_EMPTY;
        waiting|=link->clock.phase!=CLOCK_EMPTY;
        pthread_mutex_unlock(&state_lock);
    }
    pthread_mutex_lock(&state_lock);
    atomic_store(&root->node_active,false);
    if(root->service_query){
        struct service_query *q=root->service_query;root->service_query=NULL;
        q->result=-1;q->complete=true;service_query_release(q);
    }
    root->app_query.found=false;root->app_query.complete=true;
    waiting|=root->app_query.owned;
#if CONFIG_WENDY_NET_RECLAIM_PAYLOADS_FOR_TLS
    root->reclaim.released=0;root->reclaim.complete=true;waiting|=root->reclaim.owned;
#endif
    pthread_mutex_unlock(&state_lock);
#if CONFIG_WENDY_NET_BLE
    if(root->config.ble){
        waiting|=!wble_mesh_stop();
        waiting|=!wendy_ble_mesh_advertisement_idle();
    }
#endif
    /* Join all protocol/context loans before trimming empty shared PSA tables.
     * This mutex-taking SDK operation stays on the existing crypto worker. */
    if(!waiting && !root->crypto_cleanup_submitted)
        root->crypto_cleanup_submitted=wendy_pki_work_submit(shutdown_crypto_cleanup,root);
    waiting|=!root->crypto_cleanup_submitted || !atomic_load(&root->crypto_cleanup_done);
    return !waiting;
}
static void finish_shutdown(struct peer_state *root)
{
    atomic_store(&runtime_state,WendyComNetState_WENDY_COM_NET_STOPPING);
    while(!shutdown_step(root))vTaskDelay(1);
    while(!wendy_pki_io_work_idle())vTaskDelay(1);
    while(!wendy_pki_work_stop())vTaskDelay(1);
#if CONFIG_WENDY_NET_RETAIN_TLS_INPUT
    update_input_workspace(root,false);
#endif
#if CONFIG_WENDY_NET_BLE
    wble_mesh_set_wakeup(NULL);
#endif
    (void)wnm_close(root->mdns);root->mdns=NULL;
    wnad_stop();
    pthread_mutex_lock(&state_lock);state=NULL;pthread_mutex_unlock(&state_lock);
    wnrs_service_clear(&root->service_registry);
    while(root->next){struct peer_state *link=root->next;root->next=link->next;wendy_net_free(link->control);wendy_net_free(link);}
#if CONFIG_WENDY_NET_BLE
    delete_ble_reports(root);
#endif
    delete_packet_queue(root);wendy_net_free(root->control);wendy_net_free(root->selection);wendy_net_free(root);
    wendy_net_runtime_memory_close();
    atomic_store(&starting,false);
    ESP_LOGI(TAG,"mesh shutdown complete; actor/crypto resources released");
    ESP_LOGI(TAG,"mesh stopped: heap=%u internal=%u largest=%u internal_largest=%u tasks=%u",
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT),
        (unsigned)uxTaskGetNumberOfTasks());
}
static void run(void *argument)
{
    wendy_net_memory_scope_t previous=wendy_net_runtime_scope_enter();
    struct peer_state *s=argument;
    if(wnad_start()) {
        ESP_LOGE(TAG,"actor driver initialization failed");atomic_store(&runtime_error,ESP_ERR_NO_MEM);
        /* No mesh crypto operation has run before driver startup succeeds.
         * Cleanup must not wait forever for the worker that failed to start,
         * or trim unrelated baseline PSA state on a failed activation. */
        s->crypto_cleanup_submitted=true;atomic_store(&s->crypto_cleanup_done,true);
        finish_shutdown(s);wendy_net_memory_scope_leave(previous);vTaskDelete(NULL);return;
    }
#if CONFIG_WENDY_NET_BLE
    wble_mesh_set_wakeup(wnad_wake);
#endif
    wendy_net_agent_start();
    (void)wendy_net_app_start();
    atomic_store(&runtime_error,0);atomic_store(&runtime_state,WendyComNetState_WENDY_COM_NET_RUNNING);
    router_run(s);
    finish_shutdown(s);wendy_net_memory_scope_leave(previous);vTaskDelete(NULL);return;
}
static esp_err_t start_enrolled(void)
{
    if (state)
        return ESP_OK;
    struct peer_state *s = wendy_net_calloc(1, sizeof *s);
    if (!s)
        return ESP_ERR_NO_MEM;
    pthread_mutex_lock(&state_lock);s->config=applied_config;pthread_mutex_unlock(&state_lock);
    s->selection=wendy_net_calloc(1,sizeof *s->selection);
    if(!s->selection){wendy_net_free(s);return ESP_ERR_NO_MEM;}
    s->listener=-1;s->candidate_index=-1;
    s->setup_fd=-1;
    create_packet_queue(s);
    if(!allocate_control(s)){delete_packet_queue(s);wendy_net_free(s->control);wendy_net_free(s->selection);wendy_net_free(s);return ESP_ERR_NO_MEM;}
#if CONFIG_WENDY_NET_BLE
    if(s->config.ble){
        if(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),&s->ble_reports_charge,
            4*sizeof(struct ble_seen)+sizeof(StaticQueue_t)+64,WENDY_NET_MEMORY_INTERNAL))
            s->ble_reports=xQueueCreate(4,sizeof(struct ble_seen));
        if(!s->ble_reports)wendy_net_memory_release(&s->ble_reports_charge);
        if(!s->ble_reports){delete_packet_queue(s);wendy_net_free(s->control);wendy_net_free(s->selection);wendy_net_free(s);return ESP_ERR_NO_MEM;}
    }
#endif
    if (!s->queue)
    {
        delete_packet_queue(s);
#if CONFIG_WENDY_NET_BLE
        delete_ble_reports(s);
#endif
        wendy_net_free(s->control);wendy_net_free(s->selection);wendy_net_free(s);
        return ESP_ERR_NO_MEM;
    }
    wn_selection_init(s->selection);
    /* Publish only an initialized rejecting netif to the route hook. */
    struct netif_change change = {.s = s};
    if (tcpip_api_call(change_netif, &change.call) != ERR_OK)
    {
        delete_packet_queue(s);
#if CONFIG_WENDY_NET_BLE
        delete_ble_reports(s);
#endif
        wendy_net_free(s->control);wendy_net_free(s->selection);wendy_net_free(s);
        return ESP_FAIL;
    }
    wnne_init(&s->netif_effect,WNNE_DOWN);
    atomic_init(&s->crypto_cleanup_done,false);
    s->mdns=s->config.infrastructure_wifi ? wnm_open(discovery_ready):NULL;
    if(s->config.infrastructure_wifi && !s->mdns){
        change.remove=true;(void)tcpip_api_call(change_netif,&change.call);
#if CONFIG_WENDY_NET_BLE
        delete_ble_reports(s);
#endif
        delete_packet_queue(s);wendy_net_free(s->control);wendy_net_free(s->selection);wendy_net_free(s);
        return ESP_ERR_NO_MEM;
    }
    state = s;
    if (wendy_net_task_create(run, "wendy-net", CONFIG_WENDY_NET_TASK_STACK_SIZE, s, CONFIG_WENDY_NET_TASK_PRIORITY, NULL) != pdPASS)
    {
        state = NULL;
        (void)wnm_close(s->mdns);
        change.remove = true;
        (void)tcpip_api_call(change_netif, &change.call);
        delete_packet_queue(s);
#if CONFIG_WENDY_NET_BLE
        delete_ble_reports(s);
#endif
        wendy_net_free(s->control);wendy_net_free(s->selection);wendy_net_free(s);
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "native endpoint started: state=%u packet_queue_idle=%u packet_queue_limit=%u stack=%u bytes",
             (unsigned)sizeof *s,(unsigned)sizeof *s->queue,(unsigned)PEER_QUEUE,
             (unsigned)CONFIG_WENDY_NET_TASK_STACK_SIZE);
    return ESP_OK;
}
static void await_identity(void *unused)
{
    (void)unused;
    wendy_net_memory_scope_t previous=wendy_net_runtime_scope_enter();
    atomic_store(&identity_task,xTaskGetCurrentTaskHandle());
    for (;;)
    {
        if(atomic_load(&stopping))break;
        char nonce[65];
        bool enrolled = false;
        /* This status-only query is a cheap storage hint, not admission.
         * The actual connection still verifies identity, roots and time. */
        if (!wendy_pki_reset_in_progress() && wendy_conf_is_current() &&
            wendy_pki_challenge(true, nonce, &enrolled) == ESP_OK && enrolled)
        {
            esp_err_t result = start_enrolled();
            if (result == ESP_OK)
            {
                atomic_store(&identity_task,NULL);
                wendy_net_memory_scope_leave(previous);
                vTaskDelete(NULL);
                return;
            }
            ESP_LOGW(TAG, "native peer waiting for memory: %s free=%u largest=%u",
                     esp_err_to_name(result), (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
                     (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
        }
        ulTaskNotifyTake(pdTRUE,pdMS_TO_TICKS(5000));
    }
    atomic_store(&identity_task,NULL);atomic_store(&starting,false);
    wendy_net_runtime_memory_close();
    wendy_net_memory_scope_leave(previous);
    vTaskDelete(NULL);
}
void wn_peer_configuration_changed(void)
{
    atomic_store(&stopping,true);
    if(atomic_load(&starting))atomic_store(&runtime_state,WendyComNetState_WENDY_COM_NET_STOPPING);
    TaskHandle_t task=atomic_load(&identity_task);if(task)xTaskNotifyGive(task);
    wnad_wake();
}
void wn_peer_runtime_status(WendyComNetStatus *status)
{
    wendy_net_memory_snapshot_t memory;
    wendy_net_runtime_memory_snapshot(&memory);
    status->memory_limit_bytes=(uint32_t)wendy_net_runtime_memory_limit();
    status->has_allocated_bytes=true;status->allocated_bytes=(uint32_t)memory.current_bytes;
    status->has_internal_bytes=true;status->internal_bytes=(uint32_t)memory.internal_bytes;
    status->state=(WendyComNetState)atomic_load(&runtime_state);
    status->error_code=atomic_load(&runtime_error);
    pthread_mutex_lock(&state_lock);
    status->has_applied=true;status->applied=applied_config;
    struct peer_state *root=state;if(root)status->active_links=atomic_load(&root->carrier_count);
    pthread_mutex_unlock(&state_lock);
}
static void lifecycle_poll(void)
{
    /* When no actor exists, the baseline server drives the same deferred
     * management receipt. An existing actor owns its carrier queue sample. */
    if(!state)wn_settings_poll(true);
    if(wn_settings_pending())return;
    if(wn_settings_restarting()){
        if(wn_settings_restart_due() && !atomic_load(&starting) && !state &&
           !atomic_load(&identity_task) && wendy_net_runtime_memory_drained()){
            ESP_LOGI(TAG,"saved carrier change applied; restarting endpoint");
            esp_restart();
        }
        return;
    }
    if(!atomic_load(&settings_ready) || atomic_load(&starting) || state || atomic_load(&identity_task))return;
    WendyComNetConfig config=wn_settings_get();
    atomic_store(&stopping,false);
    if(!config.enabled){
        wendy_net_runtime_memory_close();
        if(!wendy_net_runtime_memory_drained()){
            atomic_store(&runtime_state,WendyComNetState_WENDY_COM_NET_STOPPING);return;
        }
        pthread_mutex_lock(&state_lock);applied_config=config;pthread_mutex_unlock(&state_lock);
        atomic_store(&runtime_state,WendyComNetState_WENDY_COM_NET_OFF);return;
    }
    /* Reopening waits for actual FreeRTOS task reaping and any old public
     * request owner, so a retiring generation cannot spend the next budget. */
    if(!wendy_net_runtime_memory_drained())return;
    if(atomic_exchange(&starting,true))return;
    if(!wendy_net_runtime_memory_open()){
        atomic_store(&starting,false);atomic_store(&runtime_error,ESP_ERR_NO_MEM);
        atomic_store(&runtime_state,WendyComNetState_WENDY_COM_NET_FAILED);return;
    }
    pthread_mutex_lock(&state_lock);applied_config=config;pthread_mutex_unlock(&state_lock);
    atomic_store(&runtime_state,WendyComNetState_WENDY_COM_NET_STARTING);
    if(wendy_net_task_create(await_identity,"net-identity",4096,NULL,4,NULL)!=pdPASS){
        wendy_net_runtime_memory_close();
        atomic_store(&runtime_error,ESP_ERR_NO_MEM);
        atomic_store(&starting,false);atomic_store(&runtime_state,WendyComNetState_WENDY_COM_NET_FAILED);return;
    }
}
esp_err_t wendy_net_peer_start(void)
{
    esp_err_t result=wn_settings_init();if(result!=ESP_OK)return result;
    atomic_store(&settings_ready,true);lifecycle_poll();
    return ESP_OK;
}
