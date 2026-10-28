/* NAN-only radio adapter. SDK events transfer bounded discovery/NDP metadata;
 * the native peer actor retains TLS, identity and route ownership. */
#include "wendy_net_nan.h"
#include "wendy_net_nan_protocol.h"
#include "wendy_conf.h"
#include "wendy_pki_crypto.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_nan.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_wifi_default.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/ip6_addr.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PEERS 2
#ifndef CONFIG_WENDY_NET_TEST_NAN_PASSIVE_SUBSCRIBER
#define CONFIG_WENDY_NET_TEST_NAN_PASSIVE_SUBSCRIBER 0
#endif
enum event_kind { MATCH, REQUEST, CONFIRM, ENDED };
struct event {
    enum event_kind kind;
    uint8_t id,publish,status,nmi[6],ndi[6],own[6],size;
    uint16_t raw_size;
    uint8_t ssi[WN_NAN_PRESENCE_SIZE+4];
};
struct offer {struct wn_candidate candidate;int fd;};
struct peer {
    bool used,connected,server,offered;
    uint8_t device[16],nmi[6],ndi[6],id,publish;
    int listener;
    int64_t seen,retry;
    struct wn_candidate candidate;
};
static struct peer peers[PEERS];
static uint8_t tenant[16],self[16],mesh[8],presence[WN_NAN_PRESENCE_SIZE];
static QueueHandle_t events,offers;
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static atomic_bool started;
static atomic_bool stopping;
static esp_netif_t *interface;
static const char *TAG="net-nan";

static void receive(void *unused,esp_event_base_t base,int32_t id,void *data)
{
    (void)unused;(void)base;
    struct event e={0};const uint8_t *ssi=NULL;size_t size=0;
    if(id==WIFI_EVENT_NAN_SVC_MATCH){
        wifi_event_nan_svc_match_t *m=data;e.kind=MATCH;e.publish=m->publish_id;
        memcpy(e.nmi,m->pub_if_mac,6);ssi=m->ssi;size=m->ssi_len;
    }else if(id==WIFI_EVENT_NDP_INDICATION){
        wifi_event_ndp_indication_t *m=data;e.kind=REQUEST;e.id=m->ndp_id;
        memcpy(e.nmi,m->peer_nmi,6);memcpy(e.ndi,m->peer_ndi,6);ssi=m->ssi;size=m->ssi_len;
    }else if(id==WIFI_EVENT_NDP_CONFIRM){
        wifi_event_ndp_confirm_t *m=data;e.kind=CONFIRM;e.id=m->ndp_id;e.status=m->status;
        memcpy(e.nmi,m->peer_nmi,6);memcpy(e.ndi,m->peer_ndi,6);memcpy(e.own,m->own_ndi,6);
        ssi=m->ssi;size=m->ssi_len;
    }else if(id==WIFI_EVENT_NDP_TERMINATED){
        wifi_event_ndp_terminated_t *m=data;e.kind=ENDED;e.id=m->ndp_id;
    }else return;
    e.raw_size=(uint16_t)size;
    if(ssi && size<=sizeof e.ssi){memcpy(e.ssi,ssi,size);e.size=(uint8_t)size;}
    (void)xQueueSend(events,&e,0);
}

static struct peer *find_peer(const uint8_t nmi[6])
{
    for(unsigned i=0;i<PEERS;i++)if(peers[i].used && !memcmp(peers[i].nmi,nmi,6))return &peers[i];
    return NULL;
}
static struct peer *remember(const struct event *e)
{
    struct wn_nan_hint hint;
    if(!wn_nan_presence_read(tenant,mesh,e->ssi,e->size,&hint) || !memcmp(hint.device,self,16))return NULL;
    struct peer *p=find_peer(e->nmi);
    if(!p)for(unsigned i=0;i<PEERS;i++)if(!peers[i].used){
        p=&peers[i];memset(p,0,sizeof *p);p->listener=-1;p->used=true;
        p->retry=esp_timer_get_time()+INT64_C(5000000);
        memcpy(p->nmi,e->nmi,6);memcpy(p->device,hint.device,16);
        char device[37];wn_uuid_format(p->device,device);
        ESP_LOGI(TAG,"Discovered NAN candidate: %s",device);break;
    }
    if(!p || memcmp(p->device,hint.device,16))return NULL;
    p->seen=esp_timer_get_time();if(e->publish)p->publish=e->publish;
    return p;
}
static uint16_t port_for(const uint8_t uuid[16])
{return (uint16_t)(20000+(((unsigned)uuid[14]<<8)|uuid[15])%40000);}
static void forget_path(struct peer *p)
{
    if(p->listener>=0)close(p->listener);
    p->listener=-1;p->connected=p->offered=false;p->id=0;
    p->retry=esp_timer_get_time()+INT64_C(10000000);
}
static int server_listener(uint16_t port)
{
    int fd=socket(AF_INET6,SOCK_STREAM,0),yes=1;
    struct sockaddr_in6 address={.sin6_family=AF_INET6,.sin6_port=htons(port)};
    if(fd<0)return -1;
    if(fd>=FD_SETSIZE || fcntl(fd,F_SETFL,O_NONBLOCK)<0 ||
       setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) ||
       setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&yes,sizeof yes) ||
       bind(fd,(struct sockaddr*)&address,sizeof address) || listen(fd,1)){
        close(fd);return -1;
    }
    return fd;
}

static void handle_event(const struct event *e)
{
    wifi_nan_datapath_resp_t response={0};bool respond=false;
    pthread_mutex_lock(&lock);
    if(e->kind==ENDED){
        for(unsigned i=0;i<PEERS;i++)if(peers[i].used && peers[i].id==e->id)forget_path(&peers[i]);
        pthread_mutex_unlock(&lock);return;
    }
    static bool logged_discovery;
    if(e->kind==MATCH && !logged_discovery){
        ESP_LOGI(TAG,"First discovery: rawSSI=%u copied=%u",e->raw_size,e->size);
        logged_discovery=true;
    }
    struct peer *p=remember(e);
    if(!p)p=find_peer(e->nmi);
    if(e->kind==REQUEST){
        ESP_LOGI(TAG,"Incoming NDP: id=%u rawSSI=%u SSI=%u known=%u",e->id,e->raw_size,e->size,(unsigned)(p!=NULL));
        respond=true;response.accept=p && (!p->id || p->id==e->id);response.ndp_id=e->id;
        memcpy(response.peer_mac,e->nmi,6);
        if(response.accept){p->server=true;p->id=e->id;memcpy(p->ndi,e->ndi,6);}
    }else if(e->kind==CONFIRM && p){
        if(e->status!=NDP_STATUS_ACCEPTED)forget_path(p);
        else{
            if(p->connected && p->id==e->id && !memcmp(p->ndi,e->ndi,6)){
                pthread_mutex_unlock(&lock);return;
            }
            if(p->listener>=0)close(p->listener);
            p->listener=-1;
            p->id=e->id;p->connected=true;p->offered=false;
            memcpy(p->ndi,e->ndi,6);
            ip6_addr_t ip;char text[48];
            esp_wifi_nan_get_ipv6_linklocal_from_mac(&ip,p->ndi);
            ip6addr_ntoa_r(&ip,text,sizeof text);
            p->candidate=(struct wn_candidate){.medium=WN_NAN,.cost=512,
                .port=port_for(p->server ? p->device:self)};
            wn_uuid_format(p->device,p->candidate.device);
            // lwIP parses a textual scope as its netif name (e.g. na0),
            // not a numeric POSIX interface index.
            char name[6]={0};
            if(esp_netif_get_netif_impl_name(interface,name)!=ESP_OK){
                forget_path(p);pthread_mutex_unlock(&lock);return;
            }
            snprintf(p->candidate.address,sizeof p->candidate.address,"%s%%%s",text,name);
            p->retry=0;
            if(p->server)p->listener=server_listener(p->candidate.port);
            ESP_LOGI(TAG,"NDP ready: id=%u peer=%s address=%s TCP=%u server=%u",
                p->id,p->candidate.device,p->candidate.address,p->candidate.port,(unsigned)p->server);
        }
    }
    pthread_mutex_unlock(&lock);
    if(respond){
        esp_err_t result=esp_wifi_nan_datapath_resp(&response);
        ESP_LOGI(TAG,"NDP response: id=%u accepted=%u result=%s",e->id,
            (unsigned)response.accept,esp_err_to_name(result));
    }
}
static void tick(void)
{
    int64_t now=esp_timer_get_time();
    for(unsigned i=0;i<PEERS;i++){
        wifi_nan_datapath_req_t request={0};bool dial=false;
        pthread_mutex_lock(&lock);struct peer *p=&peers[i];
        if(p->used && !p->connected && !p->id && now-p->seen>=INT64_C(60000000))p->used=false;
        if(p->used && !p->connected && !p->id && p->publish && now>=p->retry &&
           now-p->seen<INT64_C(60000000) &&
           memcmp(self,p->device,16)<0){
            request.pub_id=p->publish;request.confirm_required=true;
            memcpy(request.peer_mac,p->nmi,6);p->server=false;
            p->retry=now+INT64_C(15000000);dial=true;
        }
        if(p->used && p->connected){
            struct offer offer={.candidate=p->candidate,.fd=-1};
            bool have=false;
            if(p->server && p->listener>=0){
                offer.fd=accept(p->listener,NULL,NULL);have=offer.fd>=0;
            }else if(!p->server && now>=p->retry)have=true;
            if(have){
                if(xQueueSend(offers,&offer,0)!=pdTRUE && offer.fd>=0)close(offer.fd);
                p->retry=now+INT64_C(5000000);
            }
        }
        pthread_mutex_unlock(&lock);
        if(dial){
            uint8_t id=esp_wifi_nan_datapath_req(&request);
            pthread_mutex_lock(&lock);if(id)p->id=id;pthread_mutex_unlock(&lock);
            ESP_LOGI(TAG,"NDP request finished: id=%u",id);
        }
    }
}

bool wn_nan_take(struct wn_candidate *candidate,int *fd)
{
    struct offer offer;
    if(!offers || !candidate || !fd || xQueueReceive(offers,&offer,0)!=pdTRUE)return false;
    if(!wn_nan_peer_live(offer.candidate.device)){
        if(offer.fd>=0)close(offer.fd);
        return false;
    }
    *candidate=offer.candidate;*fd=offer.fd;return true;
}
bool wn_nan_peer_live(const char *device)
{
    bool live=false;pthread_mutex_lock(&lock);
    for(unsigned i=0;i<PEERS;i++)if(peers[i].used && peers[i].connected &&
        !strcmp(peers[i].candidate.device,device)){live=true;break;}
    pthread_mutex_unlock(&lock);return live;
}

static void run(void *unused)
{
    (void)unused;
    uint8_t pub=0,sub=0;bool registered=false,radio=false;
    esp_err_t result=esp_event_handler_register(WIFI_EVENT,ESP_EVENT_ANY_ID,receive,NULL);
    if(result!=ESP_OK)goto failed;
    registered=true;
    interface=esp_netif_create_default_wifi_nan();
    wifi_nan_sync_config_t config=WIFI_NAN_SYNC_CONFIG_DEFAULT();
    result=esp_wifi_nan_sync_start(&config);
    if(result!=ESP_OK)goto failed;
    radio=true;
    wifi_nan_publish_cfg_t publish={.service_name="wendy.mesh.v1",
        .type=NAN_PUBLISH_UNSOLICITED,.ndp_resp_needed=1,.datapath_reqd=1,
        .ssi_len=sizeof presence,.ssi=presence};
    wifi_nan_subscribe_cfg_t subscribe={.service_name="wendy.mesh.v1",
        .type=CONFIG_WENDY_NET_TEST_NAN_PASSIVE_SUBSCRIBER ? NAN_SUBSCRIBE_PASSIVE:NAN_SUBSCRIBE_ACTIVE,
        .datapath_reqd=1,
        .ssi_len=sizeof presence,.ssi=presence};
    if(!CONFIG_WENDY_NET_TEST_NAN_PASSIVE_SUBSCRIBER)
        pub=esp_wifi_nan_publish_service(&publish);
    sub=esp_wifi_nan_subscribe_service(&subscribe);
    ESP_LOGI(TAG,"TLS-only NAN discovery active: publish=%u subscribe=%u passive_test=%u stackfree=%u",
        pub,sub,(unsigned)CONFIG_WENDY_NET_TEST_NAN_PASSIVE_SUBSCRIBER,
        (unsigned)uxTaskGetStackHighWaterMark(NULL));
    if(!sub || (!CONFIG_WENDY_NET_TEST_NAN_PASSIVE_SUBSCRIBER && !pub)){
        result=ESP_FAIL;goto failed;
    }
    while(!atomic_load(&stopping)){
        struct event event;
        while(xQueueReceive(events,&event,0)==pdTRUE)handle_event(&event);
        tick();vTaskDelay(pdMS_TO_TICKS(100));
    }
failed:
    if(!atomic_load(&stopping))ESP_LOGE(TAG,"NAN-only adapter start failed: %s",esp_err_to_name(result));
    if(registered)(void)esp_event_handler_unregister(WIFI_EVENT,ESP_EVENT_ANY_ID,receive);
    if(pub)(void)esp_wifi_nan_cancel_service(pub);
    if(sub)(void)esp_wifi_nan_cancel_service(sub);
    if(radio)(void)esp_wifi_nan_sync_stop();
    if(interface){esp_netif_destroy_default_wifi(interface);interface=NULL;}
    for(unsigned i=0;i<PEERS;i++)forget_path(&peers[i]);
    struct offer offer;while(offers && xQueueReceive(offers,&offer,0)==pdTRUE)if(offer.fd>=0)close(offer.fd);
    if(events){vQueueDelete(events);events=NULL;}
    if(offers){vQueueDelete(offers);offers=NULL;}
    atomic_store(&started,false);
    vTaskDelete(NULL);
}
bool wn_nan_stop(void)
{atomic_store(&stopping,true);return !atomic_load(&started);}
esp_err_t wn_nan_start(void)
{
    if(atomic_exchange(&started,true))return ESP_OK;
    atomic_store(&stopping,false);
    char tenant_text[37],device[65],network[64];uint8_t hash[32];
    wendy_conf_get_enrolled_ids(tenant_text,device);
    snprintf(network,sizeof network,"tenant:%s:default",tenant_text);
    if(wn_uuid_parse(tenant_text,tenant) || wn_uuid_parse(device,self) ||
       wendy_pki_sha256((const uint8_t*)network,strlen(network),hash))goto failed;
    memcpy(mesh,hash,sizeof mesh);
    if(wn_nan_presence_write(tenant,self,mesh,true,presence)<0)goto failed;
    events=xQueueCreate(8,sizeof(struct event));offers=xQueueCreate(2,sizeof(struct offer));
    if(!events || !offers)goto failed;
    for(unsigned i=0;i<PEERS;i++)peers[i].listener=-1;
    if(xTaskCreate(run,"net-nan",6144,NULL,3,NULL)==pdPASS)return ESP_OK;
failed:
    if(events){vQueueDelete(events);events=NULL;}
    if(offers){vQueueDelete(offers);offers=NULL;}
    atomic_store(&started,false);return ESP_FAIL;
}
