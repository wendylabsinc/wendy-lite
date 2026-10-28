#include "wendy_net_alloc.h"
#include "wendy_net_task.h"
/* One bounded, device-authenticated app stream per TCP/TLS connection. */
#include "wendy_net_peer.h"
#include "wendy_net_peer_protocol.h"
#include "wendy_pki_mesh.h"
#include "wendy_pki_work.h"
#include "wendy_net_profile.h"
#include "actor_driver.h"
#include "wendy_pki_verify.h"
#include "wendy_conf.h"
#if CONFIG_WENDY_NET
#include "wendy_net.h"
#endif
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_memory_utils.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CONFIG_WENDY_NET_TEST_ECHO_SERVICE
#define CONFIG_WENDY_NET_TEST_ECHO_SERVICE 0
#endif
#define APP_PORT 43022
#ifndef CONFIG_WENDY_SERVER_PORT
#define CONFIG_WENDY_SERVER_PORT 5054
#endif
#define AGENT_PORT CONFIG_WENDY_SERVER_PORT
#ifndef CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE
#if ESP_PLATFORM && !CONFIG_SPIRAM
#define CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE 256
#else
#define CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE 1024
#endif
#endif
#define ECHO_PORT 28081
#define TIME_PORT 43025
#define DATAGRAM_RELAY_STACK 4096
#ifndef CONFIG_WENDY_NET_TCP_RELAY_STACK_SIZE
#define CONFIG_WENDY_NET_TCP_RELAY_STACK_SIZE 8192
#endif
#ifndef CONFIG_WENDY_NET_APP_MAX_FLOWS
#define CONFIG_WENDY_NET_APP_MAX_FLOWS 1
#endif
static atomic_bool starting,ready;
static atomic_uint inbound_flows,outbound_flows;
/* Handshakes still use the single certificate worker. A resident relay owns
 * one admission slot, not the whole incoming/outgoing direction. */
static bool claim_flow(atomic_uint *counter)
{
    unsigned count=atomic_load(counter);
    do {
        if(count>=CONFIG_WENDY_NET_APP_MAX_FLOWS)return false;
    }while(!atomic_compare_exchange_weak(counter,&count,count+1));
    return true;
}
static atomic_int listener=-1;
static atomic_int time_listener=-1;
static const char *TAG="wendy_net_app";

static int transfer(wendy_pki_connection *c,void *data,size_t size,bool writing,int64_t deadline)
{
    uint8_t *p=data;
    while (size && esp_timer_get_time()<deadline && wendy_conf_is_current()) {
        ssize_t n=writing ? wendy_pki_write(c,p,size) : wendy_pki_read(c,p,size);
        if (n>0 && (size_t)n<=size) {p+=n;size-=n;}
        else if ((n!=-2 && n!=-3) || wendy_pki_wait(c,n==-3,deadline)<0) return -1;
    }
    return size ? -1 : 0;
}

static esp_err_t app_connect(const char *peer,uint16_t service_port,
                            wendy_pki_connection **connection,uint16_t *datagrams)
{
    if (!connection) return ESP_ERR_INVALID_ARG;
    *connection = NULL;
    if (!peer || !service_port) return ESP_ERR_INVALID_ARG;
    if(!datagrams && service_port==AGENT_PORT)return ESP_ERR_NOT_SUPPORTED;
    uint8_t address[16]; uint16_t port;
    esp_err_t result = wendy_net_peer_app_endpoint(peer, address, &port);
    if (result != ESP_OK) return result;
    char host[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, address, host, sizeof host)) return ESP_FAIL;
    struct wendy_pki_mesh_identity identity;
    wendy_net_peer_prepare_handshake();
    result = wendy_pki_app_connect(host, port, peer, connection, &identity);
    if (result != ESP_OK) return result;
    uint8_t request[8] = {'W','A','S','1'}, ack[8]={0};
    size_t request_size=6,ack_size=1;
    if(datagrams){
        memcpy(request,"WAU3",4);wn_put16(request+6,*datagrams);
        request_size=ack_size=8;
    }
    wn_put16(request+4, service_port);
    int64_t deadline = esp_timer_get_time()+INT64_C(10000000);
    bool failed=transfer(*connection,request,request_size,true,deadline) ||
                transfer(*connection,ack,ack_size,false,deadline);
    if(datagrams){
        uint16_t selected=wn_get16(ack+6);
        failed=failed || memcmp(ack,"WUA3",4) || ack[5]!=3 || ack[4]!=1 ||
               !selected || selected>*datagrams;
        if(!failed)*datagrams=selected;
    }else failed=failed || ack[0]!=1;
    if (failed) {
        wendy_pki_close(*connection); *connection = NULL;
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t wendy_net_app_connect(const char *peer,uint16_t service_port,
                               wendy_pki_connection **connection)
{
    return app_connect(peer,service_port,connection,NULL);
}

esp_err_t wendy_net_app_refresh_time(const char *peer,struct wendy_pki_mesh_identity *identity)
{
    if(!claim_flow(&outbound_flows))return ESP_ERR_INVALID_STATE;
    wendy_pki_connection *connection=NULL;
    esp_err_t result=wendy_net_app_connect(peer,TIME_PORT,&connection);
    if(result!=ESP_OK){atomic_fetch_sub(&outbound_flows,1);return result;}
    uint8_t nonce[32],request[128],header[8]={'W','N','T','1'},*reply=NULL;
    esp_fill_random(nonce,sizeof nonce);
    size_t size=wendy_pki_time_request(request,nonce),reply_size=0;
    int64_t started=esp_timer_get_time(),deadline=started+INT64_C(30000000);
    result=ESP_FAIL;wn_put32(header+4,(uint32_t)size);
    if(!size || transfer(connection,header,8,true,deadline) ||
       transfer(connection,request,size,true,deadline) || transfer(connection,header,4,false,deadline))goto done;
    reply_size=wn_get32(header);
    if(!reply_size || reply_size>65536 || !(reply=wendy_net_malloc(reply_size)) ||
       transfer(connection,reply,reply_size,false,deadline))goto done;
    /* Release all app TLS records/chain state before full TSA verification. */
    wendy_pki_close(connection);connection=NULL;
    result=wendy_pki_net_time_reply(identity,nonce,reply,reply_size,started);
done:
    wendy_pki_close(connection);wendy_net_free(reply);
    ESP_LOGI(TAG,"mesh app signed-time renewal: peer=%s result=%s ms=%u",peer,
        esp_err_to_name(result),(unsigned)((esp_timer_get_time()-started)/1000));
    atomic_fetch_sub(&outbound_flows,1);return result;
}

#if CONFIG_WENDY_NET_TEST_APP_CLIENT
static atomic_bool test_busy, test_passed;
static int64_t test_next;
static void test_client(void *argument)
{
    wendy_net_memory_scope_t previous=wendy_net_runtime_scope_enter();
    char *peer = argument;
    wendy_pki_connection *c = NULL;
    int64_t started = esp_timer_get_time();
    esp_err_t result = wendy_net_app_connect(peer, ECHO_PORT, &c);
    size_t count = 0;
    uint8_t sent[1024], received[1024];
    int64_t deadline = started + INT64_C(180000000);
    if (result == ESP_OK) {
        while (count < 65536) {
            esp_fill_random(sent, sizeof sent);
            if (transfer(c, sent, sizeof sent, true, deadline) ||
                transfer(c, received, sizeof received, false, deadline) ||
                memcmp(sent, received, sizeof sent)) {
                result = ESP_FAIL; break;
            }
            count += sizeof sent;
        }
    }
    wendy_pki_close(c);
    bool passed = result == ESP_OK && count == 65536;
    ESP_LOGI(TAG, "native app TLS client: peer=%s result=%s bytes=%u ms=%u stackfree=%u",
        peer, passed ? "PASS" : esp_err_to_name(result), (unsigned)count,
        (unsigned)((esp_timer_get_time()-started)/1000),
        (unsigned)uxTaskGetStackHighWaterMark(NULL));
    if (passed) atomic_store(&test_passed, true);
    wendy_net_free(peer); atomic_store(&test_busy, false);
    wendy_net_memory_scope_leave(previous);vTaskDelete(NULL);
}
#endif
void wendy_net_app_test_start(const char *peer)
{
#if CONFIG_WENDY_NET_TEST_APP_CLIENT
    int64_t now = esp_timer_get_time();
    if (atomic_load(&test_passed) || now < test_next || atomic_exchange(&test_busy, true)) return;
    test_next = now + INT64_C(60000000);
    char *copy = wendy_net_strdup(peer);
    if (copy && wendy_net_task_create(test_client, "net-app-test", 16384, copy, 4, NULL) == pdPASS) return;
    wendy_net_free(copy); atomic_store(&test_busy, false);
#else
    (void)peer;
#endif
}

/* Native WendyCom mTLS uses its signed agent endpoint directly. App TLS is
 * for guest services, not another wrapper around the agent's own TLS. */
struct buffer {uint8_t data[CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE];size_t size,offset;bool eof;};
struct app_flow {
    wendy_pki_connection *connection;
    int backend;
    bool test_echo,outbound,native_agent;
    uint16_t datagram_max;
    uint16_t service_port;
    int guest_handle,listener_handle;
    uint8_t *datagram_in,*datagram_out;
    /* Guest TX arrives with raw heap ownership. Charge its transferred lifetime
     * explicitly; RX uses a managed pointer and passes its matching destructor. */
    wendy_net_memory_reservation_t datagram_out_charge;
    struct wna_channel channel;
    struct wna_session state;
    struct wendy_pki_net_setup *setup;
    atomic_bool job_done;
    int job_result,fd,pair_listener,pair_guest;
    bool connecting,backend_connecting,negotiated,local_half;
    unsigned phase;
    uint8_t request[8],response[8];
    size_t received,sent,wanted;
    char expected[37];
    struct buffer *buffers;
};
/* Only UDP flows carry this state. All live UDP relays share one on-demand
 * task; packet storage and each independently authenticated TLS context stay
 * owned by their flow. No task or payload allocation survives the last flow. */
struct datagram_flow {
    struct app_flow flow;
    struct datagram_flow *next;
    uint8_t header[2],output_header[2];
    size_t header_used,received,wanted,outgoing,sent;
    int output_handle;
    unsigned inbound,outbound,last_in,last_out;
    int64_t activity;
};
static struct datagram_flow *datagram_flows;
static void app_actor_add(struct app_flow *);

/* Only actual pending packets own payload memory. Negotiating a large UDP
 * capacity does not reserve that capacity twice on an idle encrypted flow. */
static void *datagram_alloc(size_t size)
{
    return wendy_net_malloc(size ? size:1);
}
/* One bounded nonblocking pass per flow; never wait on one peer while a
 * different peer has work. PKI read/write retain their lifetime checks. */
static int datagram_step(struct datagram_flow *d)
{
    struct app_flow *flow=&d->flow;
    wendy_pki_connection *c=flow->connection;
    if(!wendy_conf_is_current() || wendy_pki_reset_in_progress() ||
       esp_timer_get_time()-d->activity>=INT64_C(30000000))return -1;
#if CONFIG_WENDY_NET
    if(flow->outbound && !wendy_net_mesh_socket_live(flow->guest_handle))return -1;
    if(!flow->outbound && wendy_net_guest_datagram_owner(flow->service_port)!=flow->listener_handle)return -1;
#endif
    bool progress=false;
    if(d->header_used<2){
        ssize_t n=wendy_pki_read(c,d->header+d->header_used,2-d->header_used);
        if(n>0){d->header_used+=n;progress=true;if(d->header_used==2){
            d->wanted=wn_get16(d->header);if(d->wanted>flow->datagram_max)return -1;
        }} else if(!n || (n!=-2 && n!=-3))return -1;
    }
    if(d->header_used==2 && !flow->datagram_in){
        flow->datagram_in=datagram_alloc(d->wanted);
        if(!flow->datagram_in){
            ESP_LOGW(TAG,"UDP input allocation failed: bytes=%u heap=%u largest=%u",
                (unsigned)d->wanted,(unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
                (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
            return -1;
        }
    }
    if(d->header_used==2 && d->received<d->wanted){
        ssize_t n=wendy_pki_read(c,flow->datagram_in+d->received,d->wanted-d->received);
        if(n>0){d->received+=n;progress=true;}
        else if(!n || (n!=-2 && n!=-3))return -1;
    }
    if(d->header_used==2 && d->received==d->wanted){
#if CONFIG_WENDY_NET
        int delivered=flow->outbound ?
            wendy_net_mesh_datagram_receive_owned(flow->guest_handle,&flow->datagram_in,d->wanted,wendy_net_free):
            wendy_net_guest_datagram_deliver_owned(flow->listener_handle,&flow->guest_handle,&flow->datagram_in,d->wanted,flow->datagram_max,wendy_net_free);

        if(delivered<0)return -1;
        if(delivered){
            d->inbound++;d->last_in=(unsigned)d->wanted;d->header_used=d->received=d->wanted=0;progress=true;
        }
#else
        return -1;
#endif
    }
    if(!flow->datagram_out){
#if CONFIG_WENDY_NET
        size_t length=0;
        int taken=wendy_net_guest_datagram_take(flow->guest_handle,&flow->datagram_out,&length);
        if(taken<0)return -1;
        if(taken){
            d->output_handle=flow->guest_handle;
            if(length>flow->datagram_max)return -1;
            if(!wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),
                &flow->datagram_out_charge,wendy_net_memory_charge(length ? length:1),
                esp_ptr_external_ram(flow->datagram_out) ? WENDY_NET_MEMORY_EXTERNAL:WENDY_NET_MEMORY_INTERNAL))return -1;
            d->outbound++;d->last_out=(unsigned)length;
            wn_put16(d->output_header,(uint16_t)length);d->outgoing=length+2;d->sent=0;progress=true;
        }
#endif
    }
    if(d->sent<d->outgoing){
        size_t chunk;const uint8_t *data;
        if(d->sent<2){data=d->output_header+d->sent;chunk=2-d->sent;}
        else{data=flow->datagram_out+d->sent-2;chunk=d->outgoing-d->sent;if(chunk>1024)chunk=1024;}
        ssize_t n=wendy_pki_write(c,data,chunk);
        if(n>0){
            d->sent+=n;progress=true;
            if(d->sent==d->outgoing){
                free(flow->datagram_out);flow->datagram_out=NULL;
                wendy_net_memory_release(&flow->datagram_out_charge);d->sent=d->outgoing=0;
#if CONFIG_WENDY_NET
                wendy_net_guest_datagram_sent(d->output_handle);
#endif
            }
        }else if(!n || (n!=-2 && n!=-3))return -1;
    }
    if(progress)d->activity=esp_timer_get_time();
    return progress ? 1:0;
}

static void close_flow(struct app_flow *flow)
{
#if CONFIG_WENDY_NET
    /* Before WAU/WAS negotiation there is no native datagram association or
     * loopback stream yet. Complete the pending guest connect explicitly so
     * ordinary route loss/peer restart does not leave it resolving forever. */
    if(flow->outbound && !flow->negotiated){
        ESP_LOGI(TAG,"outgoing VIP setup closed: peer=%s phase=%u connecting=%u channel_failed=%u result=%d",
            flow->expected,(unsigned)flow->state.phase,(unsigned)flow->connecting,
            (unsigned)flow->channel.failed,flow->job_result);
        wendy_net_mesh_connected(flow->guest_handle,-1);
    }else if(flow->datagram_max)wendy_net_guest_datagram_closed(flow->guest_handle);
#endif
    if(flow->state.lent)abort();
    if (flow->backend>=0) close(flow->backend);
    if(flow->fd>=0)close(flow->fd);
    if(flow->pair_listener>=0)close(flow->pair_listener);
    if(flow->pair_guest>=0)close(flow->pair_guest);
    wendy_pki_net_dispose(flow->setup);
    wnad_handshake_release(flow);
    wendy_net_free(flow->buffers);
    bool outbound=flow->outbound;
    wendy_pki_close(flow->connection);
    wendy_net_free(flow->datagram_in);free(flow->datagram_out);
    wendy_net_memory_release(&flow->datagram_out_charge);wendy_net_free(flow);
    ESP_LOGI(TAG,"app TLS closed: heap=%u largest=%u stackfree=%u",
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT),
        (unsigned)uxTaskGetStackHighWaterMark(NULL));
    atomic_fetch_sub(outbound ? &outbound_flows : &inbound_flows,1);
}
#if CONFIG_WENDY_NET
struct guest_connect {int handle;char peer[37];uint16_t port;bool datagram;int64_t deadline;};

/* A loopback pair lets the existing guest socket task retain its buffers,
 * readiness notifications and cleanup. Only the native relay owns TLS. */
static struct guest_connect *pending_guest;
static pthread_mutex_t request_lock=PTHREAD_MUTEX_INITIALIZER;
static int guest_mesh_resolve(const char *host,uint8_t address[16])
{
    uint8_t uuid[16];int recognized=wn_device_hostname_parse(host,uuid);
    if(recognized<=0)return recognized;
    if(!wendy_conf_is_current() || wendy_pki_reset_in_progress())return -1;
    wn_address(uuid,address);return 1;
}
static int guest_mesh_begin(int handle,const char *host,uint16_t port,bool datagram)
{
    if(!atomic_load(&ready))return -1;
    uint8_t uuid[16];int recognized=wn_device_hostname_parse(host,uuid);
    if(recognized<=0)return recognized;
    if(!wendy_conf_is_current() || wendy_pki_reset_in_progress())return -1;
    char peer[37];wn_uuid_format(uuid,peer);
    char tenant[37],self[65];wendy_conf_get_enrolled_ids(tenant,self);
    if(!strcmp(peer,self)){
        /* The current guest already owns both ends of this local service.
         * Reuse its listener bridge instead of queueing a client handshake
         * whose server would need the same serialized TLS worker. Listener
         * lookup and completion retain the ordinary stop/reset ownership. */
        int owner=-1;
        int fd=datagram ? wendy_net_guest_datagram_connect(port,&owner)
                        : wendy_net_guest_service_connect(port);
#if CONFIG_WENDY_NET_TEST_DIAGNOSTICS
        ESP_LOGI(TAG,"guest local service: port=%u handle=%d fd=%d datagram=%u",
                 (unsigned)port,handle,fd,(unsigned)datagram);
#endif
        (void)wendy_net_mesh_connected(handle,fd);
        return 1;
    }
    if(!claim_flow(&outbound_flows))return -1;
    struct guest_connect *request=wendy_net_calloc(1,sizeof *request);
    if(request){
        request->handle=handle;request->port=port;request->datagram=datagram;
        request->deadline=esp_timer_get_time()+INT64_C(120000000);
        memcpy(request->peer,peer,sizeof peer);
        pthread_mutex_lock(&request_lock);
        bool accepted=atomic_load(&ready) && pending_guest==NULL;
        if(accepted)pending_guest=request;
        pthread_mutex_unlock(&request_lock);
        if(accepted){wnad_wake();return 1;}
    }
    wendy_net_free(request);atomic_fetch_sub(&outbound_flows,1);return -1;
}
#endif
/* Accepted VIPs and all established TCP/UDP relays are actor-owned. */
static struct app_flow *new_flow(int fd,bool outbound)
{
    struct datagram_flow *d=wendy_net_calloc(1,sizeof *d);if(!d)return NULL;
    struct app_flow *f=&d->flow;
    f->fd=fd;f->outbound=outbound;f->backend=f->pair_listener=f->pair_guest=-1;
    f->state=(struct wna_session){.phase=WNA_PREPARE,.deadline=(uint64_t)esp_timer_get_time()+UINT64_C(120000000)};
    f->wanted=6;return f;
}
static void app_actor_add(struct app_flow *flow)
{
    struct datagram_flow *d=(struct datagram_flow *)flow;
    d->activity=esp_timer_get_time();d->next=datagram_flows;datagram_flows=d;
}
void wendy_net_app_accept(int fd)
{
    if(!wendy_conf_is_current() || !claim_flow(&inbound_flows)){close(fd);return;}
    struct app_flow *flow=new_flow(fd,false);
    if(!flow || fcntl(fd,F_SETFL,O_NONBLOCK)<0){wendy_net_free(flow);close(fd);atomic_fetch_sub(&inbound_flows,1);return;}
    app_actor_add(flow);
}
static void app_setup_work(void *context)
{
    struct app_flow *f=context;
    if(f->state.phase==WNA_PREPARE){
        struct wendy_pki_stream bio={.context=&f->channel,.read=wna_read,.write=wna_write,.wait=wnad_no_wait};
        esp_err_t result=wendy_pki_net_begin(&bio,!f->outbound,f->expected[0] ? f->expected:NULL,true,&f->setup);
        f->job_result=result==ESP_OK ? 0:result==ESP_ERR_TIMEOUT ? 2:-1;
    }else f->job_result=wendy_pki_net_step(f->setup);
    atomic_store(&f->job_done,true);
}
static int tls_transfer(struct app_flow *f,uint8_t *bytes,size_t size,size_t *offset,bool writing)
{
    if(*offset>=size)return 0;
    ssize_t n=writing ? wendy_pki_write(f->connection,bytes+*offset,size-*offset):
                       wendy_pki_read(f->connection,bytes+*offset,size-*offset);
    if(n>0){*offset+=(size_t)n;return *offset==size ? 0:1;}
    return n==-2 || n==-3 ? 1:-1;
}
static int begin_pair(struct app_flow *f)
{
    if(f->pair_listener>=0)return 0;
    f->pair_listener=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    socklen_t size=sizeof address;
    if(f->pair_listener<0 || f->pair_listener>=FD_SETSIZE || fcntl(f->pair_listener,F_SETFL,O_NONBLOCK)<0 ||
       bind(f->pair_listener,(struct sockaddr *)&address,size) || getsockname(f->pair_listener,(struct sockaddr *)&address,&size) ||
       listen(f->pair_listener,1))return -1;
    bool connecting;
    f->pair_guest=wnad_connect("127.0.0.1",ntohs(address.sin_port),&connecting);
    return f->pair_guest<0 ? -1:0;
}
static int negotiate(struct app_flow *f)
{
    if(f->outbound){
        int r=tls_transfer(f,f->request,f->datagram_max ? 8:6,&f->sent,true);if(r)return r;
        r=tls_transfer(f,f->response,f->datagram_max ? 8:1,&f->received,false);if(r)return r;
        if(f->datagram_max){
            unsigned maximum=wn_get16(f->response+6);
            if(memcmp(f->response,"WUA3",4) || f->response[4]!=1 || f->response[5]!=3 || !maximum || maximum>f->datagram_max)return -1;
            f->datagram_max=(uint16_t)maximum;
            if(wendy_net_mesh_datagram_connected(f->guest_handle,maximum))return -1;
        }else{
            if(f->response[0]!=1 || begin_pair(f))return -1;
            if(f->backend<0){
                f->backend=accept(f->pair_listener,NULL,NULL);
                if(f->backend<0)return errno==EAGAIN || errno==EWOULDBLOCK ? 1:-1;
                if(f->backend>=FD_SETSIZE || fcntl(f->backend,F_SETFL,O_NONBLOCK)<0)return -1;
                close(f->pair_listener);f->pair_listener=-1;
                wendy_net_mesh_connected(f->guest_handle,f->pair_guest);f->pair_guest=-1;
            }
        }
    }else{
        int r=tls_transfer(f,f->request,f->wanted,&f->received,false);if(r)return r;
        if(!f->phase){
            f->service_port=wn_get16(f->request+4);
            if(!memcmp(f->request,"WAU3",4)){
                f->wanted=8;if(f->received<8)return 1;
                unsigned maximum=wn_get16(f->request+6);
                if(maximum>wendy_net_guest_datagram_capacity())maximum=wendy_net_guest_datagram_capacity();
                if(maximum>65507)maximum=65507;
                f->listener_handle=wendy_net_guest_datagram_owner(f->service_port);
                if(!maximum || f->listener_handle<=0)return -1;
                f->datagram_max=(uint16_t)maximum;memcpy(f->response,"WUA3",4);
                f->response[4]=1;f->response[5]=3;wn_put16(f->response+6,f->datagram_max);
            }else{
                if(memcmp(f->request,"WAS1",4))return -1;
                if(f->service_port==AGENT_PORT)return -1;
                f->test_echo=CONFIG_WENDY_NET_TEST_ECHO_SERVICE && f->service_port==ECHO_PORT;
                if(!f->test_echo){
                    if(f->service_port==TIME_PORT)
                        f->backend=wnad_connect("127.0.0.1",f->service_port,&f->backend_connecting);
                    else {f->backend=wendy_net_guest_service_begin(f->service_port);f->backend_connecting=f->backend>=0;}
                    if(f->backend<0)return -1;
                }
                f->response[0]=1;
            }
            f->phase=1;
        }
        if(f->backend_connecting){
            int connected=wnad_connected(f->backend);if(connected<=0)return connected ? -1:1;
            f->backend_connecting=false;
        }
        r=tls_transfer(f,f->response,f->datagram_max ? 8:1,&f->sent,true);if(r)return r;
    }
    if(!f->datagram_max && !f->buffers){f->buffers=wendy_net_calloc(2,sizeof *f->buffers);if(!f->buffers)return -1;}
    f->negotiated=true;((struct datagram_flow *)f)->activity=esp_timer_get_time();
    ESP_LOGI(TAG,"actor VIP ready: peer=%s port=%u udp=%u heap=%u",f->expected,(unsigned)f->service_port,(unsigned)f->datagram_max,(unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
    return 0;
}
static int relay_step(struct app_flow *f)
{
    struct buffer *remote=&f->buffers[0],*local=&f->buffers[1];bool progress=false;
    if(remote->offset==remote->size && !remote->eof){
        ssize_t n=wendy_pki_read(f->connection,remote->data,sizeof remote->data);
        if(n>0){remote->offset=0;remote->size=n;progress=true;}
        else if(!n)remote->eof=true;else if(n!=-2 && n!=-3)return -1;
    }
    if(f->test_echo){
        if(remote->offset<remote->size){
            ssize_t n=wendy_pki_write(f->connection,remote->data+remote->offset,remote->size-remote->offset);
            if(n>0){remote->offset+=n;progress=true;}else if(n!=-2 && n!=-3)return -1;
        }
        if(remote->eof && remote->offset==remote->size && !f->channel.output.size)return -1;
        return progress;
    }
    if(remote->offset<remote->size){
        ssize_t n=send(f->backend,remote->data+remote->offset,remote->size-remote->offset,MSG_DONTWAIT);
        if(n>0){remote->offset+=n;progress=true;}
        else if(!n || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR))return -1;
    }
    if(remote->eof && remote->offset==remote->size && !f->local_half){shutdown(f->backend,SHUT_WR);f->local_half=true;}
    if(local->offset==local->size && !local->eof){
        ssize_t n=recv(f->backend,local->data,sizeof local->data,MSG_DONTWAIT);
        if(n>0){local->offset=0;local->size=n;progress=true;}
        else if(!n)local->eof=true;else if(errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)return -1;
    }
    if(local->offset<local->size){
        ssize_t n=wendy_pki_write(f->connection,local->data+local->offset,local->size-local->offset);
        if(n>0){local->offset+=n;progress=true;}else if(n!=-2 && n!=-3)return -1;
    }
    if(local->eof && local->offset==local->size && !f->channel.output.size)return -1;
    return progress;
}
static int app_step(struct app_flow *f,int64_t now)
{
    if(f->state.lent){
        if(!atomic_load(&f->job_done))return 0;
        wna_completed(&f->state,f->job_result);
        if(f->job_result==2){f->state.retry_at=(uint64_t)now+50000;wnad_handshake_release(f);}
    }
    if(f->state.cancel || !wendy_conf_is_current() || wendy_pki_reset_in_progress())return -1;
    if(!f->negotiated && now>=(int64_t)f->state.deadline)return -1;
    if(f->connecting){int r=wnad_connected(f->fd);if(r<=0)return r;f->connecting=false;}
    if(f->native_agent){
        /* Transfer the connected raw stream to the guest. WendyCom's client
         * and native agent retain their one end-to-end TLS session. */
        wendy_net_mesh_connected(f->guest_handle,f->fd);f->fd=-1;f->negotiated=true;
        return -1;
    }
    int progress=wnad_channel_io(&f->channel,f->fd,NULL);if(progress<0)return -1;
    if(f->state.phase!=WNA_READY){
        enum wna_effect e=wna_next(&f->state,(uint64_t)now,f->channel.input.size || f->channel.eof,
            wna_buffer_space(&f->channel.output)!=0);
        if(e==WNA_CLOSE)return -1;
        if(e==WNA_CRYPTO_PREPARE && !wnad_handshake_claim(f))return progress;
        if(e==WNA_CRYPTO_PREPARE || e==WNA_CRYPTO_STEP){
            atomic_store(&f->job_done,false);
            if(wendy_pki_work_submit(app_setup_work,f))wna_lend(&f->state);
        }
        return progress;
    }
    if(!f->connection){f->connection=wendy_pki_net_take(f->setup,&(struct wendy_pki_mesh_identity){0});f->setup=NULL;wnad_handshake_release(f);if(!f->connection)return -1;}
    if(!f->negotiated){if(now>=(int64_t)f->state.deadline)return -1;return negotiate(f)<0 ? -1:progress;}
    int r=f->datagram_max ? datagram_step((struct datagram_flow *)f):relay_step(f);
    return r<0 ? -1:progress || r;
}
bool wendy_net_app_yield_setup(void)
{
    bool changed=false;
    for(struct datagram_flow *d=datagram_flows;d;d=d->next){
        struct app_flow *f=&d->flow;
        if(wna_yield_guest_setup(&f->state,WENDY_NET_NON_TRANSIT,f->outbound,
            f->connection || f->negotiated || f->native_agent,
            wendy_pki_handshake_owned(f))){
            ESP_LOGI(TAG,"yielding outgoing guest TLS setup for native management: peer=%s lent=%u",
                f->expected,(unsigned)f->state.lent);
            changed=true;
        }
    }
    return changed;
}
int wendy_net_app_poll(void)
{
    int fd=atomic_load(&listener),progress=0;
    if(fd>=0 && atomic_load(&inbound_flows)<CONFIG_WENDY_NET_APP_MAX_FLOWS){int incoming=accept(fd,NULL,NULL);if(incoming>=0){wendy_net_app_accept(incoming);progress=1;}}
#if CONFIG_WENDY_NET
    pthread_mutex_lock(&request_lock);struct guest_connect *q=pending_guest;pending_guest=NULL;pthread_mutex_unlock(&request_lock);
    if(q){
        uint8_t address[16];uint16_t port=0;
        bool native_agent=!q->datagram &&
            wendy_net_peer_agent_endpoint_now(q->peer,address,&port)==ESP_OK && port==q->port;
        esp_err_t endpoint=native_agent ? ESP_OK:wendy_net_peer_app_endpoint_now(q->peer,address,&port);
        if(endpoint!=ESP_OK && esp_timer_get_time()<q->deadline){
            pthread_mutex_lock(&request_lock);
            if(atomic_load(&ready) && !pending_guest){pending_guest=q;q=NULL;}
            pthread_mutex_unlock(&request_lock);
        }
        if(q){
        struct app_flow *f=endpoint==ESP_OK ? new_flow(-1,true):NULL;
        if(f && endpoint==ESP_OK){
            char host[INET6_ADDRSTRLEN];inet_ntop(AF_INET6,address,host,sizeof host);
            f->fd=wnad_connect(host,port,&f->connecting);
        }
        if(f && f->fd>=0){
            f->guest_handle=q->handle;f->service_port=q->port;memcpy(f->expected,q->peer,37);
            f->native_agent=native_agent;
            if(q->datagram)f->datagram_max=(uint16_t)wendy_net_guest_datagram_capacity();
            memcpy(f->request,q->datagram ? "WAU3":"WAS1",4);wn_put16(f->request+4,q->port);wn_put16(f->request+6,f->datagram_max);
            app_actor_add(f);
        }else{if(f)close_flow(f);else atomic_fetch_sub(&outbound_flows,1);wendy_net_mesh_connected(q->handle,-1);}
        wendy_net_free(q);progress=1;
        }
    }
#endif
    int64_t now=esp_timer_get_time();
    for(struct datagram_flow **at=&datagram_flows;*at;){
        struct datagram_flow *d=*at;int r=app_step(&d->flow,now);
        if(r<0){*at=d->next;close_flow(&d->flow);progress=1;}
        else{progress|=r>0;at=&d->next;}
    }
    return progress;
}
bool wendy_net_app_stop(void)
{
    atomic_store(&ready,false);
    int fd=atomic_exchange(&listener,-1);if(fd>=0)close(fd);
    fd=atomic_exchange(&time_listener,-1);if(fd>=0)close(fd);
#if CONFIG_WENDY_NET
    wendy_net_set_mesh_connector(NULL);wendy_net_set_mesh_resolver(NULL);
    wendy_net_set_service_catalog(NULL);
    pthread_mutex_lock(&request_lock);
    struct guest_connect *q=pending_guest;pending_guest=NULL;
    pthread_mutex_unlock(&request_lock);
    if(q){wendy_net_mesh_connected(q->handle,-1);atomic_fetch_sub(&outbound_flows,1);wendy_net_free(q);}
#endif
    for(struct datagram_flow **at=&datagram_flows;*at;){
        struct app_flow *f=&(*at)->flow;f->state.cancel=true;
        if(f->state.lent){
            if(!atomic_load(&f->job_done)){at=&(*at)->next;continue;}
            wna_completed(&f->state,f->job_result);
        }
        *at=(*at)->next;
#if CONFIG_WENDY_NET
        if(f->outbound && !f->negotiated && !f->datagram_max)wendy_net_mesh_connected(f->guest_handle,-1);
#endif
        close_flow(f);
    }
    bool done=datagram_flows==NULL;
#if CONFIG_WENDY_NET
    if(done)wendy_net_mesh_discard_pending_datagrams();
#endif
    if(done)atomic_store(&starting,false);
    return done;
}
void wendy_net_app_watch(fd_set *rd,fd_set *wr,int *maximum,int64_t *deadline)
{
#if CONFIG_WENDY_NET
    pthread_mutex_lock(&request_lock);
    if(pending_guest){
        int64_t next=esp_timer_get_time()+INT64_C(1000000);
        if(pending_guest->deadline<next)next=pending_guest->deadline;
        if(next<*deadline)*deadline=next;
    }
    pthread_mutex_unlock(&request_lock);
#endif
    int fd=atomic_load(&listener);
    if(fd>=0 && atomic_load(&inbound_flows)<CONFIG_WENDY_NET_APP_MAX_FLOWS){FD_SET(fd,rd);if(fd>*maximum)*maximum=fd;}
    for(struct datagram_flow *d=datagram_flows;d;d=d->next){
        struct app_flow *f=&d->flow;
        if(f->state.lent)continue;
        if(!f->negotiated && (int64_t)f->state.deadline<*deadline)*deadline=(int64_t)f->state.deadline;
        if(f->state.retry_at && f->state.retry_at>(uint64_t)esp_timer_get_time() &&
           f->state.retry_at<(uint64_t)*deadline)*deadline=(int64_t)f->state.retry_at;
        bool can_read=!f->negotiated || f->datagram_max ||
            (f->buffers && f->buffers[0].offset==f->buffers[0].size && !f->buffers[0].eof);
        if(can_read && f->state.phase==WNA_READY &&
           (f->channel.input.size || (f->connection && wendy_pki_pending(f->connection))))
            *deadline=esp_timer_get_time();
        fd=f->fd;
        if(fd>=0){if(wna_buffer_space(&f->channel.input))FD_SET(fd,rd);if(f->connecting || f->channel.output.size)FD_SET(fd,wr);if(fd>*maximum)*maximum=fd;}
        if(f->backend>=0){
            fd=f->backend;
            if(f->backend_connecting)FD_SET(fd,wr);
            else if(f->buffers){if(f->buffers[1].offset==f->buffers[1].size && !f->buffers[1].eof)FD_SET(fd,rd);if(f->buffers[0].offset<f->buffers[0].size)FD_SET(fd,wr);}
            if(fd>*maximum)*maximum=fd;
        }
        if(f->pair_listener>=0){FD_SET(f->pair_listener,rd);if(f->pair_listener>*maximum)*maximum=f->pair_listener;}
    }
}
esp_err_t wendy_net_app_start(void)
{
    if (atomic_exchange(&starting,true)) return ESP_OK;
    int fd=socket(AF_INET6,SOCK_STREAM,0),yes=1,v6_only=0;
    struct sockaddr_in6 addr={.sin6_family=AF_INET6,.sin6_port=htons(APP_PORT)};
    if (fd<0) goto failed;
    if (fd>=FD_SETSIZE || setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) ||
        setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&v6_only,sizeof v6_only) ||
        bind(fd,(struct sockaddr*)&addr,sizeof addr) || listen(fd,CONFIG_WENDY_NET_APP_MAX_FLOWS) || fcntl(fd,F_SETFL,O_NONBLOCK)<0) goto failed;
    atomic_store(&listener,fd);atomic_store(&ready,true);
    int clock_fd=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in clock_addr={.sin_family=AF_INET,.sin_port=htons(TIME_PORT),
        .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if(clock_fd>=0 && clock_fd<FD_SETSIZE &&
       !setsockopt(clock_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) &&
       !bind(clock_fd,(struct sockaddr *)&clock_addr,sizeof clock_addr) && !listen(clock_fd,1))
        atomic_store(&time_listener,clock_fd);
    else if(clock_fd>=0)close(clock_fd);
#if CONFIG_WENDY_NET
    wendy_net_set_mesh_connector(guest_mesh_begin);
    wendy_net_set_mesh_resolver(guest_mesh_resolve);
    wendy_net_set_service_catalog(wendy_net_peer_service_catalog);
#endif
    ESP_LOGI(TAG,"TLS app listener ready on TCP%u; per-direction flow cap=%u",APP_PORT,(unsigned)CONFIG_WENDY_NET_APP_MAX_FLOWS);
#if CONFIG_WENDY_NET_TEST_AGENT_PROXY
    extern esp_err_t wendy_net_agent_proxy_start(void);
    if (wendy_net_agent_proxy_start()!=ESP_OK)
        ESP_LOGW(TAG,"lab agent proxy could not start");
#endif
    return ESP_OK;
failed:
    if (fd>=0) close(fd);
    atomic_store(&starting,false);return ESP_FAIL;
}
/* Keep the bounded TCP backlog while all relay slots are occupied. Accepting
 * and closing immediately would turn an ordinary reconnect into a TLS EOF. */
int wendy_net_app_listener(void)
{
    return -1; /* The mesh actor owns VIP acceptance, not the management worker. */
}
bool wendy_net_app_management_ready(void)
{
    if(!wendy_pki_handshake_available())return false;
#if CONFIG_WENDY_NET_MANAGEMENT_SETUP_FREE_BYTES > 0
    unsigned flows=atomic_load(&inbound_flows)+atomic_load(&outbound_flows);
    bool bulk=flows!=0;
    size_t available=heap_caps_get_free_size(MALLOC_CAP_8BIT);
#if CONFIG_WENDY_NET_RETAIN_TLS_INPUT
    available+=wendy_pki_input_workspace_cached_bytes();
#endif
    return !bulk || available>=CONFIG_WENDY_NET_MANAGEMENT_SETUP_FREE_BYTES;
#else
    return true;
#endif
}
int wendy_net_app_time_listener(void){return atomic_load(&time_listener);}

bool wendy_net_app_ready(void) {return atomic_load(&ready);}
