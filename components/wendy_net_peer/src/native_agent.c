/* Native WendyCom VIP TLS is mesh state. Only plaintext application bytes cross
 * to the existing com task. Raw socket operations live in this outer driver. */
#include "wendy_net_agent.h"
#include "agent_bridge.h"
#include "actor_driver.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_work.h"
#include "wendy_net_profile.h"
#include "wendy_conf.h"
#include "esp_timer.h"
#include "esp_log.h"
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <fcntl.h>
#include <netinet/tcp.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#ifndef CONFIG_WENDY_NET_APP_MAX_FLOWS
#define CONFIG_WENDY_NET_APP_MAX_FLOWS 1
#endif
#ifndef CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE
#define CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE 1024
#endif
struct native_flow {
    struct native_flow *next;
    int fd,result;
    struct wna_channel channel;
    struct wna_session state;
    struct wendy_pki_agent_setup *setup;
    wendy_pki_connection *connection;
    struct wendy_pki_agent_info info;
    struct wnab_bridge *bridge;
    atomic_bool done;
    const uint8_t *writing;
    size_t write_size;
    bool disposing,input_eof;
    int read_need,write_need;
    int64_t drain_deadline;
};
static struct native_flow *flows;
static unsigned flow_count;
static int native_socket_options(int fd)
{
    /* A userspace operator router can disappear without sending TCP FIN/RST.
     * Without probes, two such sessions exhaust a C5's management capacity
     * until certificate expiry. Reclaim a silent dead transport in about 30s;
     * an idle but reachable operator simply acknowledges the TCP probes. */
    int enabled=1,idle=15,interval=5,probes=3;
#ifdef TCP_KEEPIDLE
    int idle_option=TCP_KEEPIDLE; /* lwIP/Linux: seconds, unlike lwIP TCP_KEEPALIVE. */
#else
    int idle_option=TCP_KEEPALIVE; /* Darwin's seconds-based spelling. */
#endif
    return setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&enabled,sizeof enabled) ||
        setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&enabled,sizeof enabled) ||
        setsockopt(fd,IPPROTO_TCP,idle_option,&idle,sizeof idle) ||
        setsockopt(fd,IPPROTO_TCP,TCP_KEEPINTVL,&interval,sizeof interval) ||
        setsockopt(fd,IPPROTO_TCP,TCP_KEEPCNT,&probes,sizeof probes);
}
static int ending(struct native_flow *f,const char *reason,int64_t now)
{
    ESP_LOGI("net-native-agent","native VIP closed: reason=%s phase=%u result=%d",reason,(unsigned)f->state.phase,f->result);
    (void)f;(void)reason;(void)now;return -1;
}
/* One raw descriptor mailbox, no allocation or per-flow fd while OFF. The
 * trylock never waits behind a preempted lower-priority publisher. */
static atomic_flag mailbox_lock=ATOMIC_FLAG_INIT;
static atomic_bool accepting;
static atomic_uint publishers;
static int pending=-1;
void wendy_net_agent_start(void){atomic_store(&accepting,true);}
void wendy_net_agent_accept(int fd)
{
    bool accepted=false;
    if(!atomic_flag_test_and_set_explicit(&mailbox_lock,memory_order_acquire)){
        if(atomic_load(&accepting) && pending<0){
            pending=fd;atomic_fetch_add(&publishers,1);accepted=true;
        }
        atomic_flag_clear_explicit(&mailbox_lock,memory_order_release);
    }
    if(!accepted){close(fd);return;}
    wnad_wake();
    /* stop retains the actor wake fd until every publisher has passed here. */
    atomic_fetch_sub_explicit(&publishers,1,memory_order_release);
}
static int take_pending(void)
{
    if(atomic_flag_test_and_set_explicit(&mailbox_lock,memory_order_acquire))return -1;
    int fd=pending;pending=-1;
    atomic_flag_clear_explicit(&mailbox_lock,memory_order_release);return fd;
}
/* Native input EOF is a half close. TLS/com may still have a final reply to
 * emit; it does not close the opposite memory-BIO direction. */
static ssize_t write_bio(void *context,const void *bytes,size_t size)
{
    struct wna_channel *channel=context;
    if(channel->failed)return -1;
    size_t room=wna_buffer_space(&channel->output);if(!room)return -3;
    if(size>room)size=room;
    memcpy(channel->output.bytes+channel->output.size,bytes,size);
    channel->output.size+=size;return (ssize_t)size;
}
static void work(void *context)
{
    struct native_flow *f=context;
    if(f->disposing){
        wendy_pki_agent_dispose(f->setup);f->setup=NULL;
        wendy_pki_close(f->connection);f->connection=NULL;f->result=0;
    }else if(f->state.phase==WNA_PREPARE){
        struct wendy_pki_stream bio={.context=&f->channel,.read=wna_read,.write=write_bio,.wait=wnad_no_wait};
        esp_err_t result=wendy_pki_agent_begin(&bio,&f->setup);
        f->result=result==ESP_OK ? 0:(result==ESP_ERR_TIMEOUT || result==ESP_ERR_NO_MEM) ? 2:-1;
    }else f->result=wendy_pki_agent_step(f->setup);
    atomic_store_explicit(&f->done,true,memory_order_release);
}
static bool collect(struct native_flow *f,int64_t now)
{
    if(!f->state.lent)return true;
    if(!atomic_load_explicit(&f->done,memory_order_acquire))return false;
    if(f->disposing){f->state.lent=false;return true;}
    wna_completed(&f->state,f->result);
    if(f->result==2){f->state.retry_at=(uint64_t)now+50000;wnad_handshake_release(f);}
    return true;
}
static bool dispose(struct native_flow *f)
{
    if(!collect(f,esp_timer_get_time()))return false;
    if(!f->disposing){
        f->disposing=true;
        if(f->bridge)wnab_close(f->bridge);
        close(f->fd);f->fd=-1;
    }
    /* Source-handle close and TLS destruction are a worker effect too. Never
     * free a context from beneath a running handshake or cleanup loan. */
    if(f->setup || f->connection){
        atomic_store(&f->done,false);
        if(wendy_pki_work_submit(work,f))f->state.lent=true;
        return false;
    }
    if(f->bridge){
        if(!wnab_retired(f->bridge))return false;
        wnab_release(f->bridge);f->bridge=NULL;
    }
    wnad_handshake_release(f);wendy_net_free(f);--flow_count;return true;
}
static bool tls_ready(struct native_flow *f,int need,bool reading)
{
    if(need==-2)return f->channel.input.size || f->channel.eof ||
        (reading && wendy_pki_pending(f->connection));
    if(need==-3)return wna_buffer_space(&f->channel.output)!=0;
    return true;
}
static bool plaintext_ready(struct native_flow *f)
{
    if((f->write_size || wnap_available(wnab_outgoing(f->bridge))) && tls_ready(f,f->write_need,false))return true;
    if(wnab_closed(f->bridge))return !f->write_size && !wnap_available(wnab_outgoing(f->bridge)) && !f->channel.output.size;
    return !f->input_eof && wnap_space(wnab_incoming(f->bridge)) && tls_ready(f,f->read_need,true);
}
static int plaintext(struct native_flow *f,int64_t now)
{
    struct wnab_bridge *b=f->bridge;int progress=0;
    /* Keep the identical pointer/length across TLS WANT_WRITE/READ retries.
     * The com producer cannot overwrite this consumer span before consume. */
    if(!f->write_size)f->write_size=wnap_read_span(wnab_outgoing(b),&f->writing);
    if((f->input_eof || wnab_closed(b)) && !f->drain_deadline)f->drain_deadline=now+INT64_C(45000000);
    if(f->drain_deadline && now>=f->drain_deadline)return -1;
    if(f->write_size && tls_ready(f,f->write_need,false)){
        ssize_t n=wendy_pki_write(f->connection,f->writing,f->write_size);
        if(n>0){wnap_consume(wnab_outgoing(b),(size_t)n);f->write_size=0;f->write_need=0;wnab_notify(b);progress=1;}
        else if(n==-2 || n==-3)f->write_need=(int)n;
        else return -1;
    }
    if(wnab_closed(b)){
        /* Ordinary application completion drains accepted plaintext and its
         * final encrypted BIO bytes; explicit OFF/expiry may abort instead. */
        return !f->write_size && !wnap_available(wnab_outgoing(b)) && !f->channel.output.size ? -1:progress;
    }
    uint8_t *bytes;size_t room=wnap_write_span(wnab_incoming(b),&bytes);
    if(room && !f->input_eof && tls_ready(f,f->read_need,true)){
        ssize_t n=wendy_pki_read(f->connection,bytes,room);
        if(n>0){wnap_produce(wnab_incoming(b),(size_t)n);f->read_need=0;wnab_notify(b);progress=1;}
        else if(!n){f->input_eof=true;f->drain_deadline=now+INT64_C(45000000);wnab_input_eof(b);progress=1;}
        else if(n==-2 || n==-3)f->read_need=(int)n;
        else return -1;
    }
    return progress;
}
static int step(struct native_flow *f,int64_t now)
{
    if(!collect(f,now))return 0;
    if(!wendy_conf_is_current() || wendy_pki_reset_in_progress())return ending(f,"configuration",now);
    if(f->connection && (!wendy_conf_snapshot_current(f->info.config_generation) || now>=f->info.session_deadline_us))return ending(f,"session-expiry-or-generation",now);
    if(!f->connection && now>=(int64_t)f->state.deadline)return ending(f,"setup-deadline",now);
    int progress=wnad_channel_io(&f->channel,f->fd,NULL);if(progress<0)return ending(f,"socket-io",now);
    if(f->state.phase!=WNA_READY){
        enum wna_effect effect=wna_next(&f->state,(uint64_t)now,
            f->channel.input.size || f->channel.eof,wna_buffer_space(&f->channel.output)!=0);
        if(effect==WNA_CLOSE)return ending(f,"tls-state",now);
        if(effect==WNA_CRYPTO_PREPARE && !wnad_handshake_claim(f)){
#if WENDY_NET_NON_TRANSIT
            /* Only cancel the competing unestablished guest. Its normal actor
             * completion/disposal releases the borrowed workspace; existing
             * application I/O and unconstrained peers keep running. */
            progress|=wendy_net_app_yield_setup();
#endif
            return progress;
        }
        if(effect==WNA_CRYPTO_PREPARE || effect==WNA_CRYPTO_STEP){
            atomic_store(&f->done,false);
            if(wendy_pki_work_submit(work,f))wna_lend(&f->state);
        }
        return progress;
    }
    if(!f->connection){
        f->connection=wendy_pki_agent_take(f->setup,&f->info);
        if(!f->connection)return ending(f,"take-context",now); /* setup still belongs to cleanup worker */
        f->setup=NULL;wnad_handshake_release(f);
        enum wcom_link_permission permission=f->info.role==WENDY_PEER_ROLE_OPERATOR ? WCOM_LINK_PERMISSION_FULL:
            f->info.role==WENDY_PEER_ROLE_DEVICE ? WCOM_LINK_PERMISSION_SENSOR_ONLY:WCOM_LINK_PERMISSION_NONE;
        f->bridge=wnab_open(permission,CONFIG_WENDY_NET_TCP_RELAY_BUFFER_SIZE);
        if(!f->bridge)return ending(f,"backend-allocation",now);
        ESP_LOGI("net-native-agent","authenticated native VIP role=%u",(unsigned)f->info.role);
    }
    int result=plaintext(f,now);return result<0 ? ending(f,"plaintext-or-backend",now):progress || result;
}
int wendy_net_agent_poll(void)
{
    int progress=0,fd=take_pending();
    if(fd>=0){
        struct native_flow *f=flow_count<CONFIG_WENDY_NET_APP_MAX_FLOWS ? wendy_net_calloc(1,sizeof *f):NULL;
        if(!f)ESP_LOGD("net-native-agent","native VIP admission unavailable: live=%u limit=%u",flow_count,(unsigned)CONFIG_WENDY_NET_APP_MAX_FLOWS);
        int flags=fcntl(fd,F_GETFL,0);
        if(!f || fd>=FD_SETSIZE || flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0 ||
           native_socket_options(fd)){
            close(fd);wendy_net_free(f);
        }else{
            f->fd=fd;f->state.phase=WNA_PREPARE;
            f->state.deadline=(uint64_t)esp_timer_get_time()+UINT64_C(60000000);
            atomic_init(&f->done,false);f->next=flows;flows=f;++flow_count;
        }
        progress=1;
    }
    int64_t now=esp_timer_get_time();
    for(struct native_flow **at=&flows;*at;){
        struct native_flow *f=*at;
        int result=f->disposing ? -1:step(f,now);
        struct native_flow *next=f->next;
        if(result<0 && dispose(f)){*at=next;progress=1;}
        else{progress|=result>0;at=&f->next;}
    }
    return progress;
}
bool wendy_net_agent_stop(void)
{
    atomic_store(&accepting,false);
    bool locked=!atomic_flag_test_and_set_explicit(&mailbox_lock,memory_order_acquire);
    if(locked){int fd=pending;pending=-1;atomic_flag_clear_explicit(&mailbox_lock,memory_order_release);if(fd>=0)close(fd);}
    for(struct native_flow **at=&flows;*at;){
        struct native_flow *f=*at;
        struct native_flow *next=f->next;
        if(dispose(f))*at=next;
        else at=&f->next;
    }
    return locked && !flows && !wnab_live() && !atomic_load_explicit(&publishers,memory_order_acquire);
}
void wendy_net_agent_watch(fd_set *rd,fd_set *wr,int *maximum,int64_t *deadline)
{
    int64_t now=esp_timer_get_time();
    for(struct native_flow *f=flows;f;f=f->next){
        if(f->state.lent || f->disposing)continue;
        if(wna_buffer_space(&f->channel.input) && !f->channel.eof)FD_SET(f->fd,rd);
        if(f->channel.output.size)FD_SET(f->fd,wr);
        if(f->fd>*maximum)*maximum=f->fd;
        int64_t next=f->connection ? f->info.session_deadline_us:(int64_t)f->state.deadline;
        if(next<*deadline)*deadline=next;
        if(f->state.retry_at>(uint64_t)now && f->state.retry_at<(uint64_t)*deadline)*deadline=(int64_t)f->state.retry_at;
        if(f->drain_deadline && f->drain_deadline<*deadline)*deadline=f->drain_deadline;
        if(f->connection && plaintext_ready(f))*deadline=now;
    }
}
