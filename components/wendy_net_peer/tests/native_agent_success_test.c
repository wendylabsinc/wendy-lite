/* Ordinary actor/com lifetime and bounded plaintext pressure. Actual PQC TLS
 * interoperability is separately exercised by pki_native_agent_actor_* cases. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sched.h>
#include <poll.h>
#include "wendy_net_alloc.h"
#include "../src/native_agent.c"

static int64_t now=1000000;
static bool current=true,prepare_busy,immediate_close,slots_full,transmit_blocked;
static uint64_t generation=1;
static void (*cpu_callback)(void *);
static void *cpu_argument,*gate_owner;
static unsigned actor_wakes,com_wakes,removed,steps,closed,reply_completed;
static void reply_complete(uint32_t token){assert(token==41 || token==42);reply_completed++;}
static struct wcom_operation *operations_first,*operations_last;
static const struct wcom_stream_ops *com_ops;
static void *com_context;
static wcom_interruption_handler_t interruption;
static int com_id=-1,next_id=4;
static enum wcom_link_permission expected_permission=WCOM_LINK_PERMISSION_FULL;
struct wendy_pki_connection {struct wendy_pki_stream bio;};
struct wendy_pki_agent_setup {struct wendy_pki_connection *connection;unsigned steps;uint64_t generation;};
int64_t esp_timer_get_time(void){return now;}
bool wendy_conf_is_current(void){return current;}
bool wendy_conf_snapshot_current(uint64_t value){return current && value==generation;}
bool wendy_pki_reset_in_progress(void){return false;}
void wnad_wake(void){actor_wakes++;}
bool wnad_handshake_claim(void *owner){if(gate_owner && gate_owner!=owner)return false;gate_owner=owner;return true;}
void wnad_handshake_release(void *owner){if(gate_owner==owner)gate_owner=NULL;}
int wnad_no_wait(void *ctx,bool writing,int64_t deadline){(void)ctx;(void)writing;(void)deadline;assert(0);return -1;}
bool wendy_pki_work_submit(void (*fn)(void *),void *context)
{if(cpu_callback)return false;cpu_callback=fn;cpu_argument=context;return true;}
static void finish_cpu(void)
{assert(cpu_callback);void (*fn)(void *)=cpu_callback;void *arg=cpu_argument;cpu_callback=NULL;cpu_argument=NULL;fn(arg);}
esp_err_t wendy_pki_agent_begin(const struct wendy_pki_stream *bio,struct wendy_pki_agent_setup **out)
{
    if(prepare_busy)return ESP_ERR_TIMEOUT;
    struct wendy_pki_agent_setup *op=wendy_net_calloc(1,sizeof *op);assert(op);
    op->connection=wendy_net_calloc(1,sizeof *op->connection);assert(op->connection);
    op->connection->bio=*bio;op->generation=generation;*out=op;return ESP_OK;
}
int wendy_pki_agent_step(struct wendy_pki_agent_setup *op)
{steps++;return ++op->steps<3 ? 1:0;}
wendy_pki_connection *wendy_pki_agent_take(struct wendy_pki_agent_setup *op,struct wendy_pki_agent_info *info)
{
    assert(op && op->steps==3);
    if(op->generation!=generation)return NULL;
    *info=(struct wendy_pki_agent_info){.role=expected_permission==WCOM_LINK_PERMISSION_FULL ? WENDY_PEER_ROLE_OPERATOR:WENDY_PEER_ROLE_DEVICE,
        .config_generation=generation,.session_deadline_us=now+100000000};
    struct wendy_pki_connection *connection=op->connection;wendy_net_free(op);return connection;
}
void wendy_pki_close(wendy_pki_connection *connection){if(connection){closed++;wendy_net_free(connection);}}
void wendy_pki_agent_dispose(struct wendy_pki_agent_setup *op)
{if(op){wendy_pki_close(op->connection);wendy_net_free(op);}}
ssize_t wendy_pki_read(void *connection,void *bytes,size_t size)
{struct wendy_pki_connection *c=connection;return c->bio.read(c->bio.context,bytes,size);}
ssize_t wendy_pki_write(void *connection,const void *bytes,size_t size)
{struct wendy_pki_connection *c=connection;return c->bio.write(c->bio.context,bytes,size);}
bool wendy_pki_pending(wendy_pki_connection *connection)
{struct wna_channel *channel=connection->bio.context;return channel->input.size!=0;}
int wnad_channel_io(struct wna_channel *channel,int fd,const struct wendy_pki_stream *stream)
{
    (void)stream;int progress=0;
    if(channel->output.size && !transmit_blocked){ssize_t n=send(fd,channel->output.bytes+channel->output.offset,channel->output.size,0);
        if(n>0){wna_buffer_consume(&channel->output,(size_t)n);progress=1;}
        else assert(errno==EAGAIN || errno==EWOULDBLOCK);}
    size_t room=wna_buffer_space(&channel->input);
    if(room && !channel->eof){ssize_t n=recv(fd,channel->input.bytes+channel->input.size,room,0);
        if(n>0){channel->input.size+=(size_t)n;progress=1;}
        else if(!n){channel->eof=true;progress=1;}
        else assert(errno==EAGAIN || errno==EWOULDBLOCK);}
    return progress;
}
int wcom_core_wakeup_fd(void){return 0;}
void wcom_core_wake(void){com_wakes++;}
void wcom_core_exec(struct wcom_operation *operation)
{
    operation->next=NULL;
    if(operations_last)operations_last->next=operation;else operations_first=operation;
    operations_last=operation;
}
static void finish_com(void)
{
    while(operations_first){struct wcom_operation *op=operations_first;operations_first=op->next;
        if(!operations_first)operations_last=NULL;
        op->func(op);}
}
int wcom_add_routed_stream_link_with_permission(const struct wcom_stream_ops *ops,void *context,
    wcom_interruption_handler_t callback,enum wcom_link_permission permission)
{
    assert(permission==expected_permission);
    if(slots_full)return -1;
    assert(com_id<0);com_id=++next_id;com_ops=ops;com_context=context;interruption=callback;
    int result=com_id;
    if(immediate_close)callback(com_id,WCOM_INTERRUPTION_CONNECTION_CLOSED);
    return result;
}
void wcom_remove_link(int id){assert(id==com_id);removed++;com_id=-1;com_context=NULL;com_ops=NULL;}
void wcom_close(int id){assert(id==com_id);interruption(id,WCOM_INTERRUPTION_CONNECTION_CLOSED);}
static size_t used(void){wendy_net_memory_snapshot_t s;wendy_net_runtime_memory_snapshot(&s);return s.current_bytes;}
static void socket_pair(int fds[2])
{
    int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!bind(listener,(struct sockaddr *)&address,sizeof address));assert(!listen(listener,1));
    socklen_t size=sizeof address;assert(!getsockname(listener,(struct sockaddr *)&address,&size));
    fds[1]=socket(AF_INET,SOCK_STREAM,0);assert(fds[1]>=0);
    assert(!connect(fds[1],(struct sockaddr *)&address,sizeof address));fds[0]=accept(listener,NULL,NULL);assert(fds[0]>=0);close(listener);
    for(unsigned i=0;i<2;i++){
        assert(!fcntl(fds[i],F_SETFL,O_NONBLOCK));int yes=1;
        assert(!setsockopt(fds[i],IPPROTO_TCP,TCP_NODELAY,&yes,sizeof yes));
    }
}
static int begin(void)
{
    int fds[2];socket_pair(fds);wendy_net_agent_start();wendy_net_agent_accept(fds[0]);wendy_net_agent_poll();
    assert(flows && flows->state.lent && cpu_callback);return fds[1];
}
static void handshake(void)
{
    for(unsigned count=0;count<12 && (!flows->connection);count++){
        if(cpu_callback)finish_cpu();
        wendy_net_agent_poll();
    }
    assert(flows && flows->connection && flows->bridge && !flows->state.lent);
}
static void stop(void)
{
    for(unsigned count=0;count<20;count++){
        bool done=wendy_net_agent_stop();
        if(done){assert(!gate_owner && !flows && !wnab_live() && !used());return;}
        if(cpu_callback)finish_cpu();
        finish_com();
    }
    assert(0);
}
static void wrap_ring(unsigned capacity)
{
    uint8_t *storage=malloc(capacity+1),*out=malloc(capacity),*source=malloc(capacity);
    for(unsigned i=0;i<capacity;i++)source[i]=(uint8_t)i;
    struct wnap_ring ring;wnap_init(&ring,storage,capacity);
    for(unsigned pass=0;pass<10;pass++){
        assert(wnap_write(&ring,source,capacity)==capacity);assert(!wnap_space(&ring));
        unsigned cut=capacity/3;assert(wnap_read(&ring,out,cut)==cut);assert(!memcmp(out,source,cut));
        assert(wnap_write(&ring,source,cut)==cut);
        assert(wnap_read(&ring,out,capacity)==capacity);
        assert(!memcmp(out,source+cut,capacity-cut));assert(!memcmp(out+capacity-cut,source,cut));
        assert(!wnap_available(&ring));
    }
    free(storage);free(out);free(source);
}
struct concurrent_pipe {struct wnap_ring ring;uint8_t bytes[769];};
static void *produce_thread(void *context)
{
    struct concurrent_pipe *pipe=context;
    for(unsigned i=0;i<200000;i++){
        uint8_t value=(uint8_t)i;
        while(!wnap_write(&pipe->ring,&value,1))sched_yield();
    }
    return NULL;
}
static void concurrent_ring(void)
{
    struct concurrent_pipe pipe;wnap_init(&pipe.ring,pipe.bytes,768);
    pthread_t producer;assert(!pthread_create(&producer,NULL,produce_thread,&pipe));
    for(unsigned i=0;i<200000;i++){
        uint8_t value;
        while(!wnap_read(&pipe.ring,&value,1))sched_yield();
        assert(value==(uint8_t)i);
    }
    assert(!pthread_join(producer,NULL));assert(!wnap_available(&pipe.ring));
}
int main(void)
{
    wrap_ring(256);wrap_ring(768);wrap_ring(1024);concurrent_ring();
    int fds[2];socket_pair(fds);wendy_net_agent_accept(fds[0]);assert(fcntl(fds[0],F_GETFD)<0 && errno==EBADF);close(fds[1]);
    assert(wendy_net_runtime_memory_open());wendy_net_memory_scope_t previous=wendy_net_runtime_scope_enter();
    struct wnab_bridge *fence=wnab_open(WCOM_LINK_PERMISSION_FULL,256);assert(fence);finish_com();
    com_ops->reply_barrier(com_context,41,reply_complete);
    uint32_t sampled=wnab_output_receipt(fence);
    com_ops->reply_barrier(com_context,42,reply_complete);
    assert(reply_completed==1); /* superseded receipt retired without a second slot */
    wnab_output_drained(fence,sampled);assert(reply_completed==1);
    wnab_output_drained(fence,wnab_output_receipt(fence));assert(reply_completed==2);
    wnab_close(fence);finish_com();assert(wnab_retired(fence));wnab_release(fence);
    reply_completed=0;
    int client=begin();
    assert(send(client,"loan",4,0)==4);wendy_net_agent_poll();
    assert(!flows->channel.input.size); /* main cannot touch a lent BIO */
    size_t before=used();assert(!wendy_net_agent_stop());assert(used()==before);
    finish_cpu();stop();assert(!used());close(client);
    /* OFF before the com add acknowledgement: queued nodes keep their leases. */
    client=begin();handshake();assert(wnab_live()==1);assert(!wendy_net_agent_stop());
    assert(wnab_live()==1 && used());
    wendy_net_runtime_memory_close();assert(!wendy_net_runtime_memory_drained());
    finish_com();stop();assert(wendy_net_runtime_memory_drained());
    assert(wendy_net_runtime_memory_open());assert(!used());close(client);
    for(unsigned permission=0;permission<2;permission++){
        expected_permission=permission ? WCOM_LINK_PERMISSION_SENSOR_ONLY:WCOM_LINK_PERMISSION_FULL;
        client=begin();handshake();finish_com();assert(com_id>=0);
        wendy_net_memory_scope_t baseline=wendy_net_memory_scope_enter(NULL,WENDY_NET_MEMORY_INTERNAL);
        size_t before_body=used();void *body=com_ops->allocate_buffer(com_context,2048);assert(body);
        size_t body_live=used();assert(body_live>before_body+2048);
        assert(!wendy_net_memory_scope_current().owner); /* allocation owner restored */
        wendy_net_memory_scope_leave(baseline);
        /* Bounded full-duplex plaintext pressure, partial application read/write,
         * exactly matching the provider used by real WendyCom HELLO fixtures. */
        uint8_t sent[16384],received[16384],echo[73];size_t tx=0,rx=0,have=0,offset=0;
        for(unsigned i=0;i<sizeof sent;i++)sent[i]=(uint8_t)(i*17);
        for(unsigned count=0;count<100000 && rx<sizeof sent;count++){
            if(tx<sizeof sent){ssize_t n=send(client,sent+tx,sizeof sent-tx,0);if(n>0)tx+=(size_t)n;else assert(errno==EAGAIN || errno==EWOULDBLOCK);}
            wendy_net_agent_poll();
            if(offset==have){ssize_t n=com_ops->read(com_context,echo,sizeof echo);if(n>0){offset=0;have=(size_t)n;}else assert(n==-2);}
            if(offset<have){ssize_t n=com_ops->write(com_context,echo+offset,have-offset);if(n>0)offset+=(size_t)n;else assert(n==-3);}
            ssize_t n=recv(client,received+rx,sizeof received-rx,0);if(n>0)rx+=(size_t)n;else assert(errno==EAGAIN || errno==EWOULDBLOCK);
        }
        assert(rx==sizeof sent && tx==sizeof sent && !memcmp(sent,received,sizeof sent));
        assert(used()==body_live);com_ops->free_buffer(com_context,body);
        /* Application completion must drain already accepted encrypted bytes. */
        assert(com_ops->write(com_context,"tail",4)==4);wcom_close(com_id);
        char tail[4];size_t got=0;
        for(unsigned i=0;i<1000 && got<4;i++){
            wendy_net_agent_poll();ssize_t n=recv(client,tail+got,4-got,0);
            if(n>0)got+=(size_t)n;
            else{struct pollfd wait={.fd=client,.events=POLLIN};(void)poll(&wait,1,1);}
        }
        assert(got==4 && !memcmp(tail,"tail",4));stop();close(client);
    }
    /* A full socket/BIO plus queued com output sleeps for writable readiness,
     * including after application close; it must not spin on nonempty rings. */
    expected_permission=WCOM_LINK_PERMISSION_FULL;
    client=begin();handshake();finish_com();transmit_blocked=true;
    uint8_t pressure[768],pressure_reply[768];
    for(unsigned i=0;i<sizeof pressure;i++)pressure[i]=(uint8_t)i;
    size_t pressure_sent=0;
    for(unsigned i=0;i<1000 && pressure_sent<sizeof pressure;i++){
        ssize_t n=com_ops->write(com_context,pressure+pressure_sent,sizeof pressure-pressure_sent);
        if(n>0)pressure_sent+=(size_t)n;else assert(n==-3);
        wendy_net_agent_poll();
    }
    for(unsigned i=0;i<10 && flows->write_need!=-3;i++)wendy_net_agent_poll();
    assert(pressure_sent==sizeof pressure && flows->write_need==-3 && flows->channel.output.size==512 && flows->write_size);
    fd_set reading,writing;FD_ZERO(&reading);FD_ZERO(&writing);int maximum=-1;int64_t deadline=now+1000000;
    wendy_net_agent_watch(&reading,&writing,&maximum,&deadline);
    assert(deadline>now && FD_ISSET(flows->fd,&writing));
    com_ops->reply_barrier(com_context,42,reply_complete);
    for(unsigned i=0;i<5;i++)wendy_net_agent_poll();
    assert(!reply_completed); /* ring and TLS BIO still contain the response */
    wcom_close(com_id);deadline=now+1000000;
    wendy_net_agent_watch(&reading,&writing,&maximum,&deadline);assert(deadline>now);
    transmit_blocked=false;size_t pressure_got=0;
    for(unsigned i=0;i<10000 && pressure_got<sizeof pressure;i++){
        wendy_net_agent_poll();ssize_t n=recv(client,pressure_reply+pressure_got,sizeof pressure-pressure_got,0);
        if(n>0)pressure_got+=(size_t)n;else assert(errno==EAGAIN || errno==EWOULDBLOCK);
    }
    assert(pressure_got==sizeof pressure && !memcmp(pressure,pressure_reply,sizeof pressure));
    assert(reply_completed==1);
    /* A delayed com close ACK keeps the slot: repeated ordinary reconnects
     * cannot build orphan bridges while application work occupies com. */
    wendy_net_agent_poll();assert(flows && flows->disposing && wnab_live()==1);
    if(cpu_callback)finish_cpu();
    wendy_net_agent_poll();
    size_t closing_used=used();
    for(unsigned i=0;i<8;i++){
        int rejected[2];socket_pair(rejected);wendy_net_agent_accept(rejected[0]);wendy_net_agent_poll();
        assert(flow_count==1 && wnab_live()==1 && used()==closing_used);close(rejected[1]);
    }
    stop();close(client);
    /* Ordinary input half close delivers buffered input and EOF to com while
     * preserving the reverse direction until its accepted final reply drains. */
    client=begin();handshake();finish_com();assert(send(client,"last",4,0)==4);assert(!shutdown(client,SHUT_WR));
    uint8_t last[4];size_t last_used=0;bool eof=false;
    for(unsigned i=0;i<10000 && !eof;i++){
        wendy_net_agent_poll();ssize_t n=com_ops->read(com_context,last+last_used,4-last_used);
        if(n>0)last_used+=(size_t)n;else if(!n)eof=true;else assert(n==-2);
        if(last_used==4 && flows->input_eof)eof=true;
    }
    assert(last_used==4 && !memcmp(last,"last",4) && flows->input_eof);
    assert(com_ops->write(com_context,"done",4)==4);wcom_close(com_id);
    size_t final_used=0;
    for(unsigned i=0;i<10000 && final_used<4;i++){
        wendy_net_agent_poll();ssize_t n=recv(client,last+final_used,4-final_used,0);if(n>0)final_used+=(size_t)n;
        else assert(errno==EAGAIN || errno==EWOULDBLOCK);
    }
    assert(final_used==4 && !memcmp(last,"done",4));stop();close(client);
    /* Ordinary protocol-buffer admission can close synchronously in CONNECTED. */
    expected_permission=WCOM_LINK_PERMISSION_FULL;immediate_close=true;
    client=begin();handshake();finish_com();assert(com_id<0);wendy_net_agent_poll();stop();close(client);immediate_close=false;
    slots_full=true;client=begin();handshake();finish_com();wendy_net_agent_poll();stop();close(client);slots_full=false;
    /* The generation can turn after worker completion but before READY/take.
     * A refused take retains its opaque setup for the cleanup worker. */
    client=begin();
    for(unsigned i=0;i<8 && (!flows->setup || flows->setup->steps<2);i++){
        assert(cpu_callback);finish_cpu();wendy_net_agent_poll();
    }
    assert(cpu_callback && flows->setup->steps==2);finish_cpu();generation++;
    wendy_net_agent_poll();assert(flows && flows->disposing && flows->setup && cpu_callback);
    stop();close(client);
    /* Clock/identity busy is transient preparation pressure, not a failed loan. */
    prepare_busy=true;client=begin();finish_cpu();wendy_net_agent_poll();assert(!gate_owner && !flows->state.lent);
    now+=50001;prepare_busy=false;wendy_net_agent_poll();handshake();finish_com();generation++;wendy_net_agent_poll();stop();close(client);
    assert(actor_wakes && com_wakes && removed>=3 && steps>=12 && closed>=6);
    wendy_net_memory_scope_leave(previous);wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
    printf("native actor: bounded duplex, roles, late CPU/com ACK, admission, epoch and OFF drain PASS\n");
}
