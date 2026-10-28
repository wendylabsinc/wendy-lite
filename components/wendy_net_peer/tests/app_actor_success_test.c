/* Production VIP outer driver with ordinary TCP/UDP payloads and explicitly
 * delayed CPU loans. Real encryption is covered by the composed TLS fixtures. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include "../src/app.c"

struct wendy_pki_connection {struct wendy_pki_stream bio;const void *retry;size_t retry_size;bool want;};
struct wendy_pki_net_setup {wendy_pki_connection *connection;};
static int64_t clock_us=1000000;static uint64_t generation=1;
static void (*job)(void *);static void *job_arg,*gate;static bool in_job,no_memory;
static unsigned closes,completions,datagrams,sent_datagrams,discarded;
static int guest_fd=-1;static uint8_t udp_payload[513];static bool reply_pending;
int64_t esp_timer_get_time(void){return clock_us;}
bool wendy_conf_is_current(void){return true;}
bool wendy_conf_snapshot_current(uint64_t value){return value==generation;}
bool wendy_pki_reset_in_progress(void){return false;}
void wendy_conf_get_enrolled_ids(char tenant[37],char device[65]){strcpy(tenant,"2558fd76-afc7-466e-9613-6b715296a526");strcpy(device,"00000000-0000-4000-8000-000000000004");}
void wnad_wake(void){}
bool wnad_handshake_claim(void *owner){if(gate && gate!=owner)return false;gate=owner;return true;}
void wnad_handshake_release(void *owner){if(gate==owner)gate=NULL;}
bool wendy_pki_handshake_owned(void *owner){return gate==owner;}
bool wendy_pki_handshake_available(void){return !gate;}
int wnad_no_wait(void *ctx,bool writing,int64_t deadline){assert(!"CPU effect waited on I/O");return -1;}
bool wendy_pki_work_submit(void (*fn)(void *),void *arg){if(job)return false;job=fn;job_arg=arg;return true;}
static void run_job(void){if(job){void (*fn)(void *)=job;void *arg=job_arg;job=NULL;job_arg=NULL;in_job=true;fn(arg);in_job=false;}}
esp_err_t wendy_pki_net_begin(const struct wendy_pki_stream *bio,bool server,const char *expected,bool app,struct wendy_pki_net_setup **out)
{
    assert(in_job && app);if(no_memory){no_memory=false;return ESP_ERR_NO_MEM;}
    *out=wendy_net_calloc(1,sizeof **out);assert(*out);
    (*out)->connection=wendy_net_calloc(1,sizeof *(*out)->connection);assert((*out)->connection);
    (*out)->connection->bio=*bio;return ESP_OK;
}
int wendy_pki_net_step(struct wendy_pki_net_setup *op){assert(in_job);return 0;}
wendy_pki_connection *wendy_pki_net_take(struct wendy_pki_net_setup *op,struct wendy_pki_mesh_identity *identity)
{identity->config_generation=generation;wendy_pki_connection *c=op->connection;wendy_net_free(op);return c;}
void wendy_pki_close(wendy_pki_connection *c){if(c){assert(in_job);closes++;wendy_net_free(c);}}
void wendy_pki_net_dispose(struct wendy_pki_net_setup *op){if(op){assert(in_job);wendy_pki_close(op->connection);wendy_net_free(op);}}
ssize_t wendy_pki_read(void *context,void *out,size_t size)
{wendy_pki_connection *c=context;if(size>31)size=31;return c->bio.read(c->bio.context,out,size);}
ssize_t wendy_pki_write(void *context,const void *bytes,size_t size)
{
    wendy_pki_connection *c=context;
    if(c->retry){assert(bytes==c->retry && size==c->retry_size);c->retry=NULL;}
    else if(!c->want){c->retry=bytes;c->retry_size=size;c->want=true;return -3;}
    c->want=false;if(size>11)size=11;return c->bio.write(c->bio.context,bytes,size);
}
bool wendy_pki_pending(wendy_pki_connection *c){return ((struct wna_channel *)c->bio.context)->input.size!=0;}
int wnad_channel_io(struct wna_channel *c,int fd,const struct wendy_pki_stream *unused)
{
    int progress=0;if(c->output.size){size_t size=c->output.size;if(size>13)size=13;
        ssize_t n=send(fd,c->output.bytes+c->output.offset,size,MSG_DONTWAIT);
        if(n>0){wna_buffer_consume(&c->output,n);progress=1;}else assert(errno==EAGAIN || errno==EWOULDBLOCK);}
    size_t room=wna_buffer_space(&c->input);if(room>19)room=19;
    if(room && !c->eof){ssize_t n=recv(fd,c->input.bytes+c->input.size,room,MSG_DONTWAIT);
        if(n>0){c->input.size+=n;progress=1;}else if(!n)c->eof=true;else assert(errno==EAGAIN || errno==EWOULDBLOCK);}
    return progress;
}
int wnad_connected(int fd){return 1;}
int wnad_connect(const char *host,unsigned port,bool *connecting){*connecting=false;return -1;}
static void pair(int fd[2]){assert(!socketpair(AF_UNIX,SOCK_STREAM,0,fd));for(unsigned i=0;i<2;i++)assert(!fcntl(fd[i],F_SETFL,O_NONBLOCK));}
int wendy_net_guest_service_begin(uint16_t port){assert(port==28000);int fd[2];pair(fd);guest_fd=fd[1];return fd[0];}
int wendy_net_guest_service_connect(uint16_t port){return -1;}
int wendy_net_guest_datagram_connect(uint16_t port,int *owner){return -1;}
int wendy_net_guest_datagram_owner(uint16_t port){return port==28001 ? 7:-1;}
unsigned wendy_net_guest_datagram_capacity(void){return 1024;}
bool wendy_net_mesh_socket_live(int handle){return true;}
int wendy_net_mesh_connected(int handle,int fd){assert(handle>0);completions++;if(fd>=0)close(fd);return 0;}
int wendy_net_mesh_datagram_connected(int handle,unsigned maximum){return 0;}
int wendy_net_guest_datagram_deliver_owned(int owner,int *association,uint8_t **packet,size_t size,unsigned maximum,wendy_net_packet_release_fn release)
{assert(owner==7 && size==sizeof udp_payload && !memcmp(*packet,udp_payload,size));*association=9;release(*packet);*packet=NULL;datagrams++;reply_pending=true;return 1;}
int wendy_net_mesh_datagram_receive_owned(int handle,uint8_t **packet,size_t size,wendy_net_packet_release_fn release){return -1;}
int wendy_net_guest_datagram_take(int handle,uint8_t **packet,size_t *size)
{if(!reply_pending)return 0;reply_pending=false;*size=sizeof udp_payload;*packet=malloc(*size);assert(*packet);memcpy(*packet,udp_payload,*size);return 1;}
void wendy_net_guest_datagram_sent(int handle){sent_datagrams++;}
void wendy_net_guest_datagram_closed(int handle){}
void wendy_net_mesh_discard_pending_datagrams(void){discarded++;}
void wendy_net_set_mesh_connector(wendy_net_mesh_begin_fn fn){}
void wendy_net_set_mesh_resolver(wendy_net_mesh_resolve_fn fn){}
void wendy_net_set_service_catalog(wendy_net_service_fn fn){}
int wendy_net_peer_service_catalog(unsigned op,const void *in,size_t n,char *out,size_t cap){return -1;}
esp_err_t wendy_net_peer_agent_endpoint_now(const char *peer,uint8_t address[16],uint16_t *port){return ESP_ERR_NOT_FOUND;}
esp_err_t wendy_net_peer_app_endpoint_now(const char *peer,uint8_t address[16],uint16_t *port){return ESP_ERR_NOT_FOUND;}
static void tick(void){clock_us+=1000;wendy_net_app_poll();run_job();}
static int begin(bool udp)
{
    int fd[2];pair(fd);wendy_net_app_accept(fd[0]);assert(datagram_flows);
    uint8_t header[8]={'W','A','S','1'};memcpy(header,udp ? "WAU3":"WAS1",4);
    wn_put16(header+4,udp ? 28001:28000);wn_put16(header+6,1024);
    assert(send(fd[1],header,udp ? 8:6,0)==(udp ? 8:6));
    for(unsigned i=0;i<1000 && !datagram_flows->flow.negotiated;i++)tick();
    assert(datagram_flows->flow.negotiated);
    uint8_t ack[8];size_t got=0,want=udp ? 8:1;
    for(unsigned i=0;i<1000 && got<want;i++){tick();ssize_t n=recv(fd[1],ack+got,want-got,0);if(n>0)got+=n;}
    assert(got==want && (udp ? !memcmp(ack,"WUA3",4):ack[0]==1));return fd[1];
}
static void stop(void)
{
    for(unsigned i=0;i<1000;i++){if(wendy_net_app_stop()){assert(!gate && !job);return;}run_job();}
    assert(!"OFF failed to drain");
}
int main(void)
{
    assert(wendy_net_runtime_memory_open());wendy_net_memory_scope_t previous=wendy_net_runtime_scope_enter();
    no_memory=true;int remote=begin(false);assert(clock_us>=1050000); /* bounded prepare retry */
    uint8_t bytes[8192],back[8192];for(unsigned i=0;i<sizeof bytes;i++)bytes[i]=(uint8_t)(i*17);
    size_t tx=0,rx=0,reply=0,received=0;
    for(unsigned i=0;i<100000 && received<sizeof bytes;i++){
        if(tx<sizeof bytes){ssize_t n=send(remote,bytes+tx,sizeof bytes-tx,0);if(n>0)tx+=n;}
        tick();ssize_t n=recv(guest_fd,back+rx,sizeof back-rx,0);if(n>0)rx+=n;
        if(reply<rx){n=send(guest_fd,back+reply,rx-reply,0);if(n>0)reply+=n;}
        n=recv(remote,back+received,sizeof back-received,0);if(n>0)received+=n;
    }
    assert(received==sizeof bytes && !memcmp(bytes,back,sizeof bytes));
    /* An incoming setup can be loaned while established I/O keeps moving. */
    int extra[2];pair(extra);struct app_flow *pending=new_flow(extra[0],true);assert(pending);
    pending->guest_handle=21;assert(claim_flow(&outbound_flows));app_actor_add(pending);
    wendy_net_app_poll();assert(pending->state.lent && job);
    /* Keep this exact TLS context loan outstanding. The established sibling's
     * transport must still relay fresh bytes in both directions. */
    assert(send(remote,"live",4,0)==4);size_t live=0;
    for(unsigned i=0;i<1000 && live<4;i++){
        wendy_net_app_poll();ssize_t n=recv(guest_fd,back+live,4-live,0);if(n>0)live+=n;
    }
    assert(live==4 && !memcmp(back,"live",4));
    assert(send(guest_fd,"next",4,0)==4);live=0;
    for(unsigned i=0;i<1000 && live<4;i++){
        wendy_net_app_poll();ssize_t n=recv(remote,back+live,4-live,0);if(n>0)live+=n;
    }
    assert(live==4 && !memcmp(back,"next",4));
    assert(wendy_net_app_yield_setup());
    assert(!datagram_flows->next->flow.state.cancel); /* established TCP survived */
    assert(!wendy_net_app_stop());assert(job && pending->state.lent);assert(closes==0);
    run_job();stop();
    close(extra[1]);close(remote);close(guest_fd);guest_fd=-1;
    remote=begin(true);for(unsigned i=0;i<sizeof udp_payload;i++)udp_payload[i]=(uint8_t)(i*31);
    uint8_t wire[515],reply_bytes[515];wn_put16(wire,sizeof udp_payload);memcpy(wire+2,udp_payload,sizeof udp_payload);
    assert(send(remote,wire,sizeof wire,0)==sizeof wire);received=0;
    for(unsigned i=0;i<100000 && received<sizeof wire;i++){tick();ssize_t n=recv(remote,reply_bytes+received,sizeof wire-received,0);if(n>0)received+=n;}
    assert(received==sizeof wire && !memcmp(wire,reply_bytes,sizeof wire));assert(datagrams==1 && sent_datagrams==1);
    stop();close(remote);assert(closes==3 && completions==1 && discarded>=2);
    remote=begin(false);generation++;wendy_net_app_poll();
    assert(datagram_flows && datagram_flows->flow.disposing && job);
    run_job();stop();close(remote);close(guest_fd);assert(closes==4);
    wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);assert(!memory.current_bytes);
    wendy_net_memory_scope_leave(previous);wendy_net_runtime_memory_close();assert(wendy_net_runtime_memory_drained());
    puts("actor TCP/UDP exact payloads, retained TLS writes, setup pressure/cancellation and OFF drainage PASS");return 0;
}
