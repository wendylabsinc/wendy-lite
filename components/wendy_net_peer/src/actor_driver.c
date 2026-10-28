#include "actor_driver.h"
#include "wake_lifetime.h"
#include "wendy_pki_work.h"
#include "lwip/sockets.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdatomic.h>
#include <netdb.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include "esp_vfs_eventfd.h"
#include "esp_vfs.h"
#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#else
#include <sched.h>
#endif
#if CONFIG_WENDY_NET_TEST_ACTOR_READINESS
static struct {atomic_uint rx_bytes,tx_bytes,rx_calls,tx_calls,rx_blocked,tx_blocked;} io_probe;
void wnad_io_probe_take(struct wnad_io_probe *out)
{
    if(!out)return;
    *out=(struct wnad_io_probe){.rx_bytes=atomic_exchange(&io_probe.rx_bytes,0),.tx_bytes=atomic_exchange(&io_probe.tx_bytes,0),
        .rx_calls=atomic_exchange(&io_probe.rx_calls,0),.tx_calls=atomic_exchange(&io_probe.tx_calls,0),
        .rx_blocked=atomic_exchange(&io_probe.rx_blocked,0),.tx_blocked=atomic_exchange(&io_probe.tx_blocked,0)};
}
#define IOPROBE(key,n) ((void)atomic_fetch_add(&io_probe.key,(unsigned)(n)))
#else
#define IOPROBE(key,n) ((void)0)
#endif
static struct wnad_wake_lifetime wake_socket={.descriptor=-1};
static atomic_uint_fast64_t io_during_crypto;
uint64_t wnad_io_during_crypto(void){return atomic_load(&io_during_crypto);}
void wnad_wake(void)
{
    int fd=wnad_wake_borrow(&wake_socket);
    if(fd>=0){uint64_t one=1;(void)write(fd,&one,sizeof one);}
    wnad_wake_return(&wake_socket);
}
int wnad_wake_fd(void){return atomic_load(&wake_socket.descriptor);}
void wnad_drain_wake(void)
{uint64_t value;(void)read(wnad_wake_fd(),&value,sizeof value);}
int wnad_start(void)
{
    if(atomic_load(&wake_socket.descriptor)>=0)return 0;
    esp_vfs_eventfd_config_t config={.max_fds=1};
    esp_err_t r=esp_vfs_eventfd_register(&config);
    if(r!=ESP_OK && r!=ESP_ERR_INVALID_STATE)return -1;
    int fd=eventfd(0,0);if(fd<0)return -1;
    atomic_store(&wake_socket.descriptor,fd);
    wendy_pki_work_bind_actor();
    if(!wendy_pki_work_start(wnad_wake)){wnad_stop();return -1;}
    return 0;
}
void wnad_stop(void)
{
    int fd=wnad_wake_detach(&wake_socket);
    /* Shutdown is already an outer drain: no producer can retain the old
     * descriptor after this counter reaches zero. Yield so a lower-priority
     * completion preempted between load/write can finish. */
    while(!wnad_wake_drained(&wake_socket)){
#ifdef ESP_PLATFORM
        vTaskDelay(1);
#else
        sched_yield();
#endif
    }
    if(fd>=0)close(fd);
    /* eventfd VFS is shared with WendyCom, BLE management and guest sockets. */
}
int wnad_no_wait(void *context,bool writing,int64_t deadline)
{(void)context;(void)writing;(void)deadline;return -1;}
int wnad_channel_io(struct wna_channel *c,int fd,const struct wendy_pki_stream *stream)
{
    if(c->failed)return -1;
    int progress=0;ssize_t n;
    struct wendy_pki_work_metrics work;wendy_pki_work_metrics(&work);
    if(c->output.size){
        IOPROBE(tx_calls,1);
        n=stream ? stream->write(stream->context,c->output.bytes+c->output.offset,c->output.size):
            send(fd,c->output.bytes+c->output.offset,c->output.size,MSG_DONTWAIT);
        if(n>0){IOPROBE(tx_bytes,n);if(work.running)atomic_fetch_add(&io_during_crypto,(uint64_t)n);wna_buffer_consume(&c->output,(size_t)n);progress=1;}
        else if(stream ? (n!=-2 && n!=-3):(!n || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR && errno!=ENOBUFS && errno!=ENOMEM))){c->failed=true;return -1;}
        else IOPROBE(tx_blocked,1);
    }
    size_t room=wna_buffer_space(&c->input);
    if(room && !c->eof){
        IOPROBE(rx_calls,1);
        n=stream ? stream->read(stream->context,c->input.bytes+c->input.size,room):
            recv(fd,c->input.bytes+c->input.size,room,MSG_DONTWAIT);
        if(n>0){IOPROBE(rx_bytes,n);if(work.running)atomic_fetch_add(&io_during_crypto,(uint64_t)n);c->input.size+=(size_t)n;progress=1;}
        else if(!n){c->eof=true;progress=1;}
        else if(stream ? (n!=-2 && n!=-3):(errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)){c->failed=true;return -1;}
        else IOPROBE(rx_blocked,1);
    }
    return progress;
}
int wnad_connect(const char *host,unsigned port,bool *connecting)
{
    char service[6];snprintf(service,sizeof service,"%u",port);
    struct addrinfo hints={.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM,.ai_flags=AI_NUMERICHOST},*address=NULL;
    if(getaddrinfo(host,service,&hints,&address))return -1;
    int fd=socket(address->ai_family,SOCK_STREAM,0);
    if(fd<0){freeaddrinfo(address);return -1;}
    int yes=1;
    if(fd>=FD_SETSIZE || fcntl(fd,F_SETFL,O_NONBLOCK)<0 ||
       setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&yes,sizeof yes)){close(fd);freeaddrinfo(address);return -1;}
    int r=connect(fd,address->ai_addr,address->ai_addrlen);freeaddrinfo(address);
    if(r && errno!=EINPROGRESS){close(fd);return -1;}
    *connecting=r!=0;return fd;
}
int wnad_connected(int fd)
{
    fd_set wr;FD_ZERO(&wr);FD_SET(fd,&wr);struct timeval zero={0};
    int r=select(fd+1,NULL,&wr,NULL,&zero);if(r<=0)return r;
    int error=0;socklen_t size=sizeof error;
    return getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size) || error ? -1:1;
}
bool wnad_handshake_claim(void *owner){return wendy_pki_handshake_claim(owner);}
void wnad_handshake_release(void *owner){wendy_pki_handshake_release(owner);wnad_wake();}
