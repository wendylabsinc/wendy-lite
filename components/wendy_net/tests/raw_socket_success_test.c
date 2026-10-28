/* Ordinary IPv6 traffic, timeout, close/reset and guest-stop unwinding. */
#include "wendy_net_raw.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static atomic_bool stop;
static bool stopping(void){return atomic_load(&stop);}
static int64_t now(void)
{struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (int64_t)t.tv_sec*1000000+t.tv_nsec/1000;}
static struct sockaddr_in6 bound(int fd)
{
    struct sockaddr_in6 a={.sin6_family=AF_INET6,.sin6_addr=IN6ADDR_LOOPBACK_INIT};
    assert(!bind(fd,(struct sockaddr *)&a,sizeof a));
    socklen_t n=sizeof a;assert(!getsockname(fd,(struct sockaddr *)&a,&n));return a;
}
static void *request_stop(void *unused)
{
    (void)unused;struct timespec delay={.tv_nsec=50000000};nanosleep(&delay,NULL);
    atomic_store(&stop,true);return NULL;
}
int main(void)
{
    struct wn_raw_socket slots[4]={0};
    struct wn_raw_set set={slots,4,stopping,now};
    int client=wn_raw_socket(&set,AF_INET6,SOCK_DGRAM,0);
    int server=wn_raw_socket(&set,AF_INET6,SOCK_DGRAM,0);
    assert(client>=0 && server>=0);
    struct sockaddr_in6 ca=bound(client),sa=bound(server);
    assert(!wn_raw_connect(&set,client,(struct sockaddr *)&sa,sizeof sa));
    assert(!wn_raw_connect(&set,server,(struct sockaddr *)&ca,sizeof ca));
    assert(!wn_raw_timeout(&set,server,1000));
    unsigned char sent[4096],received[4096];
    for(unsigned i=0;i<sizeof sent;i++)sent[i]=(unsigned char)(i*31+7);
    assert(wn_raw_send(&set,client,sent,0)==0);
    assert(wn_raw_recv(&set,server,received,sizeof received)==0);
    assert(wn_raw_send(&set,client,sent,sizeof sent)==sizeof sent);
    assert(wn_raw_recv(&set,server,received,sizeof received)==sizeof received);
    assert(!memcmp(sent,received,sizeof sent));
    wn_raw_reset(&set);assert(fcntl(client,F_GETFD)<0 && errno==EBADF);
    assert(fcntl(server,F_GETFD)<0 && errno==EBADF);

    int listener=wn_raw_socket(&set,AF_INET6,SOCK_STREAM,0);assert(listener>=0);
    sa=bound(listener);assert(!listen(listener,1));
    client=wn_raw_socket(&set,AF_INET6,SOCK_STREAM,0);assert(client>=0);
    assert(!wn_raw_timeout(&set,client,1000));
    assert(!wn_raw_connect(&set,client,(struct sockaddr *)&sa,sizeof sa));
    server=wn_raw_accept(&set,listener);assert(server>=0);
    assert(wn_raw_send(&set,client,sent,sizeof sent)==sizeof sent);
    size_t used=0;
    while(used<sizeof received){ssize_t n=wn_raw_recv(&set,server,received+used,sizeof received-used);assert(n>0);used+=(size_t)n;}
    assert(!memcmp(sent,received,sizeof sent));
    assert(!wn_raw_timeout(&set,server,10));
    assert(wn_raw_recv(&set,server,received,1)==-1 && errno==EAGAIN);
    assert(!wn_raw_nonblocking(&set,server,true));
    assert(wn_raw_recv(&set,server,received,1)==-1 && errno==EAGAIN);
    assert(!wn_raw_close(&set,listener));wn_raw_reset(&set);

    server=wn_raw_socket(&set,AF_INET6,SOCK_DGRAM,0);assert(server>=0);(void)bound(server);
    pthread_t thread;assert(!pthread_create(&thread,NULL,request_stop,NULL));
    int64_t started=now();assert(wn_raw_recv(&set,server,received,sizeof received)==-1 && errno==ECANCELED);
    assert(now()-started<500000);assert(!pthread_join(thread,NULL));
    wn_raw_reset(&set);assert(fcntl(server,F_GETFD)<0 && errno==EBADF);
    for(unsigned i=0;i<4;i++)assert(!slots[i].used);
    puts("Normal raw IPv6 TCP/UDP, timeout, reset and stop passed");return 0;
}
