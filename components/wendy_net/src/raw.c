#include "wendy_net_raw.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>

static struct wn_raw_socket *find(struct wn_raw_set *set,int fd)
{
    for(size_t i=0;i<set->capacity;i++)
        if(set->sockets[i].used && set->sockets[i].fd==fd)return &set->sockets[i];
    errno=EBADF;return NULL;
}
static bool stopping(struct wn_raw_set *set)
{
    if(set->stopping && set->stopping()){errno=ECANCELED;return true;}
    return false;
}
static int adopt(struct wn_raw_set *set,int fd,bool nonblocking,unsigned timeout)
{
    if(fd<0)return -1;
    if(fd>=FD_SETSIZE){close(fd);errno=EMFILE;return -1;}
    int flags=fcntl(fd,F_GETFL,0);
    if(flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0){int error=errno;close(fd);errno=error;return -1;}
    for(size_t i=0;i<set->capacity;i++)if(!set->sockets[i].used){
        set->sockets[i]=(struct wn_raw_socket){fd,true,nonblocking,timeout};return fd;
    }
    close(fd);errno=EMFILE;return -1;
}
int wn_raw_socket(struct wn_raw_set *set,int domain,int type,int protocol)
{
    if(stopping(set))return -1;
    return adopt(set,socket(domain,type,protocol),false,0);
}
bool wn_raw_owned(struct wn_raw_set *set,int fd){return find(set,fd)!=NULL;}
int wn_raw_nonblocking(struct wn_raw_set *set,int fd,bool enabled)
{
    struct wn_raw_socket *s=find(set,fd);if(!s)return -1;
    s->nonblocking=enabled;return 0;
}
int wn_raw_timeout(struct wn_raw_set *set,int fd,unsigned milliseconds)
{
    struct wn_raw_socket *s=find(set,fd);if(!s)return -1;
    s->timeout_ms=milliseconds;return 0;
}
static int64_t deadline(struct wn_raw_set *set,const struct wn_raw_socket *s)
{return s->timeout_ms ? set->now_us()+(int64_t)s->timeout_ms*1000:0;}
static bool retry(void){return errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR;}
static int wait_ready(struct wn_raw_set *set,struct wn_raw_socket *s,bool write,int64_t end)
{
    for(;;){
        if(stopping(set))return -1;
        if(s->nonblocking){errno=EAGAIN;return -1;}
        int64_t left=end ? end-set->now_us():25000;
        if(left<=0){errno=EAGAIN;return -1;}
        if(left>25000)left=25000;
        struct timeval timeout={.tv_sec=0,.tv_usec=(long)left};
        fd_set ready;FD_ZERO(&ready);FD_SET(s->fd,&ready);
        int n=select(s->fd+1,write ? NULL:&ready,write ? &ready:NULL,NULL,&timeout);
        if(n>0)return 0;
        if(n<0 && errno!=EINTR)return -1;
    }
}
int wn_raw_connect(struct wn_raw_set *set,int fd,const struct sockaddr *address,socklen_t size)
{
    struct wn_raw_socket *s=find(set,fd);if(!s || stopping(set))return -1;
    int n=connect(fd,address,size);
    if(!n || (errno!=EINPROGRESS && errno!=EALREADY && !retry()))return n;
    if(s->nonblocking)return -1; /* Preserve EINPROGRESS for ordinary polling. */
    if(wait_ready(set,s,true,deadline(set,s)))return -1;
    int error=0;socklen_t bytes=sizeof error;
    if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&bytes))return -1;
    if(error){errno=error;return -1;}return 0;
}
int wn_raw_accept(struct wn_raw_set *set,int fd)
{
    struct wn_raw_socket *s=find(set,fd);if(!s)return -1;
    int64_t end=deadline(set,s);
    for(;;){
        if(stopping(set))return -1;
        int accepted=accept(fd,NULL,NULL);
        if(accepted>=0)return adopt(set,accepted,s->nonblocking,s->timeout_ms);
        if(!retry() || wait_ready(set,s,false,end))return -1;
    }
}
ssize_t wn_raw_send(struct wn_raw_set *set,int fd,const void *data,size_t size)
{
    struct wn_raw_socket *s=find(set,fd);if(!s)return -1;
    int64_t end=deadline(set,s);
    for(;;){
        if(stopping(set))return -1;
        ssize_t n=send(fd,data,size,0);
        if(n>=0 || !retry())return n;
        if(wait_ready(set,s,true,end))return -1;
    }
}
ssize_t wn_raw_recv(struct wn_raw_set *set,int fd,void *data,size_t size)
{
    struct wn_raw_socket *s=find(set,fd);if(!s)return -1;
    int64_t end=deadline(set,s);
    for(;;){
        if(stopping(set))return -1;
        ssize_t n=recv(fd,data,size,0);
        if(n>=0 || !retry())return n;
        if(wait_ready(set,s,false,end))return -1;
    }
}
int wn_raw_close(struct wn_raw_set *set,int fd)
{
    struct wn_raw_socket *s=find(set,fd);if(!s)return -1;
    memset(s,0,sizeof *s);return close(fd);
}
void wn_raw_reset(struct wn_raw_set *set)
{
    for(size_t i=0;i<set->capacity;i++)if(set->sockets[i].used)
        (void)wn_raw_close(set,set->sockets[i].fd);
}
