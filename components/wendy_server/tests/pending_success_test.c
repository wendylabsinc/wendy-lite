#include "wendy_server_pending.h"
#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void)
{
    int pair[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);
    struct wendy_server_pending p={.fd=-1};bool expired;
    assert(wendy_server_pending_put(&p,pair[0],1000));
    assert(!wendy_server_pending_put(&p,pair[1],1001));
    assert(wendy_server_pending_take(&p,false,60999,&expired)==-1 && !expired);
    assert(write(pair[1],"n",1)==1); /* Waiting never consumes client bytes. */
    int fd=wendy_server_pending_take(&p,true,61000-1,&expired);
    assert(fd==pair[0] && !expired && p.fd==-1);
    char b;assert(read(fd,&b,1)==1 && b=='n');close(fd);close(pair[1]);
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);
    assert(wendy_server_pending_put(&p,pair[0],100));
    fd=wendy_server_pending_take(&p,false,60100,&expired);
    assert(fd==pair[0] && expired && p.fd==-1);close(fd);close(pair[1]);
    assert(wendy_server_pending_take(&p,true,999999,&expired)==-1 && !expired);
    /* A readiness race must not extend the original client's wait. */
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);
    assert(wendy_server_pending_put(&p,pair[0],100));
    uint64_t deadline=p.deadline_ms;
    fd=wendy_server_pending_take(&p,true,60000,&expired);
    assert(fd==pair[0] && !expired);
    assert(wendy_server_pending_put(&p,fd,60000));p.deadline_ms=deadline;
    fd=wendy_server_pending_take(&p,false,60100,&expired);
    assert(fd==pair[0] && expired);close(fd);close(pair[1]);
    puts("physical pending ownership, readiness, deadline, and bytes preserved");
}
