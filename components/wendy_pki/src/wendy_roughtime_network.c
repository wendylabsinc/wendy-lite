#include "wendy_roughtime.h"
#include "esp_random.h"
#include "esp_timer.h"
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int wendy_rt_query(struct wendy_rt_interval *out)
{
    int sockets[WENDY_RT_SERVERS]; int64_t sent[WENDY_RT_SERVERS];
    uint8_t nonce[WENDY_RT_SERVERS][32]; struct wendy_rt_interval evidence[WENDY_RT_SERVERS];
    unsigned mask=0; uint8_t *buffer=malloc(WENDY_RT_MAX_RESPONSE+1);
    if (!buffer) return -1;
    for (int i=0;i<WENDY_RT_SERVERS;i++) sockets[i]=-1;
    for (int i=0;i<WENDY_RT_SERVERS;i++) {
        struct addrinfo hints={.ai_family=AF_INET,.ai_socktype=SOCK_DGRAM}, *addresses=NULL;
        if (getaddrinfo(wendy_rt_servers[i].host,wendy_rt_servers[i].port,&hints,&addresses)) continue;
        int fd=socket(addresses->ai_family,SOCK_DGRAM,0);
        if (fd>=0 && fd<FD_SETSIZE && !connect(fd,addresses->ai_addr,addresses->ai_addrlen)) {
            esp_fill_random(nonce[i],32);
            wendy_rt_request(buffer,nonce[i],wendy_rt_servers[i].key);
            sent[i]=esp_timer_get_time();
            if (send(fd,buffer,1024,0)==1024) sockets[i]=fd;
        }
        if (fd>=0 && sockets[i]<0) close(fd);
        freeaddrinfo(addresses);
    }
    int64_t deadline=esp_timer_get_time()+3000000;
    while (esp_timer_get_time()<deadline) {
        fd_set reads; FD_ZERO(&reads); int maxfd=-1;
        for (int i=0;i<WENDY_RT_SERVERS;i++) if (sockets[i]>=0) {
            FD_SET(sockets[i],&reads); if (sockets[i]>maxfd) maxfd=sockets[i];
        }
        if (maxfd<0) break;
        struct timeval timeout={.tv_sec=0,.tv_usec=100000};
        if (select(maxfd+1,&reads,NULL,NULL,&timeout)<=0) continue;
        for (int i=0;i<WENDY_RT_SERVERS;i++) if (sockets[i]>=0 && FD_ISSET(sockets[i],&reads)) {
            ssize_t n=recv(sockets[i],buffer,WENDY_RT_MAX_RESPONSE+1,0);
            int64_t received=esp_timer_get_time();
            if (n>0 && received-sent[i]<=3000000 &&
                !wendy_rt_verify(buffer,(size_t)n,nonce[i],wendy_rt_servers[i].key,&evidence[i])) {
                evidence[i].lower-=received; evidence[i].upper-=sent[i]; mask|=1u<<i;
                close(sockets[i]); sockets[i]=-1;
            }
        }
    }
    for (int i=0;i<WENDY_RT_SERVERS;i++) if (sockets[i]>=0) close(sockets[i]);
    free(buffer);
    if (wendy_rt_consensus(evidence,mask,out)) return -1;
    int64_t now=esp_timer_get_time(); out->lower+=now; out->upper+=now;
    return 0;
}
