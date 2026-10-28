#pragma once
#include "lwip/sockets.h"

/* ESP-IDF lwIP recvmsg reports the complete UDP length even when the peek
 * iovec is shorter. recvfrom instead reports the copied prefix. This leaves
 * the datagram queued and also preserves an empty message as length zero. */
static inline int wendy_net_datagram_peek(int fd,struct sockaddr_storage *peer,
                                         socklen_t *peer_size)
{
    unsigned char preview;
    struct iovec iov={.iov_base=&preview,.iov_len=1};
    struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,
        .msg_name=peer,.msg_namelen=peer_size ? *peer_size:0};
    int size=recvmsg(fd,&msg,MSG_PEEK);
    if(size>=0 && peer_size)*peer_size=msg.msg_namelen;
    return size;
}
