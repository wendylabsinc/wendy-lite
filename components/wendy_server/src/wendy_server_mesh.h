#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Resource classification only. TLS still authenticates its peer and WendyCom
 * still decides operator/device permissions. IPv4-mapped LAN is not mesh. */
static inline bool wendy_server_mesh_address(const struct sockaddr_storage *address)
{
    if(address->ss_family!=AF_INET6)return false;
    const struct sockaddr_in6 *v6=(const struct sockaddr_in6 *)address;
    static const uint8_t device[]={0xfd,0x45,0xb8,0x91,0x56,0x7f};
    static const uint8_t operator[]={0xfd,0x45,0xb8,0x91,0x56,0x80};
    return !memcmp(v6->sin6_addr.s6_addr,device,sizeof device) ||
        !memcmp(v6->sin6_addr.s6_addr,operator,sizeof operator);
}
static inline bool wendy_server_mesh_addresses(const struct sockaddr_storage *local,
    const struct sockaddr_storage *peer)
{
    /* The accepted local VIP owns the resource path. A routed app or a future
     * endpoint may use another valid source allocation; that cannot move this
     * TLS context out of the mesh budget. Peer addresses never grant access. */
    (void)peer;
    return wendy_server_mesh_address(local);
}
/* -1 means endpoint metadata was unavailable; do not assume baseline LAN. */
static inline int wendy_server_mesh_socket(int fd)
{
    struct sockaddr_storage local={0},peer={0};
    socklen_t local_size=sizeof local,peer_size=sizeof peer;
    if(getsockname(fd,(struct sockaddr *)&local,&local_size) ||
       getpeername(fd,(struct sockaddr *)&peer,&peer_size))return -1;
    if((local.ss_family==AF_INET6 && local_size<sizeof(struct sockaddr_in6)) ||
       (peer.ss_family==AF_INET6 && peer_size<sizeof(struct sockaddr_in6)))return -1;
    return wendy_server_mesh_addresses(&local,&peer) ? 1:0;
}
