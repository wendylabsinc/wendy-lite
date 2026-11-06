#pragma once
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

/* A WendyCom link over TCP has no heartbeat. A host, broker or NAT can drop
 * it without FIN/RST, and an idle device would then hold the link slot and
 * its TLS heap forever. Applied from accept() to every socket of the LAN
 * listener, and to the cloud operator fd at the relay handoff. Probe every
 * 15 s of silence and close after 45 s without an answer
 * (idle + interval * probes). */
#define WENDY_SERVER_KEEPALIVE_IDLE_S     15
#define WENDY_SERVER_KEEPALIVE_INTERVAL_S 15
#define WENDY_SERVER_KEEPALIVE_PROBES     2

static inline int wendy_server_enable_keepalive(int fd)
{
    int enabled = 1, idle = WENDY_SERVER_KEEPALIVE_IDLE_S,
        interval = WENDY_SERVER_KEEPALIVE_INTERVAL_S, probes = WENDY_SERVER_KEEPALIVE_PROBES;
#ifdef TCP_KEEPIDLE
    int idle_option = TCP_KEEPIDLE; /* lwIP/Linux: seconds, unlike lwIP TCP_KEEPALIVE. */
#else
    int idle_option = TCP_KEEPALIVE; /* Darwin's seconds-based spelling. */
#endif
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof enabled) ||
        setsockopt(fd, IPPROTO_TCP, idle_option, &idle, sizeof idle) ||
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof interval) ||
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &probes, sizeof probes))
        return -1;
    return 0;
}
