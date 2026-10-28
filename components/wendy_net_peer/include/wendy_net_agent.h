#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>
/* Outer driver; the server transfers only routed native-agent sockets here.
 * accept always consumes fd, and never runs TLS or waits for the actor. */
void wendy_net_agent_start(void);
void wendy_net_agent_accept(int fd);
int wendy_net_agent_poll(void);
bool wendy_net_agent_stop(void);
void wendy_net_agent_watch(fd_set *,fd_set *,int *,int64_t *);
