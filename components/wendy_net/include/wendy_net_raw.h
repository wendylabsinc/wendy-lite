#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <sys/socket.h>
#endif

/* The guest executes these calls serially. Reset runs after guest execution
 * stops, as for the async socket pool. Native sockets always use O_NONBLOCK;
 * blocking guest calls wait in short slices so ordinary stop can unwind them. */
struct wn_raw_socket {int fd;bool used,nonblocking;unsigned timeout_ms;};
struct wn_raw_set {
    struct wn_raw_socket *sockets;size_t capacity;
    bool (*stopping)(void);
    int64_t (*now_us)(void);
};
int wn_raw_socket(struct wn_raw_set *,int domain,int type,int protocol);
bool wn_raw_owned(struct wn_raw_set *,int fd);
int wn_raw_nonblocking(struct wn_raw_set *,int fd,bool enabled);
int wn_raw_timeout(struct wn_raw_set *,int fd,unsigned milliseconds);
int wn_raw_connect(struct wn_raw_set *,int fd,const struct sockaddr *,socklen_t);
int wn_raw_accept(struct wn_raw_set *,int fd);
ssize_t wn_raw_send(struct wn_raw_set *,int fd,const void *,size_t);
ssize_t wn_raw_recv(struct wn_raw_set *,int fd,void *,size_t);
int wn_raw_close(struct wn_raw_set *,int fd);
void wn_raw_reset(struct wn_raw_set *);
