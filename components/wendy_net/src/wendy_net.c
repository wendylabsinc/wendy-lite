#include "wendy_net.h"
#include "wendy_net_datagram.h"
#include "wendy_net_raw.h"
#include "wendy_wasm.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_vfs_eventfd.h"
#include "wasm_export.h"
#include "wendy_safety.h"
#include "wendy_wifi.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "lwip/tcpip.h"

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#endif

static const char *TAG = "wendy_net";

/* -- WendyNet async TCP backend ---------------------------------------- */

#define WENDYNET_MAX_SOCKETS       CONFIG_WENDY_NET_MAX_SOCKETS
#define WENDYNET_MAX_LISTENERS     CONFIG_WENDY_NET_MAX_LISTENERS
#define WENDYNET_BUFFER_SIZE       CONFIG_WENDY_NET_BUFFER_SIZE
#define WENDYNET_DATAGRAM_MAX      CONFIG_WENDY_NET_DATAGRAM_MAX
#define WENDYNET_ACCEPT_QUEUE_SIZE CONFIG_WENDY_NET_ACCEPT_QUEUE_SIZE

#if CONFIG_WENDY_NET_BUFFERS_IN_PSRAM
#  define WENDYNET_BSS_ATTR EXT_RAM_BSS_ATTR
#else
#  define WENDYNET_BSS_ATTR
#endif

/* select() needs room for every wendynet fd plus the eventfd. lwIP's
 * FD_SETSIZE is set by CONFIG_LWIP_FD_SET_SIZE; bail at compile time if
 * the configured wendynet pool would exceed it. */
_Static_assert(WENDYNET_MAX_SOCKETS + WENDYNET_MAX_LISTENERS + 1 <= FD_SETSIZE,
               "wendy_net pool exceeds FD_SETSIZE; raise CONFIG_LWIP_FD_SET_SIZE");

#define WENDYNET_EVENT_ACCEPT_READY 1u
#define WENDYNET_EVENT_READ_READY   2u
#define WENDYNET_EVENT_WRITE_READY  4u
#define WENDYNET_EVENT_CLOSED       8u
#define WENDYNET_EVENT_ERROR        16u

#define WENDYNET_STATUS_READABLE 1
#define WENDYNET_STATUS_WRITABLE 2
#define WENDYNET_STATUS_CLOSED   4
#define WENDYNET_STATUS_ERROR    8

typedef enum {
    WENDYNET_SOCK_TCP = 0,        /* stream socket, own fd */
    WENDYNET_SOCK_UDP = 1,        /* datagram socket, own fd; client side uses connect() */
    WENDYNET_SOCK_UDP_PEER = 2,   /* per-peer association on a UDP listener; shares listener's fd */
} wendynet_sock_type_t;

typedef struct {
    bool used;
    int handle;
    int fd;                       /* own fd for TCP / UDP; -1 for UDP_PEER */
    wendynet_sock_type_t sock_type;
    int listener_handle;          /* for UDP_PEER: the parent UDP listener handle */
    struct sockaddr_storage peer_addr; /* UDP_PEER: IPv4 or IPv6 remote */
    socklen_t peer_addr_size;
    bool resolving;
    bool connecting;
    bool closing;
    bool closed;
    bool error;
    bool rx_datagram,tx_datagram;
    bool native_datagram;        /* native TLS owns packet transfer; no lwIP fd */
    bool tx_deferred;
    TickType_t tx_started;
    uint8_t rx_retries;
    uint16_t pending_port;
    uint16_t datagram_limit;      /* negotiated native app maximum; otherwise0 */
    uint8_t *rx;
    size_t rx_len;
    wendy_net_packet_release_fn rx_release; /* NULL for ordinary LAN buffers */
    uint8_t *tx;
    size_t tx_len;
} wendynet_socket_t;

/* Heap-allocated request handed to the lwIP tcpip thread. lwIP holds the
 * hostname pointer for the lifetime of the DNS query, so this struct must
 * outlive dns_gethostbyname() until our callback fires. */
typedef struct {
    int handle;
    char hostname[128];
} wendynet_dns_request_t;

/* Result mailbox entry pushed by the DNS callback and drained by the task. */
typedef struct {
    int handle;
    bool ok;
    ip_addr_t addr;
} wendynet_dns_result_t;

#define WENDYNET_DNS_QUEUE_DEPTH 8

typedef struct {
    bool used;
    int handle;
    int fd;
    uint8_t rx_retries;
    bool is_udp;                  /* unconnected datagram listener; demux by source addr */
    uint16_t port;
    int accepted[WENDYNET_ACCEPT_QUEUE_SIZE];
    size_t accepted_head;
    size_t accepted_count;
} wendynet_listener_t;

static SemaphoreHandle_t s_wendynet_lock;
static TaskHandle_t s_wendynet_task;
static QueueHandle_t s_wendynet_dns_results;
static uint32_t s_wendynet_handler_id;
static uint32_t s_wendynet_pending_bits;
static bool s_wendynet_event_queued;
/* Set under lock when notify decides we owe a wendy_callback_post; drained
 * by wendynet_unlock() so the post happens outside s_wendynet_lock. */
static bool s_wendynet_post_pending;
static int s_wendynet_next_handle = 1;
static wendy_net_mesh_begin_fn s_wendynet_mesh_begin;
static wendy_net_mesh_resolve_fn s_wendynet_mesh_resolve;
static wendy_net_service_fn s_service_catalog;
/* Incarnation only: no guest intent, task, or heap allocation survives OFF. */
static uint32_t s_service_epoch;
static WENDYNET_BSS_ATTR wendynet_socket_t s_wendynet_sockets[WENDYNET_MAX_SOCKETS];
static WENDYNET_BSS_ATTR wendynet_listener_t s_wendynet_listeners[WENDYNET_MAX_LISTENERS];
static WENDYNET_BSS_ATTR struct wn_raw_socket s_raw_slots[WENDYNET_MAX_SOCKETS];
static struct wn_raw_set s_raw={.sockets=s_raw_slots,.capacity=WENDYNET_MAX_SOCKETS,
    .stopping=wendy_wasm_is_terminating,.now_us=esp_timer_get_time};

/* eventfd used to wake the task's select() when other threads mutate state
 * (close marks, queued sends, new sockets/listeners, guest reset). */
static int s_wakeup_fd = -1;

/* Write a one-shot wake signal to the task's select(). */
static void wendynet_wake_locked(void)
{
    if (s_wakeup_fd < 0) {
        return;
    }
    uint64_t signal = 1;
    (void)write(s_wakeup_fd, &signal, sizeof(signal));
}

static void wendynet_lock(void)
{
    if (s_wendynet_lock) {
        xSemaphoreTake(s_wendynet_lock, portMAX_DELAY);
    }
}

static void wendynet_unlock(void)
{
#if CONFIG_WENDY_CALLBACK
    bool do_post = false;
    uint32_t post_handler_id = 0;
    uint32_t post_bits = 0;
    if (s_wendynet_post_pending) {
        do_post = true;
        post_handler_id = s_wendynet_handler_id;
        post_bits = s_wendynet_pending_bits;
        s_wendynet_post_pending = false;
    }
#endif
    if (s_wendynet_lock) {
        xSemaphoreGive(s_wendynet_lock);
    }
#if CONFIG_WENDY_CALLBACK
    /* Post the coalesced event outside the lock so a slow callback queue
     * doesn't serialize every wrapper. */
    if (do_post) {
        esp_err_t err = wendy_callback_post(post_handler_id, post_bits, 0, 0);
        if (err == ESP_OK) {
            if (s_wendynet_lock) {
                xSemaphoreTake(s_wendynet_lock, portMAX_DELAY);
            }
            s_wendynet_event_queued = true;
            if (s_wendynet_lock) {
                xSemaphoreGive(s_wendynet_lock);
            }
        }
        /* On failure event_queued stays false, so the next notify rearms. */
    }
#endif
}

static void wendynet_notify_locked(uint32_t bits)
{
#if CONFIG_WENDY_CALLBACK
    if (!s_wendynet_handler_id) {
        return;
    }
    s_wendynet_pending_bits |= bits;
    if (!s_wendynet_event_queued && !s_wendynet_post_pending) {
        s_wendynet_post_pending = true;
    }
#else
    (void)bits;
#endif
}

static int wendynet_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static wendynet_socket_t *wendynet_find_socket_locked(int handle)
{
    for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
        if (s_wendynet_sockets[i].used && s_wendynet_sockets[i].handle == handle) {
            return &s_wendynet_sockets[i];
        }
    }
    return NULL;
}

static wendynet_listener_t *wendynet_find_listener_locked(int handle)
{
    for (int i = 0; i < WENDYNET_MAX_LISTENERS; i++) {
        if (s_wendynet_listeners[i].used && s_wendynet_listeners[i].handle == handle) {
            return &s_wendynet_listeners[i];
        }
    }
    return NULL;
}

static int wendynet_alloc_handle_locked(void)
{
    int handle = s_wendynet_next_handle++;
    if (s_wendynet_next_handle <= 0) {
        s_wendynet_next_handle = 1;
    }
    return handle;
}

static void *wendynet_buffer_alloc(size_t size)
{
#if CONFIG_WENDY_NET_BUFFERS_IN_PSRAM
    return heap_caps_malloc(size,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
#else
    return malloc(size);
#endif
}

static int wendynet_socket_buffers_locked(wendynet_socket_t *sock)
{
    /* TCP keeps its stream buffers. UDP owns only the actual pending
     * packets, allocated independently on receive/send and released on drain. */
    if(sock->sock_type!=WENDYNET_SOCK_TCP || sock->rx)return 0;
    uint8_t *buffers=wendynet_buffer_alloc(2U*WENDYNET_BUFFER_SIZE);
    if(!buffers)return -1;
    sock->rx=buffers;sock->tx=buffers+WENDYNET_BUFFER_SIZE;
    return 0;
}

static wendynet_socket_t *wendynet_alloc_socket_locked(int fd)
{
    for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
        if (!s_wendynet_sockets[i].used) {
            memset(&s_wendynet_sockets[i], 0, sizeof(s_wendynet_sockets[i]));
            s_wendynet_sockets[i].used = true;
            s_wendynet_sockets[i].handle = wendynet_alloc_handle_locked();
            s_wendynet_sockets[i].fd = fd;
            if(fd>=0 && wendynet_socket_buffers_locked(&s_wendynet_sockets[i])){
                memset(&s_wendynet_sockets[i],0,sizeof(s_wendynet_sockets[i]));
                return NULL;
            }
            return &s_wendynet_sockets[i];
        }
    }
    return NULL;
}

static void wendynet_release_rx_locked(wendynet_socket_t *sock)
{
    if(sock->rx){
        if(sock->rx_release)sock->rx_release(sock->rx);
        else free(sock->rx);
    }
    sock->rx=NULL;sock->rx_len=0;sock->rx_datagram=false;sock->rx_release=NULL;
}

static void wendynet_release_socket_locked(wendynet_socket_t *sock)
{
    if (!sock || !sock->used) {
        return;
    }
    /* UDP_PEER shares the listener's fd — never close it here. */
    if (sock->fd >= 0 && sock->sock_type != WENDYNET_SOCK_UDP_PEER) {
        close(sock->fd);
    }
    wendynet_release_rx_locked(sock);
    if(sock->sock_type!=WENDYNET_SOCK_TCP)free(sock->tx);
    memset(sock, 0, sizeof(*sock));
    sock->fd = -1;
}

static bool wendynet_sockaddr_equal(const struct sockaddr_storage *a,
                                     const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family) return false;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *x=(const struct sockaddr_in *)a;
        const struct sockaddr_in *y=(const struct sockaddr_in *)b;
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
#if LWIP_IPV6
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *x=(const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *y=(const struct sockaddr_in6 *)b;
        return x->sin6_port == y->sin6_port && x->sin6_scope_id == y->sin6_scope_id &&
            !memcmp(&x->sin6_addr,&y->sin6_addr,sizeof x->sin6_addr);
    }
#endif
    return false;
}

static wendynet_socket_t *wendynet_find_udp_peer_locked(int listener_handle,
                                                         const struct sockaddr_storage *addr)
{
    for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
        wendynet_socket_t *sock = &s_wendynet_sockets[i];
        if (sock->used
            && sock->sock_type == WENDYNET_SOCK_UDP_PEER
            && !sock->closing && !sock->closed && !sock->error
            && sock->listener_handle == listener_handle
            && wendynet_sockaddr_equal(&sock->peer_addr, addr)) {
            return sock;
        }
    }
    return NULL;
}

/* Close UDP_PEER associations on a listener that is going away (lock held).
 * Like a TCP peer: raise CLOSED and let the guest drain buffered rx before the
 * slot is reclaimed; a peer with no buffered rx is freed now. */
static void wendynet_close_udp_peers_for_listener_locked(int listener_handle)
{
    for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
        wendynet_socket_t *sock = &s_wendynet_sockets[i];
        if (sock->used
            && sock->sock_type == WENDYNET_SOCK_UDP_PEER
            && sock->listener_handle == listener_handle
            && !sock->closed) {
            sock->closed = true;
            wendynet_notify_locked(WENDYNET_EVENT_CLOSED);
            if (sock->rx_len == 0 && !sock->rx_datagram) {
                wendynet_release_socket_locked(sock);
            }
        }
    }
}

static void wendynet_release_drained_closed_socket_locked(wendynet_socket_t *sock)
{
    if (!sock || !sock->used || sock->rx_len != 0 || sock->rx_datagram) {
        return;
    }
    if (sock->closed || sock->error) {
        wendynet_release_socket_locked(sock);
    }
}

static void wendynet_close_listener_locked(wendynet_listener_t *listener)
{
    if (!listener || !listener->used) {
        return;
    }
    /* Queued-but-unaccepted sockets are unreachable from the guest once the
     * listener closes; release them so they don't keep filling RX buffers. */
    for (size_t i = 0; i < listener->accepted_count; i++) {
        size_t index = (listener->accepted_head + i) % WENDYNET_ACCEPT_QUEUE_SIZE;
        wendynet_socket_t *sock = wendynet_find_socket_locked(listener->accepted[index]);
        wendynet_release_socket_locked(sock);
    }
    /* For UDP listeners: also close any per-peer associations the guest has
     * already accepted. They share the listener fd and can't outlive it. */
    if (listener->is_udp) {
        wendynet_close_udp_peers_for_listener_locked(listener->handle);
    }
    if (listener->fd >= 0) {
        close(listener->fd);
    }
    memset(listener, 0, sizeof(*listener));
    listener->fd = -1;
}

static bool wendynet_listener_enqueue_locked(wendynet_listener_t *listener, int socket_handle)
{
    if (listener->accepted_count >= WENDYNET_ACCEPT_QUEUE_SIZE) {
        return false;
    }
    size_t index = (listener->accepted_head + listener->accepted_count) % WENDYNET_ACCEPT_QUEUE_SIZE;
    listener->accepted[index] = socket_handle;
    listener->accepted_count++;
    return true;
}

static void wendynet_close_marked_sockets_locked(void)
{
    for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
        wendynet_socket_t *sock = &s_wendynet_sockets[i];
        if (!sock->used || !sock->closing) {
            continue;
        }
        if ((sock->tx_len > 0 || sock->tx_datagram) && !sock->closed && !sock->error) {
            continue;
        }
        if (sock->fd >= 0) {
            shutdown(sock->fd, SHUT_RDWR);
        }
        wendynet_release_socket_locked(sock);
        wendynet_notify_locked(WENDYNET_EVENT_CLOSED);
    }
}

/* DNS resolution callback. Runs on the lwIP tcpip thread. */
static void wendynet_dns_found(const char *name, const ip_addr_t *ipaddr,
                                void *arg)
{
    (void)name;
    wendynet_dns_request_t *req = (wendynet_dns_request_t *)arg;
    wendynet_dns_result_t result = {
        .handle = req->handle,
        .ok = (ipaddr != NULL),
    };
    if (ipaddr) {
        result.addr = *ipaddr;
    }
    if (s_wendynet_dns_results) {
        (void)xQueueSend(s_wendynet_dns_results, &result, 0);
    }
    if (s_wakeup_fd >= 0) {
        uint64_t signal = 1;
        (void)write(s_wakeup_fd, &signal, sizeof(signal));
    }
    free(req);
}

/* Scheduled via tcpip_callback so dns_gethostbyname runs on the tcpip
 * thread. Owns the request struct until either the synchronous fast paths
 * (literal IP / cache hit / immediate failure) handle it, or until lwIP
 * fires the async callback. */
static void wendynet_kick_resolve(void *arg)
{
    wendynet_dns_request_t *req = (wendynet_dns_request_t *)arg;
    ip_addr_t addr;
    err_t err = dns_gethostbyname_addrtype(req->hostname, &addr,
                                   wendynet_dns_found, req,
#if LWIP_IPV4 && LWIP_IPV6
                                   LWIP_DNS_ADDRTYPE_IPV4_IPV6
#else
                                   LWIP_DNS_ADDRTYPE_DEFAULT
#endif
                                   );
    if (err == ERR_OK) {
        /* Literal IP or cache hit — lwIP does not invoke the callback in
         * this case, so synthesize one to keep the result path uniform. */
        wendynet_dns_found(req->hostname, &addr, req);
    }
    else if (err != ERR_INPROGRESS) {
        wendynet_dns_found(req->hostname, NULL, req);
    }
    /* ERR_INPROGRESS: lwIP will invoke wendynet_dns_found later with req. */
}

/* Promote a resolving socket to connecting (or mark it errored).
 * Called by the wendynet task with wendynet_lock held. */
static void wendynet_start_resolved_connect_locked(wendynet_socket_t *sock,
                                                    const ip_addr_t *ipaddr)
{
    sock->resolving = false;

    if(wendynet_socket_buffers_locked(sock)){
        sock->closed=sock->error=true;
        wendynet_notify_locked(WENDYNET_EVENT_ERROR|WENDYNET_EVENT_CLOSED);
        return;
    }

    bool is_udp = (sock->sock_type == WENDYNET_SOCK_UDP);
    int sock_kind = is_udp ? SOCK_DGRAM : SOCK_STREAM;
    int proto = is_udp ? IPPROTO_UDP : IPPROTO_IP;

    int family=AF_INET;
#if LWIP_IPV6
    if (IP_IS_V6(ipaddr)) family=AF_INET6;
#endif
    int fd = socket(family, sock_kind, proto);
    if (fd < 0) {
        sock->closed = true;
        sock->error = true;
        wendynet_notify_locked(WENDYNET_EVENT_ERROR | WENDYNET_EVENT_CLOSED);
        return;
    }
    if (wendynet_set_nonblocking(fd) != 0) {
        close(fd);
        sock->closed = true;
        sock->error = true;
        wendynet_notify_locked(WENDYNET_EVENT_ERROR | WENDYNET_EVENT_CLOSED);
        return;
    }

    struct sockaddr_storage addr={0};
    socklen_t addr_size;
#if LWIP_IPV6
    if (family == AF_INET6) {
        struct sockaddr_in6 *v6=(struct sockaddr_in6 *)&addr;
        v6->sin6_family=AF_INET6; v6->sin6_port=htons(sock->pending_port);
        memcpy(&v6->sin6_addr,ip_2_ip6(ipaddr)->addr,sizeof v6->sin6_addr);
        v6->sin6_scope_id=ip6_addr_zone(ip_2_ip6(ipaddr));
        addr_size=sizeof *v6;
    } else
#endif
    {
        struct sockaddr_in *v4=(struct sockaddr_in *)&addr;
        v4->sin_family=AF_INET; v4->sin_port=htons(sock->pending_port);
        v4->sin_addr.s_addr=ip4_addr_get_u32(ip_2_ip4(ipaddr));
        addr_size=sizeof *v4;
    }

    sock->fd = fd;
    if (connect(fd, (struct sockaddr *)&addr, addr_size) != 0) {
        if (!is_udp && errno == EINPROGRESS) {
            sock->connecting = true;
            return;
        }
        close(fd);
        sock->fd = -1;
        sock->closed = true;
        sock->error = true;
        wendynet_notify_locked(WENDYNET_EVENT_ERROR | WENDYNET_EVENT_CLOSED);
        return;
    }
    sock->connecting = false;
    wendynet_notify_locked(WENDYNET_EVENT_WRITE_READY);
}

/* Called by the wendynet task with wendynet_lock held, before rebuilding
 * the fd_set and again after select() returns. */
static void wendynet_drain_dns_results_locked(void)
{
    if (!s_wendynet_dns_results) {
        return;
    }
    wendynet_dns_result_t result;
    while (xQueueReceive(s_wendynet_dns_results, &result, 0) == pdTRUE) {
        wendynet_socket_t *sock = wendynet_find_socket_locked(result.handle);
        if (!sock || !sock->resolving) {
            /* Socket was closed or reset while DNS was in flight. */
            continue;
        }
        if (!result.ok) {
            sock->resolving = false;
            sock->closed = true;
            sock->error = true;
            wendynet_notify_locked(WENDYNET_EVENT_ERROR
                                   | WENDYNET_EVENT_CLOSED);
            continue;
        }
        if (sock->closing) {
            /* Guest closed before DNS finished; finish the close. */
            sock->resolving = false;
            sock->closed = true;
            wendynet_notify_locked(WENDYNET_EVENT_CLOSED);
            continue;
        }
        wendynet_start_resolved_connect_locked(sock, &result.addr);
    }
}

static void wendynet_task_main(void *arg)
{
    (void)arg;

    for (;;) {
        fd_set readfds;
        fd_set writefds;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        int max_fd = -1;

        if (s_wakeup_fd >= 0) {
            FD_SET(s_wakeup_fd, &readfds);
            if (s_wakeup_fd > max_fd) {
                max_fd = s_wakeup_fd;
            }
        }

        wendynet_lock();
        wendynet_drain_dns_results_locked();
        wendynet_close_marked_sockets_locked();

        bool udp_retry = false;
        /* UDP sends are eager — there's no connection-level backpressure to
         * wait for. Drain every pending UDP tx queue before sleeping in
         * select(); each UDP slot holds at most one datagram. */
        for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
            wendynet_socket_t *sock = &s_wendynet_sockets[i];
            if (!sock->used || !sock->tx_datagram || sock->native_datagram
                || sock->closed || sock->error) {
                continue;
            }
            /* Resolve the egress fd and (for peers) the destination address. */
            int out_fd = -1;
            const struct sockaddr *dest = NULL;
            socklen_t dest_len = 0;
            if (sock->sock_type == WENDYNET_SOCK_UDP && sock->fd >= 0
                && !sock->connecting) {
                out_fd = sock->fd;  /* connected datagram socket */
            } else if (sock->sock_type == WENDYNET_SOCK_UDP_PEER) {
                wendynet_listener_t *listener =
                    wendynet_find_listener_locked(sock->listener_handle);
                if (listener && listener->fd >= 0) {
                    out_fd = listener->fd;
                    dest = (const struct sockaddr *)&sock->peer_addr;
                    dest_len = sock->peer_addr_size;
                }
                /* listener gone: out_fd stays -1, datagram is dropped below */
            } else {
                continue;
            }

            if (out_fd >= 0) {
                size_t send_free = heap_caps_get_free_size(MALLOC_CAP_8BIT);
                size_t send_largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
                int n = dest
                    ? sendto(out_fd, sock->tx, sock->tx_len, 0, dest, dest_len)
                    : send(out_fd, sock->tx, sock->tx_len, 0);
                int send_error = n < 0 ? errno : 0;
                if (n < 0 && (send_error == ENOMEM || send_error == ENOBUFS ||
                              send_error == EAGAIN || send_error == EWOULDBLOCK) &&
                    xTaskGetTickCount() - sock->tx_started < pdMS_TO_TICKS(1000)) {
                    /* A lower-priority local sender may still own the original
                     * packet while this task is already sending its reply.
                     * Retain our single pending packet and let that sender run;
                     * retrying requires no further queue or payload allocation. */
                    if (!sock->tx_deferred)
                        ESP_LOGI(TAG, "UDP send deferred: bytes=%u errno=%d heap=%u largest=%u",
                                 (unsigned)sock->tx_len, send_error,
                                 (unsigned)send_free, (unsigned)send_largest);
                    sock->tx_deferred = true;
                    udp_retry = true;
                    continue;
                }
                if (n >= 0 && sock->tx_deferred)
                    ESP_LOGI(TAG, "UDP send recovered: bytes=%u wait_ticks=%u",
                             (unsigned)sock->tx_len,
                             (unsigned)(xTaskGetTickCount() - sock->tx_started));
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    ESP_LOGW(TAG, "UDP send failed: bytes=%u errno=%d heap_before=%u largest_before=%u heap_after=%u largest_after=%u",
                             (unsigned)sock->tx_len, errno, (unsigned)send_free,
                             (unsigned)send_largest,
                             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
                             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
                    sock->error = true;
                    wendynet_notify_locked(WENDYNET_EVENT_ERROR | WENDYNET_EVENT_CLOSED);
                }
            }
            /* Consume a sent packet, a permanent failure, an exhausted retry
             * or a retired listener. UDP still has no delivery guarantee. */
            sock->tx_len = 0;
            sock->tx_datagram = false;
            free(sock->tx);sock->tx=NULL;
            wendynet_notify_locked(WENDYNET_EVENT_WRITE_READY);
        }

        for (int i = 0; i < WENDYNET_MAX_LISTENERS; i++) {
            wendynet_listener_t *listener = &s_wendynet_listeners[i];
            if (!listener->used || listener->fd < 0) {
                continue;
            }
            /* UDP listeners always read so established peers are never starved
             * by a full accept queue: capacity is enforced per-datagram in the
             * demux loop (new associations spill, existing peers keep flowing).
             * TCP keeps the accept-queue backpressure — its accepted children
             * have their own fds, so deferring accept() is harmless. */
            bool can_read = listener->is_udp
                ? true
                : (listener->accepted_count < WENDYNET_ACCEPT_QUEUE_SIZE);
            if (can_read) {
                FD_SET(listener->fd, &readfds);
                if (listener->fd > max_fd) {
                    max_fd = listener->fd;
                }
            }
        }
        for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
            wendynet_socket_t *sock = &s_wendynet_sockets[i];
            if (!sock->used || sock->fd < 0) {
                continue;
            }
            /* TCP can stream into remaining rx space; UDP slots hold a single
             * datagram, so only select for read while the slot is empty —
             * otherwise select() would spin on a readable fd we won't drain. */
            bool rx_has_space = (sock->sock_type == WENDYNET_SOCK_TCP)
                ? (sock->rx_len < WENDYNET_BUFFER_SIZE)
                : !sock->rx_datagram;
            if (!sock->connecting && !sock->closed && !sock->closing &&
                !sock->error && rx_has_space) {
                FD_SET(sock->fd, &readfds);
                if (sock->fd > max_fd) {
                    max_fd = sock->fd;
                }
            }
            /* UDP tx was drained eagerly above; only TCP waits on writefds. */
            if (!sock->closed && !sock->error && sock->sock_type == WENDYNET_SOCK_TCP &&
                (sock->connecting || sock->tx_len > 0)) {
                FD_SET(sock->fd, &writefds);
                if (sock->fd > max_fd) {
                    max_fd = sock->fd;
                }
            }
        }
        wendynet_unlock();

        // Normally wait for an fd event; temporary UDP allocation pressure
        // gets a bounded retry without spinning or retaining another packet.
        struct timeval retry_wait = {.tv_usec = 10000};
        int rc = select(max_fd + 1, &readfds, &writefds, NULL,
                        udp_retry ? &retry_wait : NULL);
        if (rc < 0) {
            // Errors here are typically transient (e.g. EBADF if a fd was
            // closed concurrently). The next iteration rebuilds the fd_set
            // from the current socket table, which is the right recovery.
            // Log + back off so a persistent failure doesn't spin the CPU.
            ESP_LOGW(TAG, "select() error: errno=%d", errno);
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        // Drain the wakeup signal so the next select() actually blocks until
        // the *next* state change (or socket-fd event).
        if (s_wakeup_fd >= 0 && FD_ISSET(s_wakeup_fd, &readfds)) {
            uint64_t drain;
            (void)read(s_wakeup_fd, &drain, sizeof(drain));
        }

        wendynet_lock();
        wendynet_drain_dns_results_locked();
        wendynet_close_marked_sockets_locked();

        bool udp_rx_pressure = false;
        for (int i = 0; i < WENDYNET_MAX_LISTENERS; i++) {
            wendynet_listener_t *listener = &s_wendynet_listeners[i];
            if (!listener->used || listener->fd < 0 || !FD_ISSET(listener->fd, &readfds)) {
                continue;
            }

            if (listener->is_udp) {
                /* Peek only the source address, then receive directly into
                 * its live association's RX buffer. A single consumer owns
                 * this fd under wendynet_lock, so the following receive takes
                 * the same complete datagram, including an empty one. No
                 * listener-sized scratch allocation or payload copy is needed.
                 * Drain/drop full or unadmitted sources as before so they do
                 * not starve established peers behind them in the UDP queue. */
                for (;;) {
                    struct sockaddr_storage src={0};
                    socklen_t src_len = sizeof(src);
                    uint8_t preview;
                    int n=wendy_net_datagram_peek(listener->fd,&src,&src_len);
                    if(n<0){
                        if(errno!=EAGAIN && errno!=EWOULDBLOCK)
                            wendynet_notify_locked(WENDYNET_EVENT_ERROR);
                        break;
                    }
                    wendynet_socket_t *peer=
                        wendynet_find_udp_peer_locked(listener->handle,&src);
                    if(!peer && listener->accepted_count<WENDYNET_ACCEPT_QUEUE_SIZE){
                        peer=wendynet_alloc_socket_locked(-1);
                        if(peer){
                            peer->sock_type=WENDYNET_SOCK_UDP_PEER;
                            peer->listener_handle=listener->handle;
                            peer->peer_addr=src;peer->peer_addr_size=src_len;
                            if(!wendynet_listener_enqueue_locked(listener,peer->handle)){
                                wendynet_release_socket_locked(peer);peer=NULL;
                            }else wendynet_notify_locked(WENDYNET_EVENT_ACCEPT_READY);
                        }
                    }
                    bool deliver=peer && !peer->rx_datagram;
                    size_t capacity=(size_t)n<WENDYNET_DATAGRAM_MAX ? (size_t)n:WENDYNET_DATAGRAM_MAX;
                    if(deliver){
                        peer->rx=wendynet_buffer_alloc(capacity ? capacity:1);
                        if(!peer->rx){
                            if(!listener->rx_retries)
                                ESP_LOGI(TAG,"UDP receive deferred: bytes=%u heap=%u largest=%u",
                                    (unsigned)capacity,(unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
                                    (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
                            if(++listener->rx_retries<=100){udp_rx_pressure=true;break;}
                            deliver=false;
                        }
                    }
                    listener->rx_retries=0;
                    n=recvfrom(listener->fd,deliver ? peer->rx:&preview,
                               deliver ? capacity:1,0,NULL,NULL);
                    if(n<0){
                        if(deliver)wendynet_release_rx_locked(peer);
                        if(errno!=EAGAIN && errno!=EWOULDBLOCK)
                            wendynet_notify_locked(WENDYNET_EVENT_ERROR);
                        break;
                    }
                    if(deliver){
                        peer->rx_len=(size_t)n;peer->rx_datagram=true;
                        wendynet_notify_locked(WENDYNET_EVENT_READ_READY);
                    }
                }
                continue;
            }

            for (;;) {
                int client_fd = accept(listener->fd, NULL, NULL);
                if (client_fd < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        wendynet_notify_locked(WENDYNET_EVENT_ERROR);
                    }
                    break;
                }

                if (wendynet_set_nonblocking(client_fd) != 0) {
                    close(client_fd);
                    continue;
                }

                wendynet_socket_t *sock = wendynet_alloc_socket_locked(client_fd);
                if (!sock) {
                    close(client_fd);
                    wendynet_notify_locked(WENDYNET_EVENT_ERROR);
                    continue;
                }

                if (!wendynet_listener_enqueue_locked(listener, sock->handle)) {
                    wendynet_release_socket_locked(sock);
                    break;
                }
                wendynet_notify_locked(WENDYNET_EVENT_ACCEPT_READY);

                if (listener->accepted_count >= WENDYNET_ACCEPT_QUEUE_SIZE) {
                    break;
                }
            }
        }

        for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
            wendynet_socket_t *sock = &s_wendynet_sockets[i];
            if (!sock->used || sock->fd < 0) {
                continue;
            }

            if (sock->sock_type == WENDYNET_SOCK_UDP) {
                /* UDP standalone (connected client): one datagram per recv,
                 * read only while the slot is empty. Sends were drained
                 * eagerly before select(). */
                if (!sock->closed && !sock->error
                    && !sock->rx_datagram
                    && FD_ISSET(sock->fd, &readfds)) {
                    int n=wendy_net_datagram_peek(sock->fd,NULL,NULL);
                    if(n>=0){
                        size_t capacity=(size_t)n<WENDYNET_DATAGRAM_MAX ? (size_t)n:WENDYNET_DATAGRAM_MAX;
                        sock->rx=wendynet_buffer_alloc(capacity ? capacity:1);
                        if(!sock->rx){
                            if(++sock->rx_retries<=100){udp_rx_pressure=true;continue;}
                            sock->rx_retries=0;
                            unsigned char discarded;
                            (void)recv(sock->fd,&discarded,1,0);
                            continue;
                        }
                        sock->rx_retries=0;
                        n=recv(sock->fd,sock->rx,capacity,0);
                    }
                    if (n >= 0) {
                        sock->rx_len = (size_t)n;
                        sock->rx_datagram = true;
                        wendynet_notify_locked(WENDYNET_EVENT_READ_READY);
                    } else {
                        wendynet_release_rx_locked(sock);
                        if(errno==EAGAIN || errno==EWOULDBLOCK)continue;
                        sock->error = true;
                        wendynet_notify_locked(WENDYNET_EVENT_ERROR | WENDYNET_EVENT_CLOSED);
                    }
                }
                continue;
            }

            if (sock->connecting && FD_ISSET(sock->fd, &writefds)) {
                int connect_error = 0;
                socklen_t connect_error_len = sizeof(connect_error);
                if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR,
                               &connect_error, &connect_error_len) != 0 ||
                    connect_error != 0) {
                    sock->connecting = false;
                    sock->closed = true;
                    sock->error = true;
                    close(sock->fd);
                    sock->fd = -1;
                    wendynet_notify_locked(WENDYNET_EVENT_ERROR | WENDYNET_EVENT_CLOSED);
                    continue;
                }
                sock->connecting = false;
                wendynet_notify_locked(WENDYNET_EVENT_WRITE_READY);
            }

            if (!sock->connecting && !sock->closed && !sock->error &&
                FD_ISSET(sock->fd, &readfds)) {
                while (sock->rx_len < WENDYNET_BUFFER_SIZE) {
                    size_t space = WENDYNET_BUFFER_SIZE - sock->rx_len;
                    int n = recv(sock->fd, sock->rx + sock->rx_len, space, 0);
                    if (n > 0) {
                        sock->rx_len += (size_t)n;
                        wendynet_notify_locked(WENDYNET_EVENT_READ_READY);
                        continue;
                    }
                    if (n == 0) {
                        sock->closed = true;
                        wendynet_notify_locked(WENDYNET_EVENT_CLOSED | WENDYNET_EVENT_READ_READY);
                        break;
                    }
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        sock->error = true;
                        wendynet_notify_locked(WENDYNET_EVENT_ERROR | WENDYNET_EVENT_CLOSED);
                    }
                    break;
                }
            }

            if (!sock->connecting && !sock->closed && !sock->error &&
                sock->tx_len > 0 && FD_ISSET(sock->fd, &writefds)) {
                bool was_full = (sock->tx_len >= WENDYNET_BUFFER_SIZE);
                int n = send(sock->fd, sock->tx, sock->tx_len, 0);
                if (n > 0) {
                    size_t sent = (size_t)n;
                    if (sent < sock->tx_len) {
                        memmove(sock->tx, sock->tx + sent, sock->tx_len - sent);
                    }
                    sock->tx_len -= sent;
                    if (was_full || sock->tx_len == 0) {
                        wendynet_notify_locked(WENDYNET_EVENT_WRITE_READY);
                    }
                } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    sock->error = true;
                    wendynet_notify_locked(WENDYNET_EVENT_ERROR | WENDYNET_EVENT_CLOSED);
                }
            }
        }

        wendynet_close_marked_sockets_locked();

        wendynet_unlock();
        /* A readable UDP fd remains readable while its packet is queued.
         * Yield outside the table lock so its lower-priority sender can
         * release original buffers before the bounded receive retry. */
        if(udp_rx_pressure)vTaskDelay(pdMS_TO_TICKS(10));
    }
}

static int wendynet_ensure_started_locked(void)
{
    if (!s_wendynet_dns_results) {
        s_wendynet_dns_results = xQueueCreate(WENDYNET_DNS_QUEUE_DEPTH,
                                              sizeof(wendynet_dns_result_t));
        if (!s_wendynet_dns_results) {
            return -1;
        }
    }
    if (s_wakeup_fd < 0) {
        s_wakeup_fd = eventfd(0, 0);
        if (s_wakeup_fd < 0) {
            ESP_LOGE(TAG, "eventfd() failed");
            return -1;
        }
    }
    if (!s_wendynet_task) {
        BaseType_t ret = xTaskCreatePinnedToCore(
            wendynet_task_main, "wendynet", 4096, NULL, 5,
            &s_wendynet_task, tskNO_AFFINITY);
        if (ret != pdPASS) {
            s_wendynet_task = NULL;
            return -1;
        }
    }
    return 0;
}

static int wendynet_init_wrapper(wasm_exec_env_t exec_env, int handler_id)
{
    (void)exec_env;
    wendynet_lock();
    int rc = wendynet_ensure_started_locked();
    if (rc == 0) {
        s_wendynet_handler_id = (uint32_t)handler_id;
    }
    wendynet_unlock();
    return rc;
}

static int wendynet_drain_events_wrapper(wasm_exec_env_t exec_env)
{
    (void)exec_env;
    wendynet_lock();
    uint32_t bits = s_wendynet_pending_bits;
    s_wendynet_pending_bits = 0;
    s_wendynet_event_queued = false;
    wendynet_unlock();
    return (int)bits;
}

/* Shared body for the TCP/UDP listen wrappers. For UDP, backlog is ignored
 * (no listen()). Returns a listener handle or -1. */
static int wendynet_listen_common(int port, bool is_udp, int backlog)
{
    if (port <= 0 || port > 65535) {
        return -1;
    }

    int family=AF_INET;
#if LWIP_IPV6
    family=AF_INET6;
#endif
    int fd = socket(family, is_udp ? SOCK_DGRAM : SOCK_STREAM,
                    is_udp ? IPPROTO_UDP : IPPROTO_IP);
    if (fd < 0) {
        return -1;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#if LWIP_IPV6
    int v6_only=0;
    if (setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&v6_only,sizeof v6_only)) {
        close(fd);return -1;
    }
#endif

    if (wendynet_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_storage addr={0};
    socklen_t addr_size;
#if LWIP_IPV6
    struct sockaddr_in6 *v6=(struct sockaddr_in6 *)&addr;
    v6->sin6_family=AF_INET6;v6->sin6_port=htons((uint16_t)port);
    addr_size=sizeof *v6;
#else
    struct sockaddr_in *v4=(struct sockaddr_in *)&addr;
    v4->sin_family=AF_INET;v4->sin_port=htons((uint16_t)port);
    addr_size=sizeof *v4;
#endif
    if (bind(fd, (struct sockaddr *)&addr, addr_size) != 0) {
        close(fd);
        return -1;
    }
    if (!is_udp &&
        listen(fd, backlog > 0 ? backlog : WENDYNET_ACCEPT_QUEUE_SIZE) != 0) {
        close(fd);
        return -1;
    }

    wendynet_lock();
    if (wendynet_ensure_started_locked() != 0) {
        wendynet_unlock();
        close(fd);
        return -1;
    }

    for (int i = 0; i < WENDYNET_MAX_LISTENERS; i++) {
        if (!s_wendynet_listeners[i].used) {
            memset(&s_wendynet_listeners[i], 0, sizeof(s_wendynet_listeners[i]));
            s_wendynet_listeners[i].used = true;
            s_wendynet_listeners[i].handle = wendynet_alloc_handle_locked();
            s_wendynet_listeners[i].fd = fd;
            s_wendynet_listeners[i].is_udp = is_udp;
            s_wendynet_listeners[i].port = (uint16_t)port;
            int handle = s_wendynet_listeners[i].handle;
            wendynet_wake_locked();
            wendynet_unlock();
            ESP_LOGI(TAG, "WendyNet listening on %s port %d (handle=%d)",
                     is_udp ? "UDP" : "TCP", port, handle);
            return handle;
        }
    }

    wendynet_unlock();
    close(fd);
    return -1;
}

/* Shared body for the TCP/UDP connect wrappers. Allocates a socket slot of the
 * given sock_type and kicks off async DNS resolution. Returns a socket handle
 * or -1. */
static int wendynet_connect_common(const char *host, int host_len, int port,
                                   wendynet_sock_type_t sock_type)
{
    if (!host || host_len <= 0 || port <= 0 || port > 65535) {
        return -1;
    }

    wendynet_dns_request_t *req = malloc(sizeof(*req));
    if (!req) {
        return -1;
    }
    int copy_len = (host_len < (int)sizeof(req->hostname) - 1) ?
        host_len : (int)sizeof(req->hostname) - 1;
    memcpy(req->hostname, host, copy_len);
    req->hostname[copy_len] = '\0';

    wendynet_lock();
    if (wendynet_ensure_started_locked() != 0) {
        wendynet_unlock();
        free(req);
        return -1;
    }

    wendynet_socket_t *sock = wendynet_alloc_socket_locked(-1);
    if (!sock) {
        wendynet_unlock();
        free(req);
        return -1;
    }
    sock->sock_type = sock_type;
    sock->resolving = true;
    sock->pending_port = (uint16_t)port;
    int handle = sock->handle;
    req->handle = handle;
    wendy_net_mesh_begin_fn mesh_begin = s_wendynet_mesh_begin;
    wendynet_unlock();

    if (mesh_begin) {
        int dispatched = mesh_begin(handle,req->hostname,(uint16_t)port,sock_type==WENDYNET_SOCK_UDP);
        if (dispatched) {
            free(req);
            if (dispatched < 0) wendy_net_mesh_connected(handle, -1);
            return handle;
        }
    }

#if LWIP_IPV6
    if (strchr(req->hostname,':')) {
        /* Resolve numeric scoped addresses outside the tcpip thread: lwIP's
         * interface-name lookup can itself call the core. The normal DNS
         * result mailbox remains the sole socket-state completion path. */
        struct addrinfo hints={.ai_family=AF_INET6,.ai_flags=AI_NUMERICHOST},*address=NULL;
        ip_addr_t literal;ip_addr_set_zero_ip6(&literal);
        bool ok=!getaddrinfo(req->hostname,NULL,&hints,&address) && address;
        if(ok){
            const struct sockaddr_in6 *v6=(const struct sockaddr_in6 *)address->ai_addr;
            memcpy(ip_2_ip6(&literal)->addr,&v6->sin6_addr,sizeof v6->sin6_addr);
            ip6_addr_set_zone(ip_2_ip6(&literal),v6->sin6_scope_id);
        }
        if(address)freeaddrinfo(address);
        wendynet_dns_found(req->hostname,ok ? &literal:NULL,req);
        return handle;
    }
#endif

    ESP_LOGI(TAG, "WendyNet (%s) resolving %s:%d (handle=%d)",
             sock_type == WENDYNET_SOCK_UDP ? "UDP" : "TCP",
             req->hostname, port, handle);

    /* Hand off to the tcpip thread. Once tcpip_callback returns ERR_OK,
     * ownership of req transfers to wendynet_kick_resolve →
     * wendynet_dns_found, which frees it. */
    err_t terr = tcpip_callback(wendynet_kick_resolve, req);
    if (terr != ERR_OK) {
        wendynet_lock();
        wendynet_socket_t *s = wendynet_find_socket_locked(handle);
        if (s) {
            wendynet_release_socket_locked(s);
        }
        wendynet_unlock();
        free(req);
        return -1;
    }
    return handle;
}

void wendy_net_set_mesh_connector(wendy_net_mesh_begin_fn begin)
{
    wendynet_lock(); s_wendynet_mesh_begin = begin; wendynet_unlock();
}
void wendy_net_set_mesh_resolver(wendy_net_mesh_resolve_fn resolve)
{
    wendynet_lock();s_wendynet_mesh_resolve=resolve;wendynet_unlock();
}

int wendy_net_mesh_connected(int handle, int fd)
{
    if (fd >= 0 && (fd >= FD_SETSIZE || wendynet_set_nonblocking(fd))) {
        close(fd); fd = -1;
    }
    wendynet_lock();
    wendynet_socket_t *sock = wendynet_find_socket_locked(handle);
    if (!sock || !sock->resolving || sock->closing) {
        wendynet_unlock(); if (fd >= 0) close(fd); return -1;
    }
    /* For canonical mesh connections, TLS setup completes before allocating
     * guest payload storage. Unused slots and failed handshakes retain none. */
    if(fd>=0 && wendynet_socket_buffers_locked(sock)){close(fd);fd=-1;}
    sock->resolving = false;
    sock->fd = fd;
    if (fd < 0) {
        sock->closed = sock->error = true;
        wendynet_notify_locked(WENDYNET_EVENT_ERROR | WENDYNET_EVENT_CLOSED);
    } else {
        wendynet_notify_locked(WENDYNET_EVENT_WRITE_READY);
    }
    wendynet_wake_locked(); wendynet_unlock(); return fd < 0 ? -1 : 0;
}

int wendy_net_mesh_datagram_connected(int handle,unsigned maximum)
{
    if(!maximum || maximum>WENDYNET_DATAGRAM_MAX)return -1;
    wendynet_lock();wendynet_socket_t *sock=wendynet_find_socket_locked(handle);
    if(!sock || sock->sock_type!=WENDYNET_SOCK_UDP || !sock->resolving ||
       sock->closing || sock->closed || sock->error){wendynet_unlock();return -1;}
    sock->resolving=false;sock->native_datagram=true;sock->datagram_limit=maximum;
    wendynet_notify_locked(WENDYNET_EVENT_WRITE_READY);wendynet_wake_locked();
    wendynet_unlock();return 0;
}

int wendy_net_mesh_datagram_receive(int handle,uint8_t **packet,size_t size)
{
    return wendy_net_mesh_datagram_receive_owned(handle,packet,size,NULL);
}

int wendy_net_mesh_datagram_receive_owned(int handle,uint8_t **packet,size_t size,
    wendy_net_packet_release_fn release)
{
    if(!packet || !*packet || size>WENDYNET_DATAGRAM_MAX)return -1;
    wendynet_lock();wendynet_socket_t *sock=wendynet_find_socket_locked(handle);
    if(!sock || !sock->native_datagram || size>sock->datagram_limit || sock->sock_type!=WENDYNET_SOCK_UDP ||
       sock->closing || sock->closed || sock->error){wendynet_unlock();return -1;}
    if(sock->rx_datagram){wendynet_unlock();return 0;}
    sock->rx=*packet;*packet=NULL;sock->rx_len=size;sock->rx_datagram=true;sock->rx_release=release;
    wendynet_notify_locked(WENDYNET_EVENT_READ_READY);wendynet_unlock();return 1;
}

static int guest_service_connect(uint16_t port,bool datagram,int *owner,bool wait)
{
    if(owner)*owner=-1;
    int handle = -1;
    wendynet_lock();
    for (unsigned i = 0; i < WENDYNET_MAX_LISTENERS; ++i) {
        wendynet_listener_t *listener = &s_wendynet_listeners[i];
        if (listener->used && listener->is_udp == datagram && listener->port == port) {
            handle = listener->handle;
            break;
        }
    }
    wendynet_unlock();
    if (handle < 0) return -1;

    int family=AF_INET;
#if LWIP_IPV6
    family=AF_INET6;
#endif
#if LWIP_IPV4
    /* lwIP's pbuf total length includes IP headers in 16 bits. An IPv6
     * loopback packet therefore cannot carry the complete 65507-byte app
     * message ceiling. IPv4 loopback can; the dual-stack guest listener and
     * the external, authenticated mesh endpoint are unchanged. */
    if(datagram)family=AF_INET;
#endif
    int fd = socket(family,datagram ? SOCK_DGRAM:SOCK_STREAM,0);
    if (fd < 0) return -1;
    if (fd >= FD_SETSIZE || wendynet_set_nonblocking(fd)) goto failed;
    struct sockaddr_storage address={0};socklen_t address_size;
#if LWIP_IPV6
    if(family==AF_INET6){
        struct sockaddr_in6 *v6=(struct sockaddr_in6 *)&address;
        v6->sin6_family=AF_INET6;v6->sin6_port=htons(port);
        v6->sin6_addr.s6_addr[15]=1;address_size=sizeof *v6;
    }else
#endif
    {
        struct sockaddr_in *v4=(struct sockaddr_in *)&address;
        v4->sin_family=AF_INET;v4->sin_port=htons(port);
        v4->sin_addr.s_addr=htonl(INADDR_LOOPBACK);address_size=sizeof *v4;
    }
    int result = connect(fd, (struct sockaddr *)&address, address_size);
    if (result && errno != EINPROGRESS) goto failed;
    if (result && wait) {
        fd_set writing;
        FD_ZERO(&writing); FD_SET(fd, &writing);
        struct timeval budget = {.tv_usec = 100000};
        int error = 0;
        socklen_t size = sizeof error;
        if (select(fd + 1, NULL, &writing, NULL, &budget) <= 0 ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) || error)
            goto failed;
    }
    /* The guest may have stopped while the local connection was opening. */
    wendynet_lock();
    wendynet_listener_t *listener = wendynet_find_listener_locked(handle);
    bool current = listener && listener->is_udp == datagram && listener->port == port;
    wendynet_unlock();
    if (!current) goto failed;
    if(owner)*owner=handle;
    return fd;
failed:
    close(fd);
    return -1;
}

int wendy_net_guest_service_connect(uint16_t port) {return guest_service_connect(port,false,NULL,true);}
int wendy_net_guest_datagram_connect(uint16_t port,int *owner) {return guest_service_connect(port,true,owner,true);}
unsigned wendy_net_guest_datagram_capacity(void) {return WENDYNET_DATAGRAM_MAX;}

int wendy_net_guest_datagram_deliver(int owner,int *association,uint8_t **packet,size_t size,unsigned maximum)
{
    return wendy_net_guest_datagram_deliver_owned(owner,association,packet,size,maximum,NULL);
}

int wendy_net_guest_datagram_deliver_owned(int owner,int *association,uint8_t **packet,size_t size,
    unsigned maximum,wendy_net_packet_release_fn release)
{
    if(!association || !packet || !*packet || !maximum || maximum>WENDYNET_DATAGRAM_MAX || size>maximum)return -1;
    wendynet_lock();
    wendynet_listener_t *listener=wendynet_find_listener_locked(owner);
    if(!listener || !listener->is_udp){wendynet_unlock();return -1;}
    wendynet_socket_t *sock=wendynet_find_socket_locked(*association);
    if(sock && (!sock->native_datagram || sock->listener_handle!=owner)){
        wendynet_unlock();return -1;
    }
    if(sock && sock->closing){wendynet_unlock();return 0;}
    if(!sock || sock->closed || sock->error){
        if(listener->accepted_count>=WENDYNET_ACCEPT_QUEUE_SIZE){wendynet_unlock();return 0;}
        sock=wendynet_alloc_socket_locked(-1);
        if(!sock){wendynet_unlock();return 0;}
        sock->sock_type=WENDYNET_SOCK_UDP_PEER;
        sock->native_datagram=true;sock->listener_handle=owner;sock->datagram_limit=maximum;
        if(!wendynet_listener_enqueue_locked(listener,sock->handle)){
            wendynet_release_socket_locked(sock);wendynet_unlock();return 0;
        }
        *association=sock->handle;
        wendynet_notify_locked(WENDYNET_EVENT_ACCEPT_READY);
    }
    if(sock->rx_datagram){wendynet_unlock();return 0;}
    sock->rx=*packet;*packet=NULL;sock->rx_len=size;sock->rx_datagram=true;sock->rx_release=release;
    wendynet_notify_locked(WENDYNET_EVENT_READ_READY);
    wendynet_unlock();return 1;
}

int wendy_net_guest_datagram_take(int association,uint8_t **packet,size_t *size)
{
    if(!packet || !size)return -1;
    *packet=NULL;*size=0;wendynet_lock();
    wendynet_socket_t *sock=wendynet_find_socket_locked(association);
    int result=0;
    if(sock && sock->native_datagram && !sock->closed && !sock->error &&
       sock->tx_datagram && sock->tx){
        *packet=sock->tx;*size=sock->tx_len;sock->tx=NULL;result=1;
        /* tx_datagram remains set while the native relay owns this packet. */
    }
    wendynet_unlock();return result;
}

void wendy_net_mesh_discard_pending_datagrams(void)
{
    wendynet_lock();
    bool released=false;
    for(unsigned i=0;i<WENDYNET_MAX_SOCKETS;i++){
        wendynet_socket_t *sock=&s_wendynet_sockets[i];
        if(sock->used && sock->native_datagram && sock->rx_datagram){
            wendynet_release_rx_locked(sock);released=true;
        }
    }
    if(released)wendynet_wake_locked();
    wendynet_unlock();
}

void wendy_net_guest_datagram_sent(int association)
{
    wendynet_lock();wendynet_socket_t *sock=wendynet_find_socket_locked(association);
    if(sock && sock->native_datagram && sock->tx_datagram && !sock->tx){
        sock->tx_datagram=false;sock->tx_len=0;
        wendynet_notify_locked(WENDYNET_EVENT_WRITE_READY);wendynet_wake_locked();
    }
    wendynet_unlock();
}

void wendy_net_guest_datagram_closed(int association)
{
    wendynet_lock();wendynet_socket_t *sock=wendynet_find_socket_locked(association);
    if(sock && sock->native_datagram){
        free(sock->tx);sock->tx=NULL;sock->tx_len=0;sock->tx_datagram=false;
        sock->closed=true;wendynet_notify_locked(WENDYNET_EVENT_CLOSED);
        wendynet_release_drained_closed_socket_locked(sock);wendynet_wake_locked();
    }
    wendynet_unlock();
}

int wendy_net_guest_listener_owner(uint16_t port,bool datagram)
{
    int handle=-1;wendynet_lock();
    for(unsigned i=0;i<WENDYNET_MAX_LISTENERS;i++){
        wendynet_listener_t *listener=&s_wendynet_listeners[i];
        if(listener->used && listener->is_udp==datagram && listener->port==port){handle=listener->handle;break;}
    }
    wendynet_unlock();return handle;
}

int wendy_net_guest_datagram_owner(uint16_t port)
{return wendy_net_guest_listener_owner(port,true);}
void wendy_net_set_service_catalog(wendy_net_service_fn callback)
{
    wendynet_lock();
    if(callback && callback!=s_service_catalog){
        if(!++s_service_epoch)++s_service_epoch;
    }
    s_service_catalog=callback;
    wendynet_unlock();
}
uint32_t wendy_net_service_epoch(void)
{
    wendynet_lock();uint32_t epoch=s_service_catalog ? s_service_epoch:0;
    wendynet_unlock();return epoch;
}
static int services_epoch_wrapper(wasm_exec_env_t env)
{(void)env;return (int)wendy_net_service_epoch();}
static int catalog_call(unsigned operation,const void *input,int size,char *out,int cap)
{
    if(!input || size<=0 || size>8192 || cap<0 || cap>65536 || (!out && cap))return -1;
    wendynet_lock();wendy_net_service_fn callback=s_service_catalog;wendynet_unlock();
    return callback ? callback(operation,input,(size_t)size,out,(size_t)cap):-2;
}
static int services_publish_wrapper(wasm_exec_env_t env,const void *spec,int size)
{(void)env;return catalog_call(1,spec,size,NULL,0);}
static int services_withdraw_wrapper(wasm_exec_env_t env,const void *service,int size)
{(void)env;return catalog_call(2,service,size,NULL,0);}
static int services_browse_wrapper(wasm_exec_env_t env,const void *type,int size,char *out,int cap)
{(void)env;return catalog_call(0,type,size,out,cap);}
static int services_browse_endpoints_wrapper(wasm_exec_env_t env,const void *type,int size,char *out,int cap)
{(void)env;return catalog_call(3,type,size,out,cap);}

bool wendy_net_mesh_socket_live(int handle)
{
    wendynet_lock();wendynet_socket_t *sock=wendynet_find_socket_locked(handle);
    bool live=sock && !sock->closed && !sock->error &&
        (!sock->closing || sock->tx_datagram);
    wendynet_unlock();return live;
}

static int wendynet_tcp_listen_wrapper(wasm_exec_env_t exec_env, int port, int backlog)
{
    (void)exec_env;
    return wendynet_listen_common(port, false, backlog);
}

static int wendynet_tcp_connect_wrapper(wasm_exec_env_t exec_env,
                                        const char *host, int host_len, int port)
{
    (void)exec_env;
    return wendynet_connect_common(host, host_len, port, WENDYNET_SOCK_TCP);
}

static int wendynet_udp_listen_wrapper(wasm_exec_env_t exec_env, int port)
{
    (void)exec_env;
    return wendynet_listen_common(port, true, 0);
}

static int wendynet_udp_connect_wrapper(wasm_exec_env_t exec_env,
                                        const char *host, int host_len, int port)
{
    (void)exec_env;
    return wendynet_connect_common(host, host_len, port, WENDYNET_SOCK_UDP);
}

static int wendynet_listener_accept_wrapper(wasm_exec_env_t exec_env, int listener_handle)
{
    (void)exec_env;
    wendynet_lock();
    wendynet_listener_t *listener = wendynet_find_listener_locked(listener_handle);
    if (!listener) {
        wendynet_unlock();
        return -1;
    }
    if (listener->accepted_count == 0) {
        wendynet_unlock();
        return 0;
    }
    int socket_handle = listener->accepted[listener->accepted_head];
    bool was_full = (listener->accepted_count >= WENDYNET_ACCEPT_QUEUE_SIZE);
    listener->accepted_head = (listener->accepted_head + 1) % WENDYNET_ACCEPT_QUEUE_SIZE;
    listener->accepted_count--;
    if (was_full) {
        wendynet_wake_locked();
    }
    wendynet_unlock();
    return socket_handle;
}

static int wendynet_listener_close_wrapper(wasm_exec_env_t exec_env, int listener_handle)
{
    (void)exec_env;
    wendynet_lock();
    wendynet_listener_t *listener = wendynet_find_listener_locked(listener_handle);
    if (!listener) {
        wendynet_unlock();
        return -1;
    }
    wendynet_close_listener_locked(listener);
    wendynet_wake_locked();
    wendynet_unlock();
    return 0;
}

/* Returns the local port the listener is bound to, in host byte order. Useful
 * when bind() was called with port 0 (OS-assigned ephemeral). Returns -1 if
 * the handle is unknown or the address cannot be retrieved. */
static int wendynet_listener_port_wrapper(wasm_exec_env_t exec_env, int listener_handle)
{
    (void)exec_env;
    wendynet_lock();
    wendynet_listener_t *listener = wendynet_find_listener_locked(listener_handle);
    if (!listener || listener->fd < 0) {
        wendynet_unlock();
        return -1;
    }
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(listener->fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        wendynet_unlock();
        return -1;
    }
    int port=-1;
    if(addr.ss_family==AF_INET)port=ntohs(((struct sockaddr_in *)&addr)->sin_port);
#if LWIP_IPV6
    if(addr.ss_family==AF_INET6)port=ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
#endif
    wendynet_unlock();
    return port;
}

static int wendynet_socket_status_wrapper(wasm_exec_env_t exec_env, int socket_handle)
{
    (void)exec_env;
    int status = 0;
    wendynet_lock();
    wendynet_socket_t *sock = wendynet_find_socket_locked(socket_handle);
    if (!sock) {
        wendynet_unlock();
        return -1;
    }
    if (sock->rx_len > 0 || sock->rx_datagram) {
        status |= WENDYNET_STATUS_READABLE;
    }
    /* TCP can accept bytes whenever there's buffer space. UDP is single-
     * datagram per slot so it's writable iff tx_len == 0. */
    bool tx_has_space = (sock->sock_type == WENDYNET_SOCK_TCP)
        ? (sock->tx_len < WENDYNET_BUFFER_SIZE)
        : !sock->tx_datagram;
    if (tx_has_space && !sock->resolving &&
        !sock->connecting && !sock->closing &&
        !sock->closed && !sock->error) {
        status |= WENDYNET_STATUS_WRITABLE;
    }
    if (sock->closing || sock->closed) {
        status |= WENDYNET_STATUS_CLOSED;
    }
    if (sock->error) {
        status |= WENDYNET_STATUS_ERROR;
    }
    wendynet_unlock();
    return status;
}

static int wendynet_socket_recv_wrapper(wasm_exec_env_t exec_env, int socket_handle, char *buf, int len)
{
    (void)exec_env;
    if (!buf || len <= 0) {
        return -1;
    }
    wendynet_lock();
    wendynet_socket_t *sock = wendynet_find_socket_locked(socket_handle);
    if (!sock) {
        wendynet_unlock();
        return -1;
    }
    if (sock->rx_len == 0 && !sock->rx_datagram) {
        int rc = (sock->resolving || sock->connecting || sock->closing
                  || sock->closed || sock->error) ? -2 : 0;
        if (rc == -2) {
            wendynet_release_drained_closed_socket_locked(sock);
        }
        wendynet_unlock();
        return rc;
    }
    size_t n = sock->rx_len < (size_t)len ? sock->rx_len : (size_t)len;
    bool need_wake;
    memcpy(buf, sock->rx, n);
    if (sock->sock_type == WENDYNET_SOCK_UDP
        || sock->sock_type == WENDYNET_SOCK_UDP_PEER) {
        /* Datagrams are atomic: consume the whole slot even if the caller's
         * buffer was smaller. Truncates the message (POSIX MSG_TRUNC). */
        wendynet_release_rx_locked(sock);
        /* A standalone UDP socket is only selected for read while its slot is
         * empty, so wake the task to re-arm its fd. A UDP_PEER has no own fd
         * (the listener fd is always selected), so no wake is needed. */
        need_wake = (sock->sock_type == WENDYNET_SOCK_UDP);
    } else {
        /* TCP: if the rx slot was full the task dropped the fd from readfds;
         * wake it to resume reading now that there's space. */
        need_wake = (sock->rx_len >= WENDYNET_BUFFER_SIZE);
        if (n < sock->rx_len) {
            memmove(sock->rx, sock->rx + n, sock->rx_len - n);
        }
        sock->rx_len -= n;
    }
    if (need_wake) {
        wendynet_wake_locked();
    }
    wendynet_unlock();
    return (int)n;
}

static int wendynet_socket_send_wrapper(wasm_exec_env_t exec_env, int socket_handle, const char *data, int len)
{
    (void)exec_env;
    if ((!data && len > 0) || len < 0) {
        return -1;
    }
    wendynet_lock();
    wendynet_socket_t *sock = wendynet_find_socket_locked(socket_handle);
    if (!sock) {
        wendynet_unlock();
        return -1;
    }
    if (sock->resolving || sock->connecting || sock->closing
        || sock->closed || sock->error) {
        wendynet_unlock();
        return -2;
    }
    /* UDP slots hold one datagram at a time. If a prior datagram is still
     * buffered, the guest must wait for the task to drain it before queuing
     * another (returns 0 = would block). The whole datagram must fit. */
    if (sock->sock_type == WENDYNET_SOCK_UDP
        || sock->sock_type == WENDYNET_SOCK_UDP_PEER) {
        if (sock->tx_datagram) {
            wendynet_unlock();
            return 0;
        }
        if ((size_t)len > WENDYNET_DATAGRAM_MAX ||
            (sock->native_datagram && (size_t)len>sock->datagram_limit)) {
            wendynet_unlock();
            return -1;
        }
        sock->tx=wendynet_buffer_alloc(len ? (size_t)len:1);
        if(!sock->tx){wendynet_unlock();return 0;}
        if(len)memcpy(sock->tx, data, (size_t)len);
        sock->tx_len = (size_t)len;
        sock->tx_datagram = true;
        sock->tx_deferred = false;
        sock->tx_started = xTaskGetTickCount();
        wendynet_wake_locked();
        wendynet_unlock();
        return len;
    }
    size_t space = WENDYNET_BUFFER_SIZE - sock->tx_len;
    if (space == 0) {
        wendynet_unlock();
        return 0;
    }
    size_t n = space < (size_t)len ? space : (size_t)len;
    bool was_empty = (sock->tx_len == 0);
    memcpy(sock->tx + sock->tx_len, data, n);
    sock->tx_len += n;
    if (was_empty) {
        wendynet_wake_locked();
    }
    wendynet_unlock();
    return (int)n;
}

static int wendynet_socket_close_wrapper(wasm_exec_env_t exec_env, int socket_handle)
{
    (void)exec_env;
    wendynet_lock();
    wendynet_socket_t *sock = wendynet_find_socket_locked(socket_handle);
    if (!sock) {
        wendynet_unlock();
        return -1;
    }
    /* UDP has no stream shutdown, but an already queued complete datagram
     * still belongs to this socket. Let the task send it before release,
     * including an empty datagram. UDP_PEER never closes the shared fd. */
    if (sock->sock_type == WENDYNET_SOCK_UDP
        || sock->sock_type == WENDYNET_SOCK_UDP_PEER) {
        if(sock->tx_datagram)sock->closing=true;
        else wendynet_release_socket_locked(sock);
        wendynet_wake_locked();
        wendynet_unlock();
        return 0;
    }
    // Peer already closed or errored: free the slot now rather than waiting
    // for the task to come around. Otherwise a guest that observes CLOSED via
    // socket_status (or via a callback) and then closes without first draining
    // rx would leak the slot until the next guest reset.
    if (sock->closed || sock->error) {
        wendynet_release_socket_locked(sock);
        wendynet_unlock();
        return 0;
    }
    sock->closing = true;
    // If there's nothing buffered to flush, abort the socket now so the task's
    // in-flight select() wakes immediately on this fd (recv→0/EOF, send→EPIPE).
    // If tx is still draining, the wakeup below tells the task to re-scan; it
    // will keep the fd in writefds, drain tx, then close on the next iteration.
    if (sock->tx_len == 0 && sock->fd >= 0) {
        shutdown(sock->fd, SHUT_RDWR);
    }
    wendynet_wake_locked();
    wendynet_unlock();
    return 0;
}

void wendy_net_guest_reset(void)
{
    wendynet_lock();
    wn_raw_reset(&s_raw);
    for (int i = 0; i < WENDYNET_MAX_LISTENERS; i++) {
        wendynet_close_listener_locked(&s_wendynet_listeners[i]);
    }
    for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
        wendynet_release_socket_locked(&s_wendynet_sockets[i]);
    }
    s_wendynet_handler_id = 0;
    s_wendynet_pending_bits = 0;
    s_wendynet_event_queued = false;
    s_wendynet_post_pending = false;
    wendynet_wake_locked();
    wendynet_unlock();
}

/* ── WiFi station/AP control ──────────────────────────────────────────── */

/* wifi_connect(ssid_ptr, ssid_len, pass_ptr, pass_len) -> 0 ok */
static int wifi_connect_wrapper(wasm_exec_env_t exec_env,
                                 const char *ssid, int ssid_len,
                                 const char *pass, int pass_len)
{
    wifi_config_t wifi_cfg = { 0 };

    int s = (ssid_len < 31) ? ssid_len : 31;
    int p = (pass_len < 63) ? pass_len : 63;
    memcpy(wifi_cfg.sta.ssid, ssid, s);
    if (pass && pass_len > 0) {
        memcpy(wifi_cfg.sta.password, pass, p);
    }

    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) return -1;

    err = esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);
    if (err != ESP_OK) return -1;

    err = wendy_wifi_set_station_enabled(true);
    return (err == ESP_OK) ? 0 : -1;
}

/* wifi_disconnect() -> 0 ok */
static int wifi_disconnect_wrapper(wasm_exec_env_t exec_env)
{
    esp_err_t err = wendy_wifi_set_station_enabled(false);
    return (err == ESP_OK) ? 0 : -1;
}

/* wifi_status() -> 0=disconnected, 1=connected, -1=error */
static int wifi_status_wrapper(wasm_exec_env_t exec_env)
{
    wifi_ap_record_t ap_info;
    esp_err_t err = esp_wifi_sta_get_ap_info(&ap_info);
    if (err == ESP_OK) return 1;
    return 0;
}

/* wifi_get_ip(buf_ptr, buf_len) -> bytes written or -1 */
static int wifi_get_ip_wrapper(wasm_exec_env_t exec_env, char *buf, int len)
{
    if (!buf || len < 16) return -1;

    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!netif) return -1;

    esp_netif_ip_info_t ip_info;
    esp_err_t err = esp_netif_get_ip_info(netif, &ip_info);
    if (err != ESP_OK) return -1;

    int written = snprintf(buf, len, IPSTR, IP2STR(&ip_info.ip));
    return (written < len) ? written : len - 1;
}

/* wifi_rssi() -> RSSI in dBm or 0 */
static int wifi_rssi_wrapper(wasm_exec_env_t exec_env)
{
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        return ap_info.rssi;
    }
    return 0;
}

/* wifi_ap_start(ssid_ptr, ssid_len, pass_ptr, pass_len, channel) -> 0 */
static int wifi_ap_start_wrapper(wasm_exec_env_t exec_env,
                                  const char *ssid, int ssid_len,
                                  const char *pass, int pass_len,
                                  int channel)
{
    wifi_config_t wifi_cfg = {
        .ap = {
            .channel = channel,
            .max_connection = 4,
            .authmode = (pass_len > 0) ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN,
        },
    };
    int s = (ssid_len < 31) ? ssid_len : 31;
    int p = (pass_len < 63) ? pass_len : 63;
    memcpy(wifi_cfg.ap.ssid, ssid, s);
    wifi_cfg.ap.ssid_len = s;
    if (pass && pass_len > 0) {
        memcpy(wifi_cfg.ap.password, pass, p);
    }

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_err_t err = esp_wifi_set_config(WIFI_IF_AP, &wifi_cfg);
    return (err == ESP_OK) ? 0 : -1;
}

/* wifi_ap_stop() -> 0 */
static int wifi_ap_stop_wrapper(wasm_exec_env_t exec_env)
{
    esp_wifi_set_mode(WIFI_MODE_STA);
    return 0;
}

/* ── BSD Sockets ──────────────────────────────────────────────────────── */

/* net_socket(domain, type, protocol) -> fd or -1 */
static int net_socket_wrapper(wasm_exec_env_t exec_env,
                               int domain, int type, int protocol)
{
    return wn_raw_socket(&s_raw,domain,type,protocol);
}

static int net_nonblocking_wrapper(wasm_exec_env_t env,int fd,int enabled)
{(void)env;return wn_raw_nonblocking(&s_raw,fd,enabled!=0);}
static int net_timeout_wrapper(wasm_exec_env_t env,int fd,int milliseconds)
{
    (void)env;if(milliseconds<0 || milliseconds>300000)return -1;
    return wn_raw_timeout(&s_raw,fd,(unsigned)milliseconds);
}
static int net_errno_wrapper(wasm_exec_env_t env){(void)env;return errno;}

/* net_connect(fd, ip_ptr, ip_len, port) -> 0 or -1 */
static int net_connect_wrapper(wasm_exec_env_t exec_env,
                                int fd, const char *ip, int ip_len, int port)
{
    if (!ip || ip_len <= 0 || ip_len >= 128 || port <= 0 || port > 65535) return -1;
    if(!wn_raw_owned(&s_raw,fd))return -1;
    char ip_buf[128],service[6];
    memcpy(ip_buf,ip,ip_len);ip_buf[ip_len]=0;
    snprintf(service,sizeof service,"%u",(unsigned)port);
    /* AI_NUMERICHOST also resolves scoped IPv6 interface names in lwIP.
     * This raw BSD API never performs mesh-service name translation. */
    struct addrinfo hints={.ai_family=AF_UNSPEC,.ai_flags=AI_NUMERICHOST},*address=NULL;
    if(getaddrinfo(ip_buf,service,&hints,&address) || !address)return -1;
    int result=wn_raw_connect(&s_raw,fd,address->ai_addr,address->ai_addrlen);
    int error=errno;freeaddrinfo(address);errno=error;return result;
}

/* net_bind(fd, port) -> 0 or -1 */
static int net_bind_wrapper(wasm_exec_env_t exec_env, int fd, int port)
{
    if(port < 0 || port > 65535)return -1;
    if(!wn_raw_owned(&s_raw,fd))return -1;
    struct sockaddr_storage current={0},addr={0};socklen_t size=sizeof current;
    if(getsockname(fd,(struct sockaddr *)&current,&size))return -1;
#if LWIP_IPV6
    if(current.ss_family==AF_INET6){
        struct sockaddr_in6 *v6=(struct sockaddr_in6 *)&addr;
        v6->sin6_family=AF_INET6;v6->sin6_port=htons((uint16_t)port);
        return bind(fd,(struct sockaddr *)v6,sizeof *v6);
    }
#endif
    struct sockaddr_in *v4=(struct sockaddr_in *)&addr;
    v4->sin_family=AF_INET;v4->sin_port=htons((uint16_t)port);
    return bind(fd,(struct sockaddr *)v4,sizeof *v4);
}

/* Local port after bind(0), for ordinary ephemeral guest listeners. */
static int net_local_port_wrapper(wasm_exec_env_t env,int fd)
{
    (void)env;if(!wn_raw_owned(&s_raw,fd))return -1;
    struct sockaddr_storage address={0};socklen_t size=sizeof address;
    if(getsockname(fd,(struct sockaddr *)&address,&size))return -1;
#if LWIP_IPV6
    if(address.ss_family==AF_INET6)return ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
#endif
    return address.ss_family==AF_INET ? ntohs(((struct sockaddr_in *)&address)->sin_port):-1;
}

/* net_listen(fd, backlog) -> 0 or -1 */
static int net_listen_wrapper(wasm_exec_env_t exec_env, int fd, int backlog)
{
    return wn_raw_owned(&s_raw,fd) ? listen(fd,backlog):-1;
}

/* net_accept(fd) -> new_fd or -1 */
static int net_accept_wrapper(wasm_exec_env_t exec_env, int fd)
{
    return wn_raw_accept(&s_raw,fd);
}

/* net_send(fd, data_ptr, data_len) -> bytes sent */
static int net_send_wrapper(wasm_exec_env_t exec_env,
                             int fd, const char *data, int len)
{
    if ((!data && len>0) || len<0) return -1;
    return wn_raw_send(&s_raw,fd,data,(size_t)len);
}

/* net_recv(fd, buf_ptr, buf_len) -> bytes received */
static int net_recv_wrapper(wasm_exec_env_t exec_env,
                             int fd, char *buf, int len)
{
    if (!buf || len <= 0) return -1;
    return wn_raw_recv(&s_raw,fd,buf,(size_t)len);
}

/* net_close(fd) -> 0 */
static int net_close_wrapper(wasm_exec_env_t exec_env, int fd)
{
    return wn_raw_close(&s_raw,fd);
}

/* ── DNS ──────────────────────────────────────────────────────────────── */

/* dns_resolve(hostname_ptr, hostname_len, result_buf_ptr, result_buf_len) -> bytes written or -1 */
static int dns_resolve_wrapper(wasm_exec_env_t exec_env,
                                const char *hostname, int hostname_len,
                                char *result_buf, int result_len)
{
    if (!hostname || hostname_len <= 0 || !result_buf || result_len < 16) return -1;

    char host_buf[128];
    int l = (hostname_len < 127) ? hostname_len : 127;
    memcpy(host_buf, hostname, l);
    host_buf[l] = '\0';

#if LWIP_IPV6
    wendynet_lock();wendy_net_mesh_resolve_fn resolve=s_wendynet_mesh_resolve;wendynet_unlock();
    uint8_t mesh_address[16];
    int mesh=resolve ? resolve(host_buf,mesh_address):0;
    if(mesh){
        return mesh>0 && inet_ntop(AF_INET6,mesh_address,result_buf,result_len)
            ? (int)strlen(result_buf):-1;
    }
#endif
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *res = NULL;

    int rc = getaddrinfo(host_buf, NULL, &hints, &res);
    if (rc != 0 || !res) return -1;

    const void *bytes=NULL;
    if(res->ai_family==AF_INET)bytes=&((struct sockaddr_in *)res->ai_addr)->sin_addr;
#if LWIP_IPV6
    if(res->ai_family==AF_INET6)bytes=&((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
#endif
    bool ok=bytes && inet_ntop(res->ai_family,bytes,result_buf,result_len);
    freeaddrinfo(res);
    return ok ? (int)strlen(result_buf) : -1;
}

/* ── TLS (mbedTLS) ────────────────────────────────────────────────────── */

/* tls_connect(host_ptr, host_len, port) -> fd or -1 */
static int tls_connect_wrapper(wasm_exec_env_t exec_env,
                                const char *host, int host_len, int port)
{
    /* This legacy guest API has no TLS context/descriptor implementation.
     * Keep the ABI available, but do not turn a TLS request into plain TCP.
     * Native Wendy Net service/carrier TLS uses its own implemented paths. */
    (void)exec_env;
    (void)host;
    (void)host_len;
    (void)port;
    ESP_LOGW(TAG, "tls_connect: generic guest TLS is not implemented");
    return -1;
}

static NativeSymbol s_net_symbols[] = {
    /* WiFi */
    { "wifi_connect",    (void *)wifi_connect_wrapper,    "(*~*~)i",    NULL },
    { "wifi_disconnect", (void *)wifi_disconnect_wrapper, "()i",        NULL },
    { "wifi_status",     (void *)wifi_status_wrapper,     "()i",        NULL },
    { "wifi_get_ip",     (void *)wifi_get_ip_wrapper,     "(*~)i",      NULL },
    { "wifi_rssi",       (void *)wifi_rssi_wrapper,       "()i",        NULL },
    { "wifi_ap_start",   (void *)wifi_ap_start_wrapper,   "(*~*~i)i",   NULL },
    { "wifi_ap_stop",    (void *)wifi_ap_stop_wrapper,    "()i",        NULL },
    /* Sockets */
    { "net_socket",      (void *)net_socket_wrapper,      "(iii)i",     NULL },
    { "net_set_nonblocking", (void *)net_nonblocking_wrapper, "(ii)i", NULL },
    { "net_set_timeout", (void *)net_timeout_wrapper, "(ii)i", NULL },
    { "net_errno",       (void *)net_errno_wrapper, "()i", NULL },
    { "net_connect",     (void *)net_connect_wrapper,     "(i*~i)i",    NULL },
    { "net_bind",        (void *)net_bind_wrapper,        "(ii)i",      NULL },
    { "net_local_port",  (void *)net_local_port_wrapper,  "(i)i",       NULL },
    { "net_listen",      (void *)net_listen_wrapper,      "(ii)i",      NULL },
    { "net_accept",      (void *)net_accept_wrapper,      "(i)i",       NULL },
    { "net_send",        (void *)net_send_wrapper,        "(i*~)i",     NULL },
    { "net_recv",        (void *)net_recv_wrapper,        "(i*~)i",     NULL },
    { "net_close",       (void *)net_close_wrapper,       "(i)i",       NULL },
    /* WendyNet async TCP/UDP */
    { "wendynet_init",           (void *)wendynet_init_wrapper,           "(i)i",    NULL },
    { "wendynet_drain_events",   (void *)wendynet_drain_events_wrapper,   "()i",     NULL },
    { "wendynet_tcp_listen",     (void *)wendynet_tcp_listen_wrapper,     "(ii)i",   NULL },
    { "wendynet_tcp_connect",    (void *)wendynet_tcp_connect_wrapper,    "(*~i)i",  NULL },
    { "wendynet_udp_listen",     (void *)wendynet_udp_listen_wrapper,     "(i)i",    NULL },
    { "wendynet_udp_connect",    (void *)wendynet_udp_connect_wrapper,    "(*~i)i",  NULL },
    { "wendynet_listener_accept",(void *)wendynet_listener_accept_wrapper,"(i)i",    NULL },
    { "wendynet_listener_close", (void *)wendynet_listener_close_wrapper, "(i)i",    NULL },
    { "wendynet_listener_port",  (void *)wendynet_listener_port_wrapper,  "(i)i",    NULL },
    { "wendynet_socket_status",  (void *)wendynet_socket_status_wrapper,  "(i)i",    NULL },
    { "wendynet_socket_recv",    (void *)wendynet_socket_recv_wrapper,    "(i*~)i",  NULL },
    { "wendynet_socket_send",    (void *)wendynet_socket_send_wrapper,    "(i*~)i",  NULL },
    { "wendynet_socket_close",   (void *)wendynet_socket_close_wrapper,   "(i)i",    NULL },
    /* DNS */
    { "services_epoch", (void *)services_epoch_wrapper, "()i", NULL },
    { "services_publish", (void *)services_publish_wrapper, "(*~)i", NULL },
    { "services_withdraw", (void *)services_withdraw_wrapper, "(*~)i", NULL },
    { "services_browse", (void *)services_browse_wrapper, "(*~*~)i", NULL },
    { "services_browse_endpoints", (void *)services_browse_endpoints_wrapper, "(*~*~)i", NULL },
    { "dns_resolve",     (void *)dns_resolve_wrapper,     "(*~*~)i",    NULL },
    /* TLS */
    { "tls_connect",     (void *)tls_connect_wrapper,     "(*~i)i",     NULL },
    { "tls_send",        (void *)net_send_wrapper,        "(i*~)i",     NULL },
    { "tls_recv",        (void *)net_recv_wrapper,        "(i*~)i",     NULL },
    { "tls_close",       (void *)net_close_wrapper,       "(i)i",       NULL },
};

int wendy_net_export_init(void)
{
    // Create the mutex eagerly
    if (!s_wendynet_lock) {
        s_wendynet_lock = xSemaphoreCreateMutex();
        if (!s_wendynet_lock) {
            ESP_LOGE(TAG, "failed to create wendynet mutex");
            return -1;
        }
    }
    if (!wasm_runtime_register_natives("wendy",
                                       s_net_symbols,
                                       sizeof(s_net_symbols) / sizeof(s_net_symbols[0]))) {
        ESP_LOGE(TAG, "failed to register net natives");
        return -1;
    }
    ESP_LOGI(TAG, "networking exports registered (%d functions)",
             (int)(sizeof(s_net_symbols) / sizeof(s_net_symbols[0])));
    return 0;
}

int wendy_net_guest_service_begin(uint16_t port) {return guest_service_connect(port,false,NULL,false);}
