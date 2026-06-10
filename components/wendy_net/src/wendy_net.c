#include "wendy_net.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/select.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_vfs_eventfd.h"
#include "wasm_export.h"
#include "wendy_safety.h"

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
    struct sockaddr_in peer_addr; /* for UDP_PEER: remote address (valid iff UDP_PEER) */
    bool resolving;
    bool connecting;
    bool closing;
    bool closed;
    bool error;
    uint16_t pending_port;
    uint8_t rx[WENDYNET_BUFFER_SIZE];
    size_t rx_len;
    uint8_t tx[WENDYNET_BUFFER_SIZE];
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
    bool is_udp;                  /* unconnected datagram listener; demux by source addr */
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
static WENDYNET_BSS_ATTR wendynet_socket_t s_wendynet_sockets[WENDYNET_MAX_SOCKETS];
static WENDYNET_BSS_ATTR wendynet_listener_t s_wendynet_listeners[WENDYNET_MAX_LISTENERS];

/* Scratch buffer for the UDP listener demux recvfrom. The wendynet task is a
 * singleton and only touches this under wendynet_lock, so a single static
 * buffer is safe. */
static WENDYNET_BSS_ATTR uint8_t s_wendynet_udp_pkt[WENDYNET_BUFFER_SIZE];

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

static wendynet_socket_t *wendynet_alloc_socket_locked(int fd)
{
    for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
        if (!s_wendynet_sockets[i].used) {
            memset(&s_wendynet_sockets[i], 0, sizeof(s_wendynet_sockets[i]));
            s_wendynet_sockets[i].used = true;
            s_wendynet_sockets[i].handle = wendynet_alloc_handle_locked();
            s_wendynet_sockets[i].fd = fd;
            return &s_wendynet_sockets[i];
        }
    }
    return NULL;
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
    memset(sock, 0, sizeof(*sock));
    sock->fd = -1;
}

static bool wendynet_sockaddr_equal(const struct sockaddr_in *a,
                                     const struct sockaddr_in *b)
{
    return a->sin_family == b->sin_family
        && a->sin_port == b->sin_port
        && a->sin_addr.s_addr == b->sin_addr.s_addr;
}

static wendynet_socket_t *wendynet_find_udp_peer_locked(int listener_handle,
                                                         const struct sockaddr_in *addr)
{
    for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
        wendynet_socket_t *sock = &s_wendynet_sockets[i];
        if (sock->used
            && sock->sock_type == WENDYNET_SOCK_UDP_PEER
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
            if (sock->rx_len == 0) {
                wendynet_release_socket_locked(sock);
            }
        }
    }
}

static void wendynet_release_drained_closed_socket_locked(wendynet_socket_t *sock)
{
    if (!sock || !sock->used || sock->rx_len != 0) {
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
        if (sock->tx_len > 0 && !sock->closed && !sock->error) {
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
    err_t err = dns_gethostbyname(req->hostname, &addr,
                                   wendynet_dns_found, req);
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

    bool is_udp = (sock->sock_type == WENDYNET_SOCK_UDP);
    int sock_kind = is_udp ? SOCK_DGRAM : SOCK_STREAM;
    int proto = is_udp ? IPPROTO_UDP : IPPROTO_IP;

    int fd = socket(AF_INET, sock_kind, proto);
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

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(sock->pending_port),
    };
    addr.sin_addr.s_addr = ip4_addr_get_u32(ip_2_ip4(ipaddr));

    sock->fd = fd;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
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

        /* UDP sends are eager — there's no connection-level backpressure to
         * wait for. Drain every pending UDP tx queue before sleeping in
         * select(); each UDP slot holds at most one datagram. */
        for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
            wendynet_socket_t *sock = &s_wendynet_sockets[i];
            if (!sock->used || sock->tx_len == 0
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
                    dest_len = sizeof(sock->peer_addr);
                }
                /* listener gone: out_fd stays -1, datagram is dropped below */
            } else {
                continue;
            }

            if (out_fd >= 0) {
                int n = dest
                    ? sendto(out_fd, sock->tx, sock->tx_len, 0, dest, dest_len)
                    : send(out_fd, sock->tx, sock->tx_len, 0);
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    sock->error = true;
                    wendynet_notify_locked(WENDYNET_EVENT_ERROR | WENDYNET_EVENT_CLOSED);
                }
            }
            /* Whether the send succeeded, returned would-block, or had nowhere
             * to go, drop the datagram (UDP semantics) and let the guest
             * enqueue another. */
            sock->tx_len = 0;
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
                : (sock->rx_len == 0);
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

        // Block indefinitely. Either a socket fd becomes ready, or another
        // thread signals s_wakeup_fd to indicate the table has changed.
        int rc = select(max_fd + 1, &readfds, &writefds, NULL, NULL);
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

        for (int i = 0; i < WENDYNET_MAX_LISTENERS; i++) {
            wendynet_listener_t *listener = &s_wendynet_listeners[i];
            if (!listener->used || listener->fd < 0 || !FD_ISSET(listener->fd, &readfds)) {
                continue;
            }

            if (listener->is_udp) {
                /* UDP listener: recvfrom each datagram and demux by source
                 * address. Always drain to EAGAIN so established peers keep
                 * receiving regardless of accept-queue pressure. A datagram
                 * from a new source spawns a UDP_PEER association and enqueues
                 * it for accept(); if there's no accept-queue room or no free
                 * socket slot, that datagram is dropped (spilled) but draining
                 * continues. Existing peers receive into their per-peer rx slot
                 * (single datagram at a time; drops on full rx are acceptable
                 * UDP semantics). */
                for (;;) {
                    struct sockaddr_in src;
                    socklen_t src_len = sizeof(src);
                    int n = recvfrom(listener->fd, s_wendynet_udp_pkt,
                                     sizeof(s_wendynet_udp_pkt), 0,
                                     (struct sockaddr *)&src, &src_len);
                    if (n < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            wendynet_notify_locked(WENDYNET_EVENT_ERROR);
                        }
                        break;
                    }

                    wendynet_socket_t *peer =
                        wendynet_find_udp_peer_locked(listener->handle, &src);
                    if (!peer) {
                        /* New association. Spill (drop this datagram, keep
                         * draining) if we can't admit one right now — never
                         * stop reading, or established peers would starve. */
                        if (listener->accepted_count >= WENDYNET_ACCEPT_QUEUE_SIZE) {
                            continue;
                        }
                        peer = wendynet_alloc_socket_locked(-1);
                        if (!peer) {
                            continue;  /* socket table full: spill */
                        }
                        peer->sock_type = WENDYNET_SOCK_UDP_PEER;
                        peer->listener_handle = listener->handle;
                        peer->peer_addr = src;

                        if (!wendynet_listener_enqueue_locked(listener, peer->handle)) {
                            wendynet_release_socket_locked(peer);
                            continue;  /* spill */
                        }
                        wendynet_notify_locked(WENDYNET_EVENT_ACCEPT_READY);
                    }

                    if (peer->rx_len == 0 && n > 0) {
                        /* n <= sizeof(s_wendynet_udp_pkt) == WENDYNET_BUFFER_SIZE,
                         * the rx slot size, so the whole datagram fits. */
                        memcpy(peer->rx, s_wendynet_udp_pkt, (size_t)n);
                        peer->rx_len = (size_t)n;
                        wendynet_notify_locked(WENDYNET_EVENT_READ_READY);
                    }
                    /* If rx_len > 0 the guest hasn't drained yet — drop. */
                }
                continue;
            }

            for (;;) {
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                int client_fd = accept(listener->fd, (struct sockaddr *)&client_addr, &addr_len);
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
                    && sock->rx_len == 0
                    && FD_ISSET(sock->fd, &readfds)) {
                    int n = recv(sock->fd, sock->rx, WENDYNET_BUFFER_SIZE, 0);
                    if (n > 0) {
                        sock->rx_len = (size_t)n;
                        wendynet_notify_locked(WENDYNET_EVENT_READ_READY);
                    } else if (n < 0
                               && errno != EAGAIN && errno != EWOULDBLOCK) {
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
        static bool s_eventfd_registered = false;
        if (!s_eventfd_registered) {
            esp_vfs_eventfd_config_t cfg = ESP_VFS_EVENTD_CONFIG_DEFAULT();
            esp_err_t err = esp_vfs_eventfd_register(&cfg);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "esp_vfs_eventfd_register: %s (continuing)",
                         esp_err_to_name(err));
            }
            s_eventfd_registered = true;
        }
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

    int fd = socket(AF_INET, is_udp ? SOCK_DGRAM : SOCK_STREAM,
                    is_udp ? IPPROTO_UDP : IPPROTO_IP);
    if (fd < 0) {
        return -1;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (wendynet_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
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
    wendynet_unlock();

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
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(listener->fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        wendynet_unlock();
        return -1;
    }
    int port = (int)ntohs(addr.sin_port);
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
    if (sock->rx_len > 0) {
        status |= WENDYNET_STATUS_READABLE;
    }
    /* TCP can accept bytes whenever there's buffer space. UDP is single-
     * datagram per slot so it's writable iff tx_len == 0. */
    bool tx_has_space = (sock->sock_type == WENDYNET_SOCK_TCP)
        ? (sock->tx_len < WENDYNET_BUFFER_SIZE)
        : (sock->tx_len == 0);
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
    if (sock->rx_len == 0) {
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
        sock->rx_len = 0;
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
    if (!data || len <= 0) {
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
        if (sock->tx_len > 0) {
            wendynet_unlock();
            return 0;
        }
        if ((size_t)len > WENDYNET_BUFFER_SIZE) {
            wendynet_unlock();
            return -1;
        }
        memcpy(sock->tx, data, (size_t)len);
        sock->tx_len = (size_t)len;
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
    /* UDP slots have no connection state to drain or shut down. UDP_PEER
     * additionally has no own fd (it lives on the listener's fd). Just
     * release the slot. */
    if (sock->sock_type == WENDYNET_SOCK_UDP
        || sock->sock_type == WENDYNET_SOCK_UDP_PEER) {
        wendynet_release_socket_locked(sock);
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

    err = esp_wifi_connect();
    return (err == ESP_OK) ? 0 : -1;
}

/* wifi_disconnect() -> 0 ok */
static int wifi_disconnect_wrapper(wasm_exec_env_t exec_env)
{
    esp_err_t err = esp_wifi_disconnect();
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
    return socket(domain, type, protocol);
}

/* net_connect(fd, ip_ptr, ip_len, port) -> 0 or -1 */
static int net_connect_wrapper(wasm_exec_env_t exec_env,
                                int fd, const char *ip, int ip_len, int port)
{
    if (!ip || ip_len <= 0) return -1;

    char ip_buf[48];
    int l = (ip_len < 47) ? ip_len : 47;
    memcpy(ip_buf, ip, l);
    ip_buf[l] = '\0';

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    inet_pton(AF_INET, ip_buf, &addr.sin_addr);

    return connect(fd, (struct sockaddr *)&addr, sizeof(addr));
}

/* net_bind(fd, port) -> 0 or -1 */
static int net_bind_wrapper(wasm_exec_env_t exec_env, int fd, int port)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    return bind(fd, (struct sockaddr *)&addr, sizeof(addr));
}

/* net_listen(fd, backlog) -> 0 or -1 */
static int net_listen_wrapper(wasm_exec_env_t exec_env, int fd, int backlog)
{
    return listen(fd, backlog);
}

/* net_accept(fd) -> new_fd or -1 */
static int net_accept_wrapper(wasm_exec_env_t exec_env, int fd)
{
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    return accept(fd, (struct sockaddr *)&client_addr, &addr_len);
}

/* net_send(fd, data_ptr, data_len) -> bytes sent */
static int net_send_wrapper(wasm_exec_env_t exec_env,
                             int fd, const char *data, int len)
{
    if (!data || len <= 0) return -1;
    return send(fd, data, len, 0);
}

/* net_recv(fd, buf_ptr, buf_len) -> bytes received */
static int net_recv_wrapper(wasm_exec_env_t exec_env,
                             int fd, char *buf, int len)
{
    if (!buf || len <= 0) return -1;
    return recv(fd, buf, len, 0);
}

/* net_close(fd) -> 0 */
static int net_close_wrapper(wasm_exec_env_t exec_env, int fd)
{
    return close(fd);
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

    struct addrinfo hints = { .ai_family = AF_INET };
    struct addrinfo *res = NULL;

    int rc = getaddrinfo(host_buf, NULL, &hints, &res);
    if (rc != 0 || !res) return -1;

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    const char *ip = inet_ntoa(addr->sin_addr);
    int written = snprintf(result_buf, result_len, "%s", ip);
    freeaddrinfo(res);

    return (written < result_len) ? written : result_len - 1;
}

/* ── TLS (mbedTLS) ────────────────────────────────────────────────────── */

/* tls_connect(host_ptr, host_len, port) -> fd or -1 */
static int tls_connect_wrapper(wasm_exec_env_t exec_env,
                                const char *host, int host_len, int port)
{
    /* Simplified: use a regular socket for now.
     * Full mbedTLS integration would wrap the socket with TLS context. */
    ESP_LOGW(TAG, "tls_connect: mbedTLS not yet integrated, using plain socket");

    char host_buf[128];
    int l = (host_len < 127) ? host_len : 127;
    memcpy(host_buf, host, l);
    host_buf[l] = '\0';

    /* Resolve hostname */
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host_buf, NULL, &hints, &res) != 0 || !res) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    struct sockaddr_in addr;
    memcpy(&addr, res->ai_addr, sizeof(addr));
    addr.sin_port = htons(port);
    freeaddrinfo(res);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* tls_send / tls_recv / tls_close reuse net_send/recv/close for now */

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
    { "net_connect",     (void *)net_connect_wrapper,     "(i*~i)i",    NULL },
    { "net_bind",        (void *)net_bind_wrapper,        "(ii)i",      NULL },
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
