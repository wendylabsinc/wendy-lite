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

typedef struct {
    bool used;
    int handle;
    int fd;
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
    if (sock->fd >= 0) {
        close(sock->fd);
    }
    memset(sock, 0, sizeof(*sock));
    sock->fd = -1;
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

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
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
        if (errno == EINPROGRESS) {
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
        for (int i = 0; i < WENDYNET_MAX_LISTENERS; i++) {
            if (s_wendynet_listeners[i].used && s_wendynet_listeners[i].fd >= 0 &&
                s_wendynet_listeners[i].accepted_count < WENDYNET_ACCEPT_QUEUE_SIZE) {
                FD_SET(s_wendynet_listeners[i].fd, &readfds);
                if (s_wendynet_listeners[i].fd > max_fd) {
                    max_fd = s_wendynet_listeners[i].fd;
                }
            }
        }
        for (int i = 0; i < WENDYNET_MAX_SOCKETS; i++) {
            wendynet_socket_t *sock = &s_wendynet_sockets[i];
            if (!sock->used || sock->fd < 0) {
                continue;
            }
            if (!sock->connecting && !sock->closed && !sock->closing &&
                !sock->error && sock->rx_len < WENDYNET_BUFFER_SIZE) {
                FD_SET(sock->fd, &readfds);
                if (sock->fd > max_fd) {
                    max_fd = sock->fd;
                }
            }
            if (!sock->closed && !sock->error &&
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
    if (!s_wendynet_lock) {
        s_wendynet_lock = xSemaphoreCreateMutex();
        if (!s_wendynet_lock) {
            return -1;
        }
    }
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

static int wendynet_tcp_listen_wrapper(wasm_exec_env_t exec_env, int port, int backlog)
{
    (void)exec_env;
    if (port <= 0 || port > 65535) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
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
    if (listen(fd, backlog > 0 ? backlog : WENDYNET_ACCEPT_QUEUE_SIZE) != 0) {
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
            int handle = s_wendynet_listeners[i].handle;
            wendynet_wake_locked();
            wendynet_unlock();
            ESP_LOGI(TAG, "WendyNet listening on TCP port %d (handle=%d)", port, handle);
            return handle;
        }
    }

    wendynet_unlock();
    close(fd);
    return -1;
}

static int wendynet_tcp_connect_wrapper(wasm_exec_env_t exec_env,
                                        const char *host, int host_len, int port)
{
    (void)exec_env;
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
    sock->resolving = true;
    sock->pending_port = (uint16_t)port;
    int handle = sock->handle;
    req->handle = handle;
    wendynet_unlock();

    ESP_LOGI(TAG, "WendyNet resolving %s:%d (handle=%d)",
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
    if (sock->tx_len < WENDYNET_BUFFER_SIZE && !sock->resolving &&
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
    bool was_full = (sock->rx_len >= WENDYNET_BUFFER_SIZE);
    memcpy(buf, sock->rx, n);
    if (n < sock->rx_len) {
        memmove(sock->rx, sock->rx + n, sock->rx_len - n);
    }
    sock->rx_len -= n;
    if (was_full) {
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
    /* WendyNet async TCP */
    { "wendynet_init",           (void *)wendynet_init_wrapper,           "(i)i",    NULL },
    { "wendynet_drain_events",   (void *)wendynet_drain_events_wrapper,   "()i",     NULL },
    { "wendynet_tcp_listen",     (void *)wendynet_tcp_listen_wrapper,     "(ii)i",   NULL },
    { "wendynet_tcp_connect",    (void *)wendynet_tcp_connect_wrapper,    "(*~i)i",  NULL },
    { "wendynet_listener_accept",(void *)wendynet_listener_accept_wrapper,"(i)i",    NULL },
    { "wendynet_listener_close", (void *)wendynet_listener_close_wrapper, "(i)i",    NULL },
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
