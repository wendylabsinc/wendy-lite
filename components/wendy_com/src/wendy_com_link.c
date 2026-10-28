
#include "wendy_com_link.h"
#include "wendy_com_uart.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "esp_vfs_eventfd.h"
#include "mbedtls/ssl.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <sys/select.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>


//--- literals ---//

#define WCOM_TASK_STACK     8192

// A vanished peer may leave its socket open until TCP's much longer retry
// limit. Bound queued writes so their done handlers can return borrowed
// sensor buffers. Successful writes renew this deadline, even during OTA.
#define WCOM_TX_STALL_TIMEOUT_US (15LL * 1000 * 1000)
/* Routed TCP may pause while a physical carrier and its signed route return.
 * The queue/buffer limits stay the same; this only bounds their holding time. */
#define WCOM_TX_ROUTED_STALL_TIMEOUT_US (45LL * 1000 * 1000)

#define WENDY_COM_LINK_ERR_UNKNOWN    -1
#define WENDY_COM_LINK_ERR_WANT_READ  -2
#define WENDY_COM_LINK_ERR_WANT_WRITE -3


//--- types ---//

enum link_type {
    LINK_TYPE_NONE = 0,
    LINK_TYPE_TLS,
    LINK_TYPE_UART,
    LINK_TYPE_STREAM,
    LINK_TYPE_SOCKET,
};

struct wcom_link {
    int id;
    enum wcom_link_state state;
    enum wcom_link_permission permission;
    enum link_type type;
    union {
        esp_tls_t *tls;
        wendy_com_uart_t *uart;
        const struct wcom_stream_ops *ops;
    };
    void *stream_ctx;                  // LINK_TYPE_STREAM only
    wcom_interruption_handler_t interruption_handler;
    int fd;
    struct wcom_tx_chunk *tx_chunk_first;
    struct wcom_tx_chunk *tx_chunk_last;
    size_t tx_chunk_offset;            // bytes already sent from tx_chunk_first
    int64_t tx_deadline_us;            // renewed whenever a queued write progresses
    struct wcom_rx_chunk *rx_chunk_first;
    struct wcom_rx_chunk *rx_chunk_last;
    size_t rx_chunk_offset;            // bytes already received into rx_chunk_first
    bool rx_need_write;                // last conn_read() returned WANT_WRITE
    bool rx_tls_readable;              // TLS layer may have buffered bytes not yet consumed
    bool tx_need_read;                 // last conn_write() returned WANT_READ
    bool routed;
};


//--- globals ---//

static const char *TAG = "wcom_hub";
static struct wcom_link _links[WCOM_LINK_COUNT];
static _Atomic(int) _wakeup_efd = -1;
static TaskHandle_t _main_task = NULL;
static int _link_id_generator = 0;
static _Atomic(struct wcom_operation *) _op_queue_head;
static struct wcom_state_change_handler *_state_change_handler_first;
static struct wcom_state_change_handler *_state_change_handler_last;


//--- internal functions ---//

static ssize_t _link_read(struct wcom_link *ch, void *buf, size_t len)
{
    ssize_t n;
    if (ch->type == LINK_TYPE_STREAM || ch->type == LINK_TYPE_SOCKET) {
        n = ch->ops->read(ch->stream_ctx, buf, len);
        if (n == WCOM_STREAM_ERR_WANT_READ)  return WENDY_COM_LINK_ERR_WANT_READ;
        if (n == WCOM_STREAM_ERR_WANT_WRITE) return WENDY_COM_LINK_ERR_WANT_WRITE;
        if (n < 0)                           return WENDY_COM_LINK_ERR_UNKNOWN;
    } else if (ch->type == LINK_TYPE_TLS) {
        n = esp_tls_conn_read(ch->tls, buf, len);
        if (n == MBEDTLS_ERR_SSL_WANT_READ)  return WENDY_COM_LINK_ERR_WANT_READ;
        if (n == MBEDTLS_ERR_SSL_WANT_WRITE) return WENDY_COM_LINK_ERR_WANT_WRITE;
        if (n < 0)                           return WENDY_COM_LINK_ERR_UNKNOWN;
    } else {
        n = wendy_com_uart_read(ch->uart, buf, len);
        if (n == WENDY_COM_UART_ERR_WANT_READ)  return WENDY_COM_LINK_ERR_WANT_READ;
        if (n == WENDY_COM_UART_ERR_WANT_WRITE) return WENDY_COM_LINK_ERR_WANT_WRITE;
        if (n < 0)                              return WENDY_COM_LINK_ERR_UNKNOWN;
    }
    return n;
}

static ssize_t _link_write(struct wcom_link *ch, const void *data, size_t len)
{
    ssize_t n;
    if (ch->type == LINK_TYPE_STREAM || ch->type == LINK_TYPE_SOCKET) {
        n = ch->ops->write(ch->stream_ctx, data, len);
        if (n == WCOM_STREAM_ERR_WANT_READ)  return WENDY_COM_LINK_ERR_WANT_READ;
        if (n == WCOM_STREAM_ERR_WANT_WRITE) return WENDY_COM_LINK_ERR_WANT_WRITE;
        if (n < 0)                           return WENDY_COM_LINK_ERR_UNKNOWN;
    } else if (ch->type == LINK_TYPE_TLS) {
        n = esp_tls_conn_write(ch->tls, data, len);
        if (n == MBEDTLS_ERR_SSL_WANT_READ)  return WENDY_COM_LINK_ERR_WANT_READ;
        if (n == MBEDTLS_ERR_SSL_WANT_WRITE) return WENDY_COM_LINK_ERR_WANT_WRITE;
        if (n < 0)                           return WENDY_COM_LINK_ERR_UNKNOWN;
    } else {
        n = wendy_com_uart_write(ch->uart, data, len);
        if (n == WENDY_COM_UART_ERR_WANT_READ)  return WENDY_COM_LINK_ERR_WANT_READ;
        if (n == WENDY_COM_UART_ERR_WANT_WRITE) return WENDY_COM_LINK_ERR_WANT_WRITE;
        if (n < 0)                              return WENDY_COM_LINK_ERR_UNKNOWN;
    }
    return n;
}

static struct wcom_link *_get_link(int link_id)
{
    if (link_id < 0)
        return NULL;
    int link_index = link_id % WCOM_LINK_COUNT;
    struct wcom_link *ch = &_links[link_index];
    if (ch->id != link_id || ch->state == WCOM_LINK_STATE_UNDEFINED)
        return NULL;
    return ch;
}

static void _fire_state_change_handlers(int link_id, enum wcom_link_state state)
{
    struct wcom_state_change_handler *h = _state_change_handler_first;
    while (h) {
        h->func(h, link_id, state);
        h = h->next;
    }
}

static void _clear_rx_queue(struct wcom_link *ch)
{
    struct wcom_rx_chunk *chunk = ch->rx_chunk_first;
    while (chunk) {
        struct wcom_rx_chunk *next = chunk->next;
        if (chunk->done_handler)
            chunk->done_handler(ch->id, chunk, false);
        chunk = next;
    }
    ch->rx_chunk_first = NULL;
    ch->rx_chunk_last = NULL;
    ch->rx_chunk_offset = 0;
}

static void _clear_tx_queue(struct wcom_link *ch)
{
    struct wcom_tx_chunk *chunk = ch->tx_chunk_first;
    while (chunk) {
        struct wcom_tx_chunk *next = chunk->next;
        if (chunk->done_handler)
            chunk->done_handler(ch->id, chunk, false);
        chunk = next;
    }
    ch->tx_chunk_first = NULL;
    ch->tx_chunk_last = NULL;
    ch->tx_chunk_offset = 0;
    ch->tx_deadline_us = 0;
}

/// Bring a link down, notifying the state change handlers and then the link's
/// own interruption handler.
static void _link_interrupt(struct wcom_link *ch, enum wcom_link_state state)
{
    ch->state = state;
    _clear_rx_queue(ch);
    _clear_tx_queue(ch);
    _fire_state_change_handlers(ch->id, state);

    // Taken last: the interruption handler is the one that may remove the link,
    // and it must run at most once per link.
    int link_id = ch->id;
    wcom_interruption_handler_t handler = ch->interruption_handler;
    ch->interruption_handler = NULL;
    if (handler)
        handler(link_id, state == WCOM_LINK_STATE_ERROR
                             ? WCOM_INTERRUPTION_CONNECTION_ERROR
                             : WCOM_INTERRUPTION_CONNECTION_CLOSED);
}

static int64_t _tx_stall_timeout(const struct wcom_link *ch)
{
    return ch->routed ? WCOM_TX_ROUTED_STALL_TIMEOUT_US : WCOM_TX_STALL_TIMEOUT_US;
}

static int64_t _tx_stall_delay(const struct wcom_link *ch, int64_t now_us)
{
    if (ch->state != WCOM_LINK_STATE_CONNECTED || !ch->tx_chunk_first)
        return -1;
    int64_t remaining = ch->tx_deadline_us - now_us;
    return remaining > 0 ? remaining : 0;
}

static bool _expire_stalled_tx(struct wcom_link *ch, int64_t now_us)
{
    if (_tx_stall_delay(ch, now_us) != 0)
        return false;
    ESP_LOGW(TAG, "tx stalled for %u seconds on link %d, closing",
        (unsigned)(_tx_stall_timeout(ch) / 1000000), ch->id);
    _link_interrupt(ch, WCOM_LINK_STATE_ERROR);
    return true;
}

static void _link_do_rx(struct wcom_link *ch)
{
    while (ch->rx_chunk_first) {
        struct wcom_rx_chunk *chunk = ch->rx_chunk_first;
        uint8_t *buf = (uint8_t *)chunk->data + ch->rx_chunk_offset;
        size_t remaining = chunk->size - ch->rx_chunk_offset;
        assert(remaining > 0);

        ssize_t n = _link_read(ch, buf, remaining);
        if (n > 0) {
            ch->rx_need_write = false;
            ch->rx_tls_readable = true; // assume more TLS data may be read even if socket is not readable
            ch->rx_chunk_offset += (size_t)n;
            if (ch->rx_chunk_offset >= chunk->size) {
                ch->rx_chunk_first = chunk->next;
                if (!ch->rx_chunk_first)
                    ch->rx_chunk_last = NULL;
                ch->rx_chunk_offset = 0;
                if (chunk->done_handler)
                    chunk->done_handler(ch->id, chunk, true);
            }
        } else if (n == WENDY_COM_LINK_ERR_WANT_WRITE) {
            ch->rx_need_write = true;
            break;
        } else if (n == WENDY_COM_LINK_ERR_WANT_READ) {
            ch->rx_need_write = false;
            ch->rx_tls_readable = false; // TLS buffer drained; wait for real socket data
            break;
        } else {
            ch->rx_need_write = false;
            ch->rx_tls_readable = false;
            if (n != 0)
                ESP_LOGE(TAG, "rx error on link %d: %d", ch->id, n);
            _link_interrupt(ch, n == 0 ? WCOM_LINK_STATE_DISCONNECTED
                                       : WCOM_LINK_STATE_ERROR);
            break;
        }
    }
}

static void _link_do_tx(struct wcom_link *ch)
{
    while (ch->tx_chunk_first) {
        struct wcom_tx_chunk *chunk = ch->tx_chunk_first;
        const uint8_t *data = (const uint8_t *)chunk->data + ch->tx_chunk_offset;
        size_t remaining = chunk->size - ch->tx_chunk_offset;
        assert(remaining > 0);

        ssize_t n = _link_write(ch, data, remaining);
        if (n > 0) {
            ch->tx_need_read = false;
            ch->tx_deadline_us = esp_timer_get_time() + _tx_stall_timeout(ch);
            ch->tx_chunk_offset += (size_t)n;
            if (ch->tx_chunk_offset >= chunk->size) {
                ch->tx_chunk_first = chunk->next;
                if (!ch->tx_chunk_first) {
                    ch->tx_chunk_last = NULL;
                    ch->tx_deadline_us = 0;
                }
                ch->tx_chunk_offset = 0;
                if (chunk->done_handler)
                    chunk->done_handler(ch->id, chunk, true);
            }
        } else if (n == WENDY_COM_LINK_ERR_WANT_READ) {
            ch->tx_need_read = true;
            break;
        } else if (n == WENDY_COM_LINK_ERR_WANT_WRITE) {
            ch->tx_need_read = false;
            break;
        } else {
            ESP_LOGE(TAG, "tx error on link %d: %d", ch->id, n);
            ch->tx_need_read = false;
            _link_interrupt(ch, WCOM_LINK_STATE_ERROR);
            break;
        }
    }
}

static void _main(void *arg)
{
    _main_task = xTaskGetCurrentTaskHandle();

    _wakeup_efd = eventfd(0, 0);

    for (;;) {
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        // always watch the wakeup fd (signals new tx data or other internal events)
        int maxfd = _wakeup_efd;
        FD_SET(_wakeup_efd, &rfds);
        int64_t wait_us = -1; // -1 = no deadline; 0 = one is due now
        int64_t now_us = esp_timer_get_time();

        for (int i = 0; i < WCOM_LINK_COUNT; i++) {
            struct wcom_link *ch = &_links[i];
            if (ch->state != WCOM_LINK_STATE_CONNECTED || ch->fd < 0)
                continue;

            if (ch->fd > maxfd)
                maxfd = ch->fd;

            int64_t tx_delay = _tx_stall_delay(ch, now_us);
            if (tx_delay >= 0 && (wait_us < 0 || tx_delay < wait_us))
                wait_us = tx_delay;

            // UART VFS reports TX-space edges but may omit initial writable
            // state. A bounded retry also covers a software writer releasing
            // its mutex without sending bytes, which generates no UART IRQ.
            if (ch->type == LINK_TYPE_UART && ch->uart->write_ready &&
                ch->tx_chunk_first && !ch->tx_need_read &&
                (wait_us < 0 || wait_us > 10000))
                wait_us = 10000;

            // Only let the auto-close deadline run while a read is posted:
            // with no rx chunk queued, _link_do_rx() never reaches read(), so
            // nothing drains the fd and nothing refreshes the keep-alive
            // timestamp. Silence measured then says nothing about the peer,
            // and an expired deadline would turn select() into a zero-timeout
            // poll that spins until the next chunk is queued.
            if (ch->type == LINK_TYPE_UART && ch->rx_chunk_first) {
                int64_t delay = wendy_com_uart_auto_close_delay(ch->uart);
                if (delay >= 0 && (wait_us < 0 || delay < wait_us))
                    wait_us = delay;
            }

            // A stream link's fd is a readiness eventfd, not the transport.
            // It is always watched for read and never for write: an eventfd
            // is permanently writable, so putting it in wfds would turn a
            // stalled transmit into a busy loop.
            if (ch->type == LINK_TYPE_STREAM ||
                (ch->type == LINK_TYPE_UART && ch->uart->read_ready)) {
                FD_SET(ch->fd, &rfds);
                continue;
            }

            // RX: only poll when chunks are queued; if last read stalled on WANT_WRITE, wait for writable
            if (ch->rx_chunk_first) {
                if (ch->rx_need_write)
                    FD_SET(ch->fd, &wfds);
                else
                    FD_SET(ch->fd, &rfds);
            }

            // TX: if data queued, wait for writable; if last write stalled on WANT_READ, wait for readable
            if (ch->tx_chunk_first) {
                if (ch->tx_need_read)
                    FD_SET(ch->fd, &rfds);
                else
                    FD_SET(ch->fd, &wfds);
            }
        }

        // A link can already be able to make progress in a way select() cannot
        // see, in which case blocking on the fds would stall it. Use a zero
        // timeout instead and let the handling below find it.
        bool progress_pending = false;
        for (int i = 0; i < WCOM_LINK_COUNT; i++) {
            struct wcom_link *ch = &_links[i];
            if (ch->state != WCOM_LINK_STATE_CONNECTED)
                continue;
            // Bytes buffered inside the TLS layer rather than on the raw fd.
            if (ch->rx_tls_readable && ch->rx_chunk_first) {
                progress_pending = true;
                break;
            }
            if (ch->type == LINK_TYPE_UART && ch->tx_chunk_first && !ch->tx_need_read &&
                ch->uart->write_ready && ch->uart->write_ready()) {
                progress_pending = true;
                break;
            }
            if (ch->type == LINK_TYPE_UART && ch->uart->read_ready &&
                ch->rx_chunk_first && (ch->uart->raw_pos < ch->uart->raw_len ||
                                      ch->uart->eof_pending || ch->uart->read_ready())) {
                progress_pending = true;
                break;
            }
            // A stream link whose wakeup fd was already drained while its
            // transport still has data to read or room to write.
            if (ch->type == LINK_TYPE_STREAM
                && ((ch->rx_chunk_first && ch->ops->can_read(ch->stream_ctx))
                    || (ch->tx_chunk_first && ch->ops->can_write(ch->stream_ctx)))) {
                progress_pending = true;
                break;
            }
        }

        struct timeval zero_tv = {0, 0};
        struct timeval deadline_tv;
        struct timeval *select_tv = NULL;
        if (progress_pending) {
            select_tv = &zero_tv;
        } else if (wait_us >= 0) {
            deadline_tv.tv_sec  = wait_us / 1000000;
            deadline_tv.tv_usec = wait_us % 1000000;
            select_tv = &deadline_tv;
        }
        if (select(maxfd + 1, &rfds, &wfds, NULL, select_tv) < 0)
            continue;

        // drain wakeup signal — no action needed beyond waking up to rebuild fd sets
        if (FD_ISSET(_wakeup_efd, &rfds)) {
            uint64_t val;
            read(_wakeup_efd, &val, sizeof(val));
        }

        // Drain and execute queued operations in FIFO order. Producers push
        // onto a LIFO, so the batch is reversed first — which rewrites ->next
        // on every node of it, long before any of their func() run. A node
        // stays owned by this queue until its own func() is entered, and that
        // is why a producer must not touch one it has already queued: doing so
        // here would splice a still-pending node into a second list.
        struct wcom_operation *op = atomic_exchange_explicit(&_op_queue_head, NULL, memory_order_acquire);
        struct wcom_operation *prev = NULL;
        while (op) {
            struct wcom_operation *next = op->next;
            op->next = prev;
            prev = op;
            op = next;
        }
        op = prev;
        while (op) {
            // Read ->next before the call, never after: entering func() hands
            // the node back to its producer, which is then free to re-queue it
            // — wendy_com_stdio and wendy_com_stdio_pump do, from inside func()
            // itself — or to free() it, as wendy_server does. These two lines
            // are therefore not reorderable.
            struct wcom_operation *next = op->next;
            op->func(op);
            op = next;
        }

        for (int i = 0; i < WCOM_LINK_COUNT; i++) {
            struct wcom_link *ch = &_links[i];
            if (ch->state != WCOM_LINK_STATE_CONNECTED || ch->fd < 0)
                continue;
            if (_expire_stalled_tx(ch, esp_timer_get_time()))
                continue;

            bool readable, writable;
            if (ch->type == LINK_TYPE_STREAM) {
                // Drain before sampling, never after: the transport signals
                // the eventfd after it changes state, so a signal that races
                // this is still visible in can_read()/can_write() — or, if it
                // lands later, leaves the counter non-zero and wakes the next
                // select(). Draining last would swallow it. The shared core fd
                // was already drained globally; leave later edges for the
                // next select rather than draining it once per link.
                if (ch->fd != _wakeup_efd && FD_ISSET(ch->fd, &rfds)) {
                    uint64_t drain;
                    read(ch->fd, &drain, sizeof(drain));
                }
                readable = ch->ops->can_read(ch->stream_ctx) || ch->rx_tls_readable;
                writable = ch->ops->can_write(ch->stream_ctx);
            } else if (ch->type == LINK_TYPE_UART && ch->uart->read_ready) {
                if (FD_ISSET(ch->fd, &rfds)) {
                    uint64_t drain;
                    read(ch->fd, &drain, sizeof drain);
                }
                readable = ch->uart->raw_pos < ch->uart->raw_len ||
                           ch->uart->eof_pending || ch->uart->read_ready() ||
                           wendy_com_uart_auto_close_delay(ch->uart) == 0;
                writable = ch->uart->write_ready && ch->uart->write_ready();
            } else {
                readable = FD_ISSET(ch->fd, &rfds) || ch->rx_tls_readable
                           || (ch->type == LINK_TYPE_UART && ch->rx_chunk_first
                               && wendy_com_uart_auto_close_delay(ch->uart) == 0);
                writable = FD_ISSET(ch->fd, &wfds) ||
                           (ch->type == LINK_TYPE_UART && ch->tx_chunk_first &&
                            !ch->tx_need_read && ch->uart->write_ready && ch->uart->write_ready());
            }

            // resume stalled read: was waiting for writable, socket is now writable
            if (writable && ch->rx_need_write)
                _link_do_rx(ch);

            // resume stalled write: was waiting for readable, socket is now readable
            if (readable && ch->tx_need_read)
                _link_do_tx(ch);

            // normal rx: incoming data arrived or TLS has buffered bytes
            if (readable && !ch->rx_need_write)
                _link_do_rx(ch);

            // normal tx: socket is writable and chunks are queued
            if (writable && ch->tx_chunk_first && !ch->tx_need_read)
                _link_do_tx(ch);
        }
    }
}


//--- public functions ---//

void wcom_core_init(void)
{
    xTaskCreatePinnedToCore(_main, "wcom", WCOM_TASK_STACK, NULL,
                             CONFIG_WENDY_COM_TASK_PRIORITY, NULL,
                             CONFIG_WENDY_COM_TASK_CORE_AFFINITY);
}

/// Execute a function on the com thread/task.
/// This function is thread-safe.
/// Queueing a node that is already queued corrupts the list. See the full
/// ownership contract in wendy_com_link.h.
void wcom_core_exec(struct wcom_operation *op)
{
    struct wcom_operation *old_head;
    do {
        old_head = atomic_load_explicit(&_op_queue_head, memory_order_relaxed);
        op->next = old_head;
    } while (!atomic_compare_exchange_weak_explicit(
        &_op_queue_head, &old_head, op,
        memory_order_release, memory_order_relaxed));

    wcom_core_wake();
}

int wcom_core_wakeup_fd(void)
{
    return atomic_load_explicit(&_wakeup_efd, memory_order_acquire);
}

void wcom_core_wake(void)
{
    int fd = wcom_core_wakeup_fd();
    if (fd >= 0) {
        uint64_t value = 1;
        (void)write(fd, &value, sizeof(value));
    }
}

bool wcom_is_com_thread(void)
{
    return xTaskGetCurrentTaskHandle() == _main_task;
}

const char *wcom_link_state_to_str(enum wcom_link_state state)
{
    switch (state) {
        case WCOM_LINK_STATE_UNDEFINED:    return "undefined";
        case WCOM_LINK_STATE_CONNECTED:    return "connected";
        case WCOM_LINK_STATE_DISCONNECTED: return "disconnected";
        case WCOM_LINK_STATE_ERROR:        return "error";
    }
    return "?";
}

/// A state change handler must never add nor remove a link: it is called while
/// the core is working on that link. Use the link's interruption handler to
/// remove it (see wcom_interruption_handler_t).
void wcom_add_state_change_handler(struct wcom_state_change_handler *handler)
{
    assert(xTaskGetCurrentTaskHandle() == _main_task);
    assert(handler);
    if (_state_change_handler_last) {
        _state_change_handler_last->next = handler;
        _state_change_handler_last = handler;
    } else {
        _state_change_handler_first = handler;
        _state_change_handler_last = handler;
    }
}

void wcom_remove_state_change_handler(struct wcom_state_change_handler *handler)
{
    assert(xTaskGetCurrentTaskHandle() == _main_task);
    assert(handler);
    struct wcom_state_change_handler *prev = NULL;
    struct wcom_state_change_handler *cur = _state_change_handler_first;
    while (cur) {
        if (cur == handler) {
            if (prev)
                prev->next = cur->next;
            else
                _state_change_handler_first = cur->next;
            if (_state_change_handler_last == cur)
                _state_change_handler_last = prev;
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}

void wcom_recv(int link_id, struct wcom_rx_chunk *chunk)
{
    assert(xTaskGetCurrentTaskHandle() == _main_task);

    struct wcom_link *ch = _get_link(link_id);
    assert(ch && chunk);
    assert(chunk->size > 0);

    if (ch->rx_chunk_last)
        ch->rx_chunk_last->next = chunk;
    else
        ch->rx_chunk_first = chunk;

    ch->rx_chunk_last = chunk;
}

void wcom_send(int link_id, struct wcom_tx_chunk *chunk)
{
    assert(xTaskGetCurrentTaskHandle() == _main_task);

    struct wcom_link *ch = _get_link(link_id);
    assert(ch && chunk);
    assert(chunk->size > 0);

    if (ch->tx_chunk_last)
        ch->tx_chunk_last->next = chunk;
    else {
        ch->tx_chunk_first = chunk;
        ch->tx_deadline_us = esp_timer_get_time() + _tx_stall_timeout(ch);
    }

    while (chunk->next)
        chunk = chunk->next;
    ch->tx_chunk_last = chunk;
}

void wcom_close(int link_id)
{
    assert(xTaskGetCurrentTaskHandle() == _main_task);

    struct wcom_link *ch = _get_link(link_id);
    if (!ch)
        return;

    _link_interrupt(ch, WCOM_LINK_STATE_DISCONNECTED);
}

/// The returned link ID is a positive number (it's never zero).
/// It is an opaque identifier that is never reused for a different connection
/// (except after a long time).
/// Returns -1 if the link couldn't be added (e.g. max links reached).
int wcom_add_tls_link(esp_tls_t *tls, wcom_interruption_handler_t interruption_handler)
{
    return wcom_add_tls_link_with_permission(tls, interruption_handler, WCOM_LINK_PERMISSION_FULL);
}

static bool _valid_permission(enum wcom_link_permission permission)
{
    return permission == WCOM_LINK_PERMISSION_FULL || permission == WCOM_LINK_PERMISSION_SENSOR_ONLY;
}

int wcom_add_tls_link_with_permission(esp_tls_t *tls,
                                      wcom_interruption_handler_t interruption_handler,
                                      enum wcom_link_permission permission)
{
    assert(xTaskGetCurrentTaskHandle() == _main_task);
    if (!_valid_permission(permission)) return -1;

    for (int i = 0; i < WCOM_LINK_COUNT; i++) {
        struct wcom_link *ch = &_links[i];
        if (ch->state == WCOM_LINK_STATE_UNDEFINED) {
            _link_id_generator++;
            if (_link_id_generator >= (INT_MAX / WCOM_LINK_COUNT))
                _link_id_generator = 1;
            ch->id = _link_id_generator * WCOM_LINK_COUNT + i;
            ch->state = WCOM_LINK_STATE_CONNECTED;
            ch->type = LINK_TYPE_TLS;
            ch->routed = false;
            ch->permission = permission;
            ch->tls = tls;
            ch->interruption_handler = interruption_handler;
            esp_tls_get_conn_sockfd(tls, &ch->fd);
            int flags = fcntl(ch->fd, F_GETFL, 0);
            fcntl(ch->fd, F_SETFL, flags | O_NONBLOCK);
            ch->tx_chunk_first = NULL;
            ch->tx_chunk_last = NULL;
            ch->tx_chunk_offset = 0;
            ch->tx_deadline_us = 0;
            ch->rx_chunk_first = NULL;
            ch->rx_chunk_last = NULL;
            ch->rx_chunk_offset = 0;
            ch->rx_need_write = false;
            ch->tx_need_read = false;
            _fire_state_change_handlers(ch->id, ch->state);
            return ch->id;
        }
    }
    return -1;
}

int wcom_add_uart_link(wendy_com_uart_t *uart, wcom_interruption_handler_t interruption_handler)
{
    assert(xTaskGetCurrentTaskHandle() == _main_task);

    for (int i = 0; i < WCOM_LINK_COUNT; i++) {
        struct wcom_link *ch = &_links[i];
        if (ch->state == WCOM_LINK_STATE_UNDEFINED) {
            _link_id_generator++;
            if (_link_id_generator >= (INT_MAX / WCOM_LINK_COUNT))
                _link_id_generator = 1;
            ch->id = _link_id_generator * WCOM_LINK_COUNT + i;
            ch->state = WCOM_LINK_STATE_CONNECTED;
            ch->type = LINK_TYPE_UART;
            ch->routed = false;
            ch->permission = WCOM_LINK_PERMISSION_FULL;
            ch->uart = uart;
            ch->interruption_handler = interruption_handler;
            ch->fd = wendy_com_uart_get_fd(uart);
            int flags = fcntl(ch->fd, F_GETFL, 0);
            fcntl(ch->fd, F_SETFL, flags | O_NONBLOCK);
            ch->tx_chunk_first = NULL;
            ch->tx_chunk_last = NULL;
            ch->tx_chunk_offset = 0;
            ch->tx_deadline_us = 0;
            ch->rx_chunk_first = NULL;
            ch->rx_chunk_last = NULL;
            ch->rx_chunk_offset = 0;
            ch->rx_need_write = false;
            ch->rx_tls_readable = false;
            ch->tx_need_read = false;
            _fire_state_change_handlers(ch->id, ch->state);
            return ch->id;
        }
    }
    return -1;
}

static int _add_custom_link(enum link_type type, const struct wcom_stream_ops *ops,
                            void *ctx, wcom_interruption_handler_t interruption_handler,
                            enum wcom_link_permission permission, bool routed)
{
    assert(xTaskGetCurrentTaskHandle() == _main_task);
    if (!_valid_permission(permission)) return -1;
    assert(ops && ops->read && ops->write && ops->wakeup_fd);
    assert(type != LINK_TYPE_STREAM || (ops->can_read && ops->can_write));
    if ((ops->allocate_buffer == NULL) != (ops->free_buffer == NULL)) return -1;

    for (int i = 0; i < WCOM_LINK_COUNT; i++) {
        struct wcom_link *ch = &_links[i];
        if (ch->state == WCOM_LINK_STATE_UNDEFINED) {
            _link_id_generator++;
            if (_link_id_generator >= (INT_MAX / WCOM_LINK_COUNT))
                _link_id_generator = 1;
            ch->id = _link_id_generator * WCOM_LINK_COUNT + i;
            ch->state = WCOM_LINK_STATE_CONNECTED;
            ch->type = type;
            ch->routed = routed;
            ch->permission = permission;
            ch->ops = ops;
            ch->stream_ctx = ctx;
            ch->interruption_handler = interruption_handler;
            // The transport owns this fd. Streams expose a readiness eventfd;
            // socket transports expose their socket, which must never be drained.
            ch->fd = ops->wakeup_fd(ctx);
            ch->tx_chunk_first = NULL;
            ch->tx_chunk_last = NULL;
            ch->tx_chunk_offset = 0;
            ch->tx_deadline_us = 0;
            ch->rx_chunk_first = NULL;
            ch->rx_chunk_last = NULL;
            ch->rx_chunk_offset = 0;
            ch->rx_need_write = false;
            ch->rx_tls_readable = false;
            ch->tx_need_read = false;
            _fire_state_change_handlers(ch->id, ch->state);
            return ch->id;
        }
    }
    return -1;
}

int wcom_add_stream_link(const struct wcom_stream_ops *ops, void *ctx,
                         wcom_interruption_handler_t handler)
{
    return _add_custom_link(LINK_TYPE_STREAM, ops, ctx, handler, WCOM_LINK_PERMISSION_FULL, false);
}

int wcom_add_routed_stream_link_with_permission(const struct wcom_stream_ops *ops, void *ctx,
                                                wcom_interruption_handler_t handler,
                                                enum wcom_link_permission permission)
{
    return _add_custom_link(LINK_TYPE_STREAM, ops, ctx, handler, permission, true);
}

bool wcom_link_get_buffer_allocator(int link_id, struct wcom_link_buffer_allocator *out)
{
    if (!out) return false;
    *out = (struct wcom_link_buffer_allocator){0};
    struct wcom_link *link = _get_link(link_id);
    if (!link || link->state != WCOM_LINK_STATE_CONNECTED) return false;
    if ((link->type == LINK_TYPE_STREAM || link->type == LINK_TYPE_SOCKET) &&
        link->ops->allocate_buffer && link->ops->free_buffer) {
        out->context = link->stream_ctx;
        out->allocate = link->ops->allocate_buffer;
        out->release = link->ops->free_buffer;
    }
    return true;
}

int wcom_add_socket_link(const struct wcom_stream_ops *ops, void *ctx,
                         wcom_interruption_handler_t handler)
{
    return wcom_add_socket_link_with_permission(ops, ctx, handler, WCOM_LINK_PERMISSION_FULL);
}

int wcom_add_socket_link_with_permission(const struct wcom_stream_ops *ops, void *ctx,
                                         wcom_interruption_handler_t handler,
                                         enum wcom_link_permission permission)
{
    return _add_custom_link(LINK_TYPE_SOCKET, ops, ctx, handler, permission, false);
}

int wcom_add_routed_socket_link_with_permission(const struct wcom_stream_ops *ops, void *ctx,
                                               wcom_interruption_handler_t handler,
                                               enum wcom_link_permission permission)
{
    return _add_custom_link(LINK_TYPE_SOCKET, ops, ctx, handler, permission, true);
}

enum wcom_link_permission wcom_link_get_permission(int link_id)
{
    struct wcom_link *link = _get_link(link_id);
    return link && link->state == WCOM_LINK_STATE_CONNECTED && _valid_permission(link->permission)
        ? link->permission : WCOM_LINK_PERMISSION_NONE;
}

bool wcom_link_is_local(int link_id)
{
    struct wcom_link *link = _get_link(link_id);
    return link && link->type == LINK_TYPE_UART;
}

void wcom_remove_link(int link_id)
{
    assert(xTaskGetCurrentTaskHandle() == _main_task);

    for (int i = 0; i < WCOM_LINK_COUNT; i++) {
        struct wcom_link *ch = &_links[i];
        if (ch->state == WCOM_LINK_STATE_UNDEFINED || ch->id != link_id)
            continue;
        ch->state = WCOM_LINK_STATE_UNDEFINED;
        _clear_rx_queue(ch);
        _clear_tx_queue(ch);
        _fire_state_change_handlers(link_id, WCOM_LINK_STATE_UNDEFINED);
        ch->id = 0;
        ch->type = LINK_TYPE_NONE;
        ch->permission = WCOM_LINK_PERMISSION_NONE;
        ch->uart = NULL;
        ch->tls = NULL;
        ch->stream_ctx = NULL;
        ch->interruption_handler = NULL;
        ch->fd = -1;
        return;
    }
}
