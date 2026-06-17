
#include "wendy_com_link.h"
#include "esp_log.h"
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
#define WCOM_TASK_PRIO      5


//--- types ---//

struct wcom_link {
    int id;
    enum wcom_link_state state;
    esp_tls_t *tls;
    int sockfd;
    struct wcom_tx_chunk *tx_chunk_first;
    struct wcom_tx_chunk *tx_chunk_last;
    size_t tx_chunk_offset;            // bytes already sent from tx_chunk_first
    struct wcom_rx_chunk *rx_chunk_first;
    struct wcom_rx_chunk *rx_chunk_last;
    size_t rx_chunk_offset;            // bytes already received into rx_chunk_first
    bool rx_need_write;                // last conn_read() returned WANT_WRITE
    bool rx_tls_readable;              // TLS layer may have buffered bytes not yet consumed
    bool tx_need_read;                 // last conn_write() returned WANT_READ
};


//--- globals ---//

static const char *TAG = "wcom_hub";
static struct wcom_link _links[WCOM_LINK_COUNT];
static int _wakeup_efd = -1;
static TaskHandle_t _main_task = NULL;
static int _link_id_generator = 0;
static _Atomic(struct wcom_operation *) _op_queue_head;
static struct wcom_state_change_handler *_state_change_handler_first;
static struct wcom_state_change_handler *_state_change_handler_last;


//--- internal functions ---//

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
}

static void _link_do_rx(struct wcom_link *ch)
{
    while (ch->rx_chunk_first) {
        struct wcom_rx_chunk *chunk = ch->rx_chunk_first;
        uint8_t *buf = (uint8_t *)chunk->data + ch->rx_chunk_offset;
        size_t remaining = chunk->size - ch->rx_chunk_offset;
        assert(remaining > 0);

        ssize_t n = esp_tls_conn_read(ch->tls, buf, remaining);
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
        } else if (n == MBEDTLS_ERR_SSL_WANT_WRITE) {
            ch->rx_need_write = true;
            break;
        } else if (n == MBEDTLS_ERR_SSL_WANT_READ) {
            ch->rx_need_write = false;
            ch->rx_tls_readable = false; // TLS buffer drained; wait for real socket data
            break;
        } else {
            ch->rx_need_write = false;
            ch->rx_tls_readable = false;
            if (n == 0) {
                ch->state = WCOM_LINK_STATE_DISCONNECTED;
            } else {
                ESP_LOGE(TAG, "rx error on link %d: %d", ch->id, n);
                ch->state = WCOM_LINK_STATE_ERROR;
            }
            _clear_rx_queue(ch);
            _clear_tx_queue(ch);
            _fire_state_change_handlers(ch->id, ch->state);
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

        ssize_t n = esp_tls_conn_write(ch->tls, data, remaining);
        if (n > 0) {
            ch->tx_need_read = false;
            ch->tx_chunk_offset += (size_t)n;
            if (ch->tx_chunk_offset >= chunk->size) {
                ch->tx_chunk_first = chunk->next;
                if (!ch->tx_chunk_first)
                    ch->tx_chunk_last = NULL;
                ch->tx_chunk_offset = 0;
                if (chunk->done_handler)
                    chunk->done_handler(ch->id, chunk, true);
            }
        } else if (n == MBEDTLS_ERR_SSL_WANT_READ) {
            ch->tx_need_read = true;
            break;
        } else if (n == MBEDTLS_ERR_SSL_WANT_WRITE) {
            ch->tx_need_read = false;
            break;
        } else {
            ESP_LOGE(TAG, "tx error on link %d: %d", ch->id, n);
            ch->tx_need_read = false;
            ch->state = WCOM_LINK_STATE_ERROR;
            _clear_rx_queue(ch);
            _clear_tx_queue(ch);
            _fire_state_change_handlers(ch->id, ch->state);
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

        for (int i = 0; i < WCOM_LINK_COUNT; i++) {
            struct wcom_link *ch = &_links[i];
            if (ch->state != WCOM_LINK_STATE_CONNECTED || ch->sockfd < 0)
                continue;

            if (ch->sockfd > maxfd)
                maxfd = ch->sockfd;

            // RX: only poll when chunks are queued; if last read stalled on WANT_WRITE, wait for writable
            if (ch->rx_chunk_first) {
                if (ch->rx_need_write)
                    FD_SET(ch->sockfd, &wfds);
                else
                    FD_SET(ch->sockfd, &rfds);
            }

            // TX: if data queued, wait for writable; if last write stalled on WANT_READ, wait for readable
            if (ch->tx_chunk_first) {
                if (ch->tx_need_read)
                    FD_SET(ch->sockfd, &rfds);
                else
                    FD_SET(ch->sockfd, &wfds);
            }
        }

        // If any link has data buffered inside the TLS layer, select() on the
        // raw fd would block even though data is ready. Use a zero timeout so we
        // don't stall, and handle those links as readable below.
        bool tls_pending = false;
        for (int i = 0; i < WCOM_LINK_COUNT; i++) {
            struct wcom_link *ch = &_links[i];
            if (ch->state == WCOM_LINK_STATE_CONNECTED && ch->rx_tls_readable && ch->rx_chunk_first) {
                tls_pending = true;
                break;
            }
        }

        struct timeval zero_tv = {0, 0};
        if (select(maxfd + 1, &rfds, &wfds, NULL, tls_pending ? &zero_tv : NULL) < 0)
            continue;

        // drain wakeup signal — no action needed beyond waking up to rebuild fd sets
        if (FD_ISSET(_wakeup_efd, &rfds)) {
            uint64_t val;
            read(_wakeup_efd, &val, sizeof(val));
        }

        // drain and execute queued operations in FIFO order
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
            struct wcom_operation *next = op->next;
            op->func(op);
            op = next;
        }

        for (int i = 0; i < WCOM_LINK_COUNT; i++) {
            struct wcom_link *ch = &_links[i];
            if (ch->state != WCOM_LINK_STATE_CONNECTED || ch->sockfd < 0)
                continue;

            bool readable = FD_ISSET(ch->sockfd, &rfds) || ch->rx_tls_readable;
            bool writable = FD_ISSET(ch->sockfd, &wfds);

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
    xTaskCreate(_main, "wcom", WCOM_TASK_STACK, NULL, WCOM_TASK_PRIO, NULL);
}

/**
 * Execute a function on the com thread/task.
 * This function is thread-safe.
 */
void wcom_core_exec(struct wcom_operation *op)
{
    struct wcom_operation *old_head;
    do {
        old_head = atomic_load_explicit(&_op_queue_head, memory_order_relaxed);
        op->next = old_head;
    } while (!atomic_compare_exchange_weak_explicit(
        &_op_queue_head, &old_head, op,
        memory_order_release, memory_order_relaxed));

    if (_wakeup_efd >= 0) {
        uint64_t val = 1;
        write(_wakeup_efd, &val, sizeof(val));
    }
}

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
    else
        ch->tx_chunk_first = chunk;

    ch->tx_chunk_last = chunk;
}

void wcom_close(int link_id)
{
    assert(xTaskGetCurrentTaskHandle() == _main_task);

    struct wcom_link *ch = _get_link(link_id);
    if (!ch)
        return;

    ch->state = WCOM_LINK_STATE_DISCONNECTED;
    _clear_rx_queue(ch);
    _clear_tx_queue(ch);
    _fire_state_change_handlers(ch->id, ch->state);
}

/**
 * The returned link ID is a positive number (it's never zero).
 * It is an opaque identifier that is never reused for a different connection
 * (except after a long time).
 * Returns -1 if the link couldn't be added (e.g. max links reached).
 */
int wcom_add_link(esp_tls_t *tls)
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
            ch->tls = tls;
            esp_tls_get_conn_sockfd(tls, &ch->sockfd);
            int flags = fcntl(ch->sockfd, F_GETFL, 0);
            fcntl(ch->sockfd, F_SETFL, flags | O_NONBLOCK);
            ch->tx_chunk_first = NULL;
            ch->tx_chunk_last = NULL;
            ch->tx_chunk_offset = 0;
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
        ch->tls = NULL;
        ch->sockfd = -1;
        return;
    }
}
