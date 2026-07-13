
#include "wendy_com_stdio.h"
#include "wendy_com_link.h"
#include "wendy_stdio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <stdatomic.h>
#include <string.h>
#include <stdint.h>


//--- literals ---//

#define WCOM_STDIO_BUF_SIZE   4096
#define WCOM_STDIO_SEM_MAX    64


//--- globals ---//

static uint8_t _buf[WCOM_STDIO_BUF_SIZE];
static size_t _tail;                    // index of the oldest unread byte
static size_t _count;                   // number of unread bytes
static bool _gap;                       // data was overwritten at the read frontier
static bool _blocking;
static bool _armed = true;              // notify the com thread when data is added
static int _writers_waiting;
static SemaphoreHandle_t _mutex;
static SemaphoreHandle_t _space_sem;
static TaskHandle_t _reader_task;
static atomic_bool _notify_in_flight;   // _notify_op is queued and not yet executed
static wcom_stdio_data_handler_t _handler;
static void *_handler_ctx;
static wendy_stdio_out_data_handler_t _chained_handler;


//--- internal functions ---//

static void _notify_func(struct wcom_operation *op)
{
    atomic_store(&_notify_in_flight, false);
    if (_handler)
        _handler(_handler_ctx);
}

static struct wcom_operation _notify_op = {
    .func = _notify_func,
};

// Post _notify_op at most once per arm cycle; if it is already queued, the
// handler will see this data anyway when the op executes.
static void _notify_locked(void)
{
    if (_count == 0 || !_armed)
        return;
    _armed = false;
    if (!atomic_exchange(&_notify_in_flight, true))
        wcom_core_exec(&_notify_op);
}

// Copy size bytes into the ring; the caller ensures they fit.
static void _copy_in(const uint8_t *data, size_t size)
{
    size_t head = (_tail + _count) % WCOM_STDIO_BUF_SIZE;
    size_t first = WCOM_STDIO_BUF_SIZE - head;
    if (first > size)
        first = size;
    memcpy(&_buf[head], data, first);
    memcpy(&_buf[0], data + first, size - first);
    _count += size;
}

static void _write_overwriting(const uint8_t *data, size_t size)
{
    if (size >= WCOM_STDIO_BUF_SIZE) {
        if (_count > 0 || size > WCOM_STDIO_BUF_SIZE)
            _gap = true;
        data += size - WCOM_STDIO_BUF_SIZE;
        size = WCOM_STDIO_BUF_SIZE;
        _tail = 0;
        _count = 0;
    }
    size_t space = WCOM_STDIO_BUF_SIZE - _count;
    if (size > space) {
        size_t drop = size - space;
        _tail = (_tail + drop) % WCOM_STDIO_BUF_SIZE;
        _count -= drop;
        _gap = true;
    }
    _copy_in(data, size);
}

static void _on_out_data(const void *vdata, size_t size)
{
    const uint8_t *data = vdata;
    size_t remaining = size;

    xSemaphoreTake(_mutex, portMAX_DELAY);
    while (remaining > 0) {
        // The com thread must never block here: it is the only task that
        // frees space by reading, so it would wait on itself.
        if (!_blocking || xTaskGetCurrentTaskHandle() == _reader_task) {
            _write_overwriting(data, remaining);
            remaining = 0;
            _notify_locked();
            break;
        }

        size_t space = WCOM_STDIO_BUF_SIZE - _count;
        size_t n = remaining < space ? remaining : space;
        _copy_in(data, n);
        data += n;
        remaining -= n;
        _notify_locked();

        if (remaining > 0) {
            _writers_waiting++;
            xSemaphoreGive(_mutex);
            xSemaphoreTake(_space_sem, portMAX_DELAY);
            xSemaphoreTake(_mutex, portMAX_DELAY);
            _writers_waiting--;
        }
    }
    // Cascade wake: one read gives the semaphore once, but the space it freed
    // may be enough for more than one waiting writer.
    if (_writers_waiting > 0 && _count < WCOM_STDIO_BUF_SIZE)
        xSemaphoreGive(_space_sem);
    xSemaphoreGive(_mutex);

    wendy_stdio_out_data_handler_t chained = _chained_handler;
    if (chained)
        chained(vdata, size);
}


//--- public functions ---//

void wcom_stdio_init(void)
{
    _mutex = xSemaphoreCreateMutex();
    _space_sem = xSemaphoreCreateCounting(WCOM_STDIO_SEM_MAX, 0);
    _chained_handler = wendy_stdio_set_out_data_handler(_on_out_data);
}

void wcom_stdio_set_blocking(bool blocking)
{
    xSemaphoreTake(_mutex, portMAX_DELAY);
    _blocking = blocking;
    if (!blocking) {
        // Wake all blocked writers so they complete in overwriting mode.
        for (int i = 0; i < _writers_waiting; i++)
            xSemaphoreGive(_space_sem);
    }
    xSemaphoreGive(_mutex);
}

void wcom_stdio_set_data_handler(wcom_stdio_data_handler_t handler, void *ctx)
{
    xSemaphoreTake(_mutex, portMAX_DELAY);
    _handler = handler;
    _handler_ctx = ctx;
    if (handler)
        _notify_locked();
    xSemaphoreGive(_mutex);
}

size_t wcom_stdio_read(void *vbuf, size_t size, bool *gap)
{
    uint8_t *buf = vbuf;

    xSemaphoreTake(_mutex, portMAX_DELAY);
    _reader_task = xTaskGetCurrentTaskHandle();

    size_t n = size < _count ? size : _count;
    if (gap)
        *gap = n > 0 && _gap;
    if (n > 0) {
        _gap = false;
        size_t first = WCOM_STDIO_BUF_SIZE - _tail;
        if (first > n)
            first = n;
        memcpy(buf, &_buf[_tail], first);
        memcpy(buf + first, &_buf[0], n - first);
        _tail = (_tail + n) % WCOM_STDIO_BUF_SIZE;
        _count -= n;
        if (_writers_waiting > 0)
            xSemaphoreGive(_space_sem);
    }
    // Re-arm exactly when the reader has seen the buffer empty, so the next
    // incoming data fires the handler again.
    if (_count == 0)
        _armed = true;
    xSemaphoreGive(_mutex);
    return n;
}
