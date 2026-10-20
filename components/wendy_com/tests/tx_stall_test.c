/* Exercise production transmission and SensorLink buffer ownership with a
 * transport that stops accepting bytes. No firmware tasks or network needed. */
#include <assert.h>
#include <limits.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include "esp_vfs_eventfd.h"

static int test_eventfd(unsigned initial, int flags);
static int test_select(int nfds, fd_set *readfds, fd_set *writefds,
                       fd_set *errorfds, struct timeval *timeout);
#define eventfd test_eventfd
#define select test_select
#include "../src/wendy_com_link.c"
#undef eventfd
#undef select
#define TAG sensor_tag
#include "../src/wendy_com_sensor.c"
#undef TAG

static int64_t now_us = 1000;
static size_t write_budget;
static ssize_t blocked_result = WCOM_STREAM_ERR_WANT_WRITE;
static int current_link, current_client = 1;
static unsigned frame_completions, response_completions, disconnections, interruptions;
static unsigned select_calls;
static int64_t expected_wait_us;
static jmp_buf main_idle;
static enum { UART_UNUSED, UART_INITIAL, UART_FULL, UART_WANT_READ } uart_scenario;
static uint8_t uart_received[32];
static size_t uart_received_size;

int64_t esp_timer_get_time(void) { return now_us; }
ssize_t wendy_com_uart_read(wendy_com_uart_t *uart, void *data, size_t size) { return -1; }
ssize_t wendy_com_uart_write(wendy_com_uart_t *uart, const void *data, size_t size)
{
    return uart->write_bytes ? uart->write_bytes(data, size) : -1;
}
int wendy_com_uart_get_fd(wendy_com_uart_t *uart) { return uart->fd; }
int64_t wendy_com_uart_auto_close_delay(wendy_com_uart_t *uart) { return -1; }
int wcom_get_link_id(int client) { return client == current_client ? current_link : -1; }
int wcom_get_channel(int client) { return wcom_get_link_id(client) > 0 ? 0 : -1; }

static ssize_t read_wire(void *context, void *data, size_t size)
{
    return WCOM_STREAM_ERR_WANT_READ;
}

static ssize_t write_wire(void *context, const void *data, size_t size)
{
    if (!write_budget)
        return blocked_result;
    if (size > write_budget)
        size = write_budget;
    write_budget -= size;
    return (ssize_t)size;
}

static int wire_fd(void *context) { return 4; }
static bool cannot_read(void *context) { return false; }
static bool can_write(void *context) { return write_budget != 0; }
static const struct wcom_stream_ops wire_ops = {
    .read = read_wire, .write = write_wire, .wakeup_fd = wire_fd,
    .can_read = cannot_read, .can_write = can_write,
};

static void frame_done(uint32_t channel)
{
    assert(channel == 0 && !_streams[0].frame.busy);
    frame_completions++;
}

static void response_done(int link_id, const struct wcom_tx_chunk *chunk, bool success)
{
    assert(!success);
    response_completions++;
}

static void state_changed(struct wcom_state_change_handler *handler, int id,
                          enum wcom_link_state state)
{
    if (state != WCOM_LINK_STATE_CONNECTED && id == current_link) {
        disconnections++;
        wcom_sensor_client_disconnected(current_client);
        current_link = -1;
    }
}

static void interrupted(int id, enum wcom_interruption_reason reason)
{
    assert(reason == WCOM_INTERRUPTION_CONNECTION_ERROR);
    assert(!_streams[0].frame.busy && !_streams[0].active);
    interruptions++;
    wcom_remove_link(id);
}

static int open_link(bool stream)
{
    int id = stream ? wcom_add_stream_link(&wire_ops, NULL, interrupted)
                    : wcom_add_socket_link(&wire_ops, NULL, interrupted);
    assert(id > 0);
    current_link = id;
    return id;
}

static void push_frame(size_t size)
{
    static uint8_t data[256 * 1024];
    assert(size <= sizeof(data));
    assert(wcom_sensor_stream_begin(current_client, 0) == WendyComResult_WENDY_COM_RESULT_OK);
    assert(wcom_sensor_stream_push(current_client, 0, data, size, now_us, frame_done)
           == WendyComResult_WENDY_COM_RESULT_OK);
}

static int test_eventfd(unsigned initial, int flags) { return 3; }

static int test_select(int nfds, fd_set *readfds, fd_set *writefds,
                       fd_set *errorfds, struct timeval *timeout)
{
    if (uart_scenario != UART_UNUSED) {
        if (response_completions) {
            assert(!timeout && !FD_ISSET(4, writefds));
            longjmp(main_idle, 1);
        }
        assert(timeout);
        int64_t delay = timeout->tv_sec * 1000000LL + timeout->tv_usec;
        bool want_read = uart_scenario == UART_WANT_READ;
        assert(!!FD_ISSET(4, writefds) == !want_read);
        assert(!!FD_ISSET(4, readfds) == want_read);
        if (want_read) {
            // Positive TX capacity must not bypass a transport's WANT_READ.
            assert(select_calls == 0 && delay == WCOM_TX_STALL_TIMEOUT_US);
        } else if (uart_scenario == UART_INITIAL && select_calls == 0) {
            assert(delay == 0 && write_budget == 3);
        } else {
            // A full ring and no IRQ must produce a bounded wait, not a
            // zero-timeout busy loop or an indefinite initial select().
            assert(delay == 10000 && write_budget == 0);
            now_us += delay;
            write_budget = select_calls < 2 ? 3 : sizeof(uart_received);
        }
        select_calls++;
        assert(select_calls <= 3);
        FD_ZERO(readfds);
        FD_ZERO(writefds); // Model UART VFS omitting initial write readiness.
        if (want_read)
            FD_SET(4, readfds);
        return 0;
    }
    if (select_calls++ == 0) {
        // No readiness event arrives. The production event loop must still
        // wake at the write deadline rather than block forever in select.
        assert(timeout);
        int64_t delay = timeout->tv_sec * 1000000LL + timeout->tv_usec;
        assert(delay == expected_wait_us && delay > 0);
        now_us += delay;
        FD_ZERO(readfds);
        FD_ZERO(writefds);
        return 0;
    }
    assert(!timeout && disconnections == 1 && interruptions == 1);
    longjmp(main_idle, 1);
}

static bool uart_ready(void) { return write_budget > 0; }

static ssize_t uart_write(const void *data, size_t size)
{
    if (!write_budget)
        return WENDY_COM_UART_ERR_WANT_WRITE;
    if (size > write_budget)
        size = write_budget;
    assert(uart_received_size + size <= sizeof(uart_received));
    memcpy(uart_received + uart_received_size, data, size);
    uart_received_size += size;
    write_budget -= size;
    return size;
}

static void uart_done(int link_id, const struct wcom_tx_chunk *chunk, bool success)
{
    assert(link_id == current_link && success);
    response_completions++;
}

static void test_uart(void)
{
    static const uint8_t payload[] = "UART partial payload";
    wendy_com_uart_t uart = { .fd = 4, .write_bytes = uart_write, .write_ready = uart_ready };
    current_link = wcom_add_uart_link(&uart, interrupted);
    assert(current_link > 0);
    struct wcom_link *link = _get_link(current_link);
    struct wcom_tx_chunk chunk = {
        .data = payload, .size = sizeof(payload), .done_handler = uart_done,
    };
    wcom_send(current_link, &chunk);
    write_budget = uart_scenario == UART_INITIAL ? 3 : 0;
    if (uart_scenario == UART_WANT_READ) {
        link->tx_need_read = true;
        write_budget = sizeof(payload);
    }
    if (!setjmp(main_idle))
        _main(NULL);
    assert(response_completions == 1 && !disconnections && !interruptions);
    assert(!link->tx_chunk_first && !link->tx_deadline_us);
    assert(uart_received_size == sizeof(payload));
    assert(memcmp(uart_received, payload, sizeof(payload)) == 0);
    assert(select_calls == (uart_scenario == UART_WANT_READ ? 1 : 3));
}

// Run TX and the deferred SensorLink continuation as separate event-loop
// turns. There are no other operations in this test's queue.
static void drain_tx(struct wcom_link *link)
{
    struct wcom_operation *op;
    do {
        _link_do_tx(link);
        op = atomic_exchange(&_op_queue_head, NULL);
        if (op) {
            assert(!op->next);
            op->func(op);
        }
    } while (op && write_budget > 0);
}

static void test_stall(bool stream, bool want_read, bool partial)
{
    blocked_result = want_read ? WCOM_STREAM_ERR_WANT_READ : WCOM_STREAM_ERR_WANT_WRITE;
    int old_id = open_link(stream);
    struct wcom_link *slot = _get_link(old_id);
    push_frame(32768);
    int64_t deadline = slot->tx_deadline_us;
    write_budget = partial ? 64 : 0;
    drain_tx(slot);
    assert(!_expire_stalled_tx(slot, now_us));
    assert(_streams[0].frame.busy && _streams[0].active && !frame_completions);
    assert(partial ? slot->tx_chunk_offset > 0 : slot->tx_chunk_offset == 0);
    assert(slot->tx_need_read == want_read);

    // Appending traffic must not keep an already stalled queue alive.
    now_us += WCOM_TX_STALL_TIMEOUT_US / 2;
    static const uint8_t response = 42;
    struct wcom_tx_chunk reply = {
        .data = &response, .size = 1, .done_handler = response_done,
    };
    wcom_send(old_id, &reply);
    assert(slot->tx_deadline_us == deadline);
    now_us = deadline - 1;
    assert(!_expire_stalled_tx(slot, now_us));
    expected_wait_us = 1;
    if (!setjmp(main_idle))
        _main(NULL);
    assert(frame_completions == 1 && response_completions == 1);
    assert(disconnections == 1 && interruptions == 1);
    assert(!_streams[0].frame.busy && !_streams[0].active && !slot->tx_deadline_us);
    assert(!_get_link(old_id));
    assert(!_expire_stalled_tx(slot, now_us + WCOM_TX_STALL_TIMEOUT_US));
    wcom_close(old_id);
    assert(disconnections == 1 && interruptions == 1 && frame_completions == 1);

    // Reuse the same storage for a new connection. The old deadline and old
    // link id must not terminate it or leave the global sensor slot occupied.
    now_us += WCOM_TX_STALL_TIMEOUT_US;
    current_client++;
    int new_id = open_link(stream);
    assert(new_id != old_id && _get_link(new_id) == slot);
    assert(!slot->tx_deadline_us);
    push_frame(32768);
    wcom_close(old_id);
    assert(!_expire_stalled_tx(slot, now_us));
    assert(_get_link(new_id) == slot && slot->state == WCOM_LINK_STATE_CONNECTED);
    write_budget = SIZE_MAX;
    drain_tx(slot);
    assert(frame_completions == 2 && !_streams[0].frame.busy && !slot->tx_deadline_us);
    assert(disconnections == 1 && interruptions == 1);
}

static void test_progress(void)
{
    int id = open_link(false);
    struct wcom_link *link = _get_link(id);
    push_frame(256 * 1024);
    int64_t started = now_us;
    for (unsigned i = 0; i < 8; ++i) {
        now_us += WCOM_TX_STALL_TIMEOUT_US - 1;
        assert(!_expire_stalled_tx(link, now_us));
        write_budget = 16384;
        drain_tx(link);
        assert(_streams[0].frame.busy && !frame_completions);
        assert(link->tx_deadline_us == now_us + WCOM_TX_STALL_TIMEOUT_US);
    }
    assert(now_us - started > WCOM_TX_STALL_TIMEOUT_US * 7);
    write_budget = SIZE_MAX;
    drain_tx(link);
    assert(frame_completions == 1 && !_streams[0].frame.busy && !link->tx_deadline_us);
    now_us += WCOM_TX_STALL_TIMEOUT_US * 2;
    assert(_tx_stall_delay(link, now_us) == -1 && !_expire_stalled_tx(link, now_us));
    assert(!disconnections && !interruptions);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    static struct wcom_state_change_handler handler = { .func = state_changed };
    wcom_add_state_change_handler(&handler);
    if (!strcmp(argv[1], "socket")) test_stall(false, false, true);
    else if (!strcmp(argv[1], "stream")) test_stall(true, false, true);
    else if (!strcmp(argv[1], "want_read")) test_stall(false, true, true);
    else if (!strcmp(argv[1], "no_bytes")) test_stall(false, false, false);
    else if (!strcmp(argv[1], "progress")) test_progress();
    else if (!strcmp(argv[1], "uart_initial")) { uart_scenario = UART_INITIAL; test_uart(); }
    else if (!strcmp(argv[1], "uart_full")) { uart_scenario = UART_FULL; test_uart(); }
    else if (!strcmp(argv[1], "uart_want_read")) { uart_scenario = UART_WANT_READ; test_uart(); }
    else assert(!"unknown scenario");
    return 0;
}
