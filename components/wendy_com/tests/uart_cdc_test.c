/* The CDC adapter shares the production serial escape parser. Exercise short
 * reads, protocol mode changes, no-progress reads, and transmit backpressure. */
#include <assert.h>
#include <errno.h>
#include <string.h>
#include "../src/wendy_com_uart.c"

static int64_t now;
static const uint8_t *incoming;
static size_t incoming_size, incoming_offset;
static bool connected = true;
static uint8_t outgoing[32];
static size_t outgoing_size, capacity;
int64_t esp_timer_get_time(void) { return now; }

static ssize_t rx(void *data, size_t size)
{
    if (!connected) return 0;
    if (incoming_offset == incoming_size) { errno = EAGAIN; return -1; }
    if (size > 3) size = 3;
    if (size > incoming_size - incoming_offset) size = incoming_size - incoming_offset;
    memcpy(data, incoming + incoming_offset, size);
    incoming_offset += size;
    return size;
}
static ssize_t tx(const void *data, size_t size)
{
    if (!capacity) return WENDY_COM_UART_ERR_WANT_WRITE;
    if (size > capacity) size = capacity;
    memcpy(outgoing + outgoing_size, data, size);
    outgoing_size += size;
    capacity -= size;
    return size;
}
int main(void)
{
    wendy_com_uart_t uart;
    wendy_com_uart_init(&uart, -1);
    uart.read_bytes = rx;
    uart.write_bytes = tx;
    const uint8_t encoded[] = {'a', 0x10, '_', 'b', 0x10, 'k', 'c', 0x10, 'o'};
    incoming = encoded; incoming_size = sizeof encoded;
    uint8_t result[16];
    assert(wendy_com_uart_read(&uart, result, sizeof result) == 4);
    const uint8_t expected[] = {'a', 0x10, 'b', 'c'};
    assert(!memcmp(result, expected, sizeof expected));
    assert(uart.last_esc_cmd == 'o' && uart.keepalive_seen);
    assert(wendy_com_uart_read(&uart, result, sizeof result) == 0);
    assert(wendy_com_uart_read(&uart, result, sizeof result) == WENDY_COM_UART_ERR_WANT_READ);
    now = 12000001;
    assert(wendy_com_uart_read(&uart, result, sizeof result) == 0);
    connected = false;
    assert(wendy_com_uart_read(&uart, result, sizeof result) == 0);
    capacity = 2;
    assert(wendy_com_uart_write(&uart, expected, sizeof expected) == 2);
    assert(wendy_com_uart_write(&uart, expected + 2, 2) == WENDY_COM_UART_ERR_WANT_WRITE);
    capacity = 2;
    assert(wendy_com_uart_write(&uart, expected + 2, 2) == 2);
    assert(outgoing_size == sizeof expected && !memcmp(outgoing, expected, sizeof expected));
}
