#include "wendy_com_uart.h"
#include "esp_timer.h"
#include <unistd.h>
#include <errno.h>

#define WCOM_UART_RX_TIMEOUT_US (12LL * 1000 * 1000) // 2x the client's 6s keep-alive interval

void wendy_com_uart_init(wendy_com_uart_t *uart, int fd)
{
    uart->fd = fd;
    uart->raw_pos = 0;
    uart->raw_len = 0;
    uart->pending_esc = false;
    uart->eof_pending = false;
    uart->last_esc_cmd = 0;
    uart->last_rx_us = esp_timer_get_time();
    uart->keepalive_seen = false;
}

ssize_t wendy_com_uart_read(wendy_com_uart_t *uart, void *data, size_t datalen)
{
    uint8_t *out = (uint8_t *)data;
    size_t written = 0;

    if (uart->eof_pending) {
        uart->eof_pending = false;
        return 0;
    }

    while (written < datalen) {
        if (uart->raw_pos >= uart->raw_len) {
            ssize_t n = read(uart->fd, uart->raw_buf, sizeof(uart->raw_buf));
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (written == 0 && uart->keepalive_seen &&
                        esp_timer_get_time() - uart->last_rx_us >= WCOM_UART_RX_TIMEOUT_US)
                        return 0; // no data, and silent too long: treat like a closed connection
                    return written > 0 ? (ssize_t)written : WENDY_COM_UART_ERR_WANT_READ;
                }
                return WENDY_COM_UART_ERR_UNKNOWN;
            }
            if (n == 0)
                return written > 0 ? (ssize_t)written : 0;
            uart->last_rx_us = esp_timer_get_time();
            uart->raw_pos = 0;
            uart->raw_len = (int)n;
        }

        uint8_t b = uart->raw_buf[uart->raw_pos++];

        if (b == WENDY_COM_UART_ESC) {
            uart->pending_esc = true;
        } else if (uart->pending_esc) {
            uart->pending_esc = false;
            switch (b) {
                case WENDY_COM_UART_ESC_CMD_ESC:
                    out[written++] = WENDY_COM_UART_ESC;
                    break;
                case WENDY_COM_UART_ESC_CMD_KEEP_ALIVE:
                    uart->keepalive_seen = true;
                    break;
                case WENDY_COM_UART_ESC_CMD_CONSOLE:
                case WENDY_COM_UART_ESC_CMD_ECHO:
                case WENDY_COM_UART_ESC_CMD_COM:
                case WENDY_COM_UART_ESC_CMD_OFF:
                    uart->last_esc_cmd = b;
                    if (written > 0) {
                        uart->eof_pending = true;
                        return (ssize_t)written;
                    }
                    return 0;
            }
        } else {
            out[written++] = b;
        }
    }

    return (ssize_t)written;
}

ssize_t wendy_com_uart_write(wendy_com_uart_t *uart, const void *data, size_t datalen)
{
    ssize_t n = write(uart->fd, data, datalen);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return WENDY_COM_UART_ERR_WANT_WRITE;
        return WENDY_COM_UART_ERR_UNKNOWN;
    }
    return n;
}

int wendy_com_uart_get_fd(wendy_com_uart_t *uart)
{
    return uart->fd;
}

int64_t wendy_com_uart_auto_close_delay(wendy_com_uart_t *uart)
{
    if (!uart->keepalive_seen)
        return -1;
    int64_t remaining = uart->last_rx_us + WCOM_UART_RX_TIMEOUT_US - esp_timer_get_time();
    return remaining > 0 ? remaining : 0;
}
