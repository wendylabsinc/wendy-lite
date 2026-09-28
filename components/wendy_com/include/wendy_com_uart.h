#ifndef WENDY_COM_UART_H
#define WENDY_COM_UART_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WENDY_COM_UART_ERR_UNKNOWN    -1
#define WENDY_COM_UART_ERR_WANT_READ  -2
#define WENDY_COM_UART_ERR_WANT_WRITE -3

#define WENDY_COM_UART_RAW_BUF_SIZE 256

#define WENDY_COM_UART_ESC 0x10 // CTRL-P, aka DLE (Data Link Escape)

typedef enum wendy_com_uart_esc_cmd {
    WENDY_COM_UART_ESC_CMD_CONSOLE    = 'c',
    WENDY_COM_UART_ESC_CMD_ECHO       = 'e',
    WENDY_COM_UART_ESC_CMD_KEEP_ALIVE = 'k',
    WENDY_COM_UART_ESC_CMD_COM        = 'm',
    WENDY_COM_UART_ESC_CMD_OFF        = 'o',
    WENDY_COM_UART_ESC_CMD_ESC        = '_',
} wendy_com_uart_esc_cmd_t;

typedef struct wendy_com_uart {
    int fd;
    uint8_t raw_buf[WENDY_COM_UART_RAW_BUF_SIZE];
    int raw_pos;
    int raw_len;
    bool pending_esc;
    bool eof_pending;
    uint8_t last_esc_cmd;
    int64_t last_rx_us;  // esp_timer_get_time() of the last receive activity
    bool keepalive_seen; // true once a DLE 'k' has been received on this link
} wendy_com_uart_t;

void wendy_com_uart_init(wendy_com_uart_t *uart, int fd);
ssize_t wendy_com_uart_read(wendy_com_uart_t *uart, void *data, size_t datalen);
ssize_t wendy_com_uart_write(wendy_com_uart_t *uart, const void *data, size_t datalen);
int wendy_com_uart_get_fd(wendy_com_uart_t *uart);
int64_t wendy_com_uart_auto_close_delay(wendy_com_uart_t *uart);

#ifdef __cplusplus
}
#endif

#endif
