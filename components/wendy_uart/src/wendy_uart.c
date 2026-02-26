#include "wendy_uart.h"

#include <string.h>
#include "driver/uart.h"
#include "esp_log.h"
#include "wasm_export.h"

#if CONFIG_WENDY_CALLBACK
#include "wendy_callback.h"
#endif

static const char *TAG = "wendy_uart";

#define MAX_UART_PORTS 3

typedef struct {
    bool opened;
    uart_port_t port;
    uint32_t on_receive_handler;
} uart_state_t;

static uart_state_t s_uart[MAX_UART_PORTS];

/* uart_open(port, tx_pin, rx_pin, baud) -> 0 ok */
static int uart_open_wrapper(wasm_exec_env_t exec_env,
                              int port, int tx_pin, int rx_pin, int baud)
{
    if (port < 0 || port >= MAX_UART_PORTS) {
        return -1;
    }
    if (s_uart[port].opened) {
        return -1; /* already open */
    }

    uart_config_t uart_config = {
        .baud_rate  = baud,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    esp_err_t err = uart_driver_install(port, 1024, 256, 0, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "uart_driver_install(%d) failed: %s", port, esp_err_to_name(err));
        return -1;
    }

    err = uart_param_config(port, &uart_config);
    if (err != ESP_OK) {
        uart_driver_delete(port);
        return -1;
    }

    err = uart_set_pin(port, tx_pin, rx_pin, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) {
        uart_driver_delete(port);
        return -1;
    }

    s_uart[port].opened = true;
    s_uart[port].port = port;
    s_uart[port].on_receive_handler = 0;
    ESP_LOGI(TAG, "UART%d opened (tx=%d rx=%d baud=%d)", port, tx_pin, rx_pin, baud);
    return 0;
}

/* uart_close(port) -> 0 ok */
static int uart_close_wrapper(wasm_exec_env_t exec_env, int port)
{
    if (port < 0 || port >= MAX_UART_PORTS || !s_uart[port].opened) {
        return -1;
    }
    uart_driver_delete(port);
    s_uart[port].opened = false;
    s_uart[port].on_receive_handler = 0;
    return 0;
}

/* uart_write(port, data_ptr, data_len) -> bytes written */
static int uart_write_wrapper(wasm_exec_env_t exec_env,
                               int port, const char *data, int len)
{
    if (port < 0 || port >= MAX_UART_PORTS || !s_uart[port].opened) {
        return -1;
    }
    if (!data || len <= 0) {
        return -1;
    }
    return uart_write_bytes(port, data, len);
}

/* uart_read(port, buf_ptr, buf_len) -> bytes read */
static int uart_read_wrapper(wasm_exec_env_t exec_env,
                              int port, char *buf, int len)
{
    if (port < 0 || port >= MAX_UART_PORTS || !s_uart[port].opened) {
        return -1;
    }
    if (!buf || len <= 0) {
        return -1;
    }
    /* Non-blocking read with short timeout */
    return uart_read_bytes(port, buf, len, pdMS_TO_TICKS(10));
}

/* uart_available(port) -> bytes in rx buffer */
static int uart_available_wrapper(wasm_exec_env_t exec_env, int port)
{
    if (port < 0 || port >= MAX_UART_PORTS || !s_uart[port].opened) {
        return -1;
    }
    size_t buffered = 0;
    uart_get_buffered_data_len(port, &buffered);
    return (int)buffered;
}

/* uart_flush(port) -> 0 ok */
static int uart_flush_wrapper(wasm_exec_env_t exec_env, int port)
{
    if (port < 0 || port >= MAX_UART_PORTS || !s_uart[port].opened) {
        return -1;
    }
    uart_wait_tx_done(port, pdMS_TO_TICKS(100));
    return 0;
}

/* uart_set_on_receive(port, handler_id) -> 0 ok */
static int uart_set_on_receive_wrapper(wasm_exec_env_t exec_env,
                                        int port, int handler_id)
{
    if (port < 0 || port >= MAX_UART_PORTS || !s_uart[port].opened) {
        return -1;
    }
    s_uart[port].on_receive_handler = (uint32_t)handler_id;
    return 0;
}

static NativeSymbol s_uart_symbols[] = {
    { "uart_open",           (void *)uart_open_wrapper,           "(iiii)i", NULL },
    { "uart_close",          (void *)uart_close_wrapper,          "(i)i",    NULL },
    { "uart_write",          (void *)uart_write_wrapper,          "(i*~)i",  NULL },
    { "uart_read",           (void *)uart_read_wrapper,           "(i*~)i",  NULL },
    { "uart_available",      (void *)uart_available_wrapper,      "(i)i",    NULL },
    { "uart_flush",          (void *)uart_flush_wrapper,          "(i)i",    NULL },
    { "uart_set_on_receive", (void *)uart_set_on_receive_wrapper, "(ii)i",   NULL },
};

int wendy_uart_export_init(void)
{
    memset(s_uart, 0, sizeof(s_uart));

    if (!wasm_runtime_register_natives("wendy",
                                       s_uart_symbols,
                                       sizeof(s_uart_symbols) / sizeof(s_uart_symbols[0]))) {
        ESP_LOGE(TAG, "failed to register UART natives");
        return -1;
    }
    ESP_LOGI(TAG, "UART exports registered");
    return 0;
}
