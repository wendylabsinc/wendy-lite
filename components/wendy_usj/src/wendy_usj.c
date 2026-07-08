#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "driver/usb_serial_jtag_select.h"
#include "esp_log.h"

#include "wendy_com.h"
#include "wendy_com_uart.h"
#include "wendy_com_link.h"
#include "wendy_usj.h"

#define TAG              "wendy_usj"
#define TX_BUF_SIZE      1024
#define RX_BUF_SIZE      3000
#define LOG_BUF_SIZE      256
#define TX_TIMEOUT_MS     500
#define POLL_INTERVAL_MS 1000
#define ESC              0x1B

typedef enum {
    USJ_MODE_OFF     = 0,
    USJ_MODE_CONSOLE = 1,
    USJ_MODE_ECHO    = 2,
    USJ_MODE_COM     = 3,
} usj_mode_t;

static vprintf_like_t s_orig_vprintf;
static atomic_int s_mode;

static int s_com_link_id = -1;
static wendy_com_uart_t s_com_uart;
static atomic_bool s_host_disconnected;


static void _handle_esc_command(uint8_t cmd);

static void _on_com_state_change(struct wcom_state_change_handler *handler,
                                int link_id, enum wcom_link_state state)
{
    if (link_id != s_com_link_id || state == WCOM_LINK_STATE_CONNECTED)
        return;

    s_com_link_id = -1;
    wcom_remove_link(link_id);

    if (s_com_uart.fd >= 0) {
        close(s_com_uart.fd);
        s_com_uart.fd = -1;
    }

    if (s_com_uart.last_esc_cmd) {
        _handle_esc_command(s_com_uart.last_esc_cmd);
    } else {
        ESP_LOGI(TAG, "mode -> off");
        atomic_store(&s_mode, USJ_MODE_OFF);
    }
}

static void _enter_com_exec(struct wcom_operation *op)
{
    static struct wcom_state_change_handler handler;
    if (!handler.func) {
        handler.func = _on_com_state_change;
        wcom_add_state_change_handler(&handler);
    }

    usb_serial_jtag_vfs_set_tx_line_endings(ESP_LINE_ENDINGS_LF);
    usb_serial_jtag_vfs_set_rx_line_endings(ESP_LINE_ENDINGS_LF);
    int fd = open("/dev/usbserjtag", O_RDWR | O_NOCTTY);
    if (fd < 0) {
        atomic_store(&s_mode, USJ_MODE_OFF);
        return;
    }

    struct termios tios;
    if (tcgetattr(fd, &tios) < 0)
        ESP_LOGE(TAG, "tcgetattr (before): errno=%d", errno);
    ESP_LOGI(TAG, "termios before: c_iflag=0x%08lx c_oflag=0x%08lx", (unsigned long)tios.c_iflag, (unsigned long)tios.c_oflag);
    tios.c_oflag = 0;
    tios.c_iflag = 0;
    if (tcsetattr(fd, TCSANOW, &tios) < 0)
        ESP_LOGE(TAG, "tcsetattr: errno=%d", errno);
    if (tcgetattr(fd, &tios) < 0)
        ESP_LOGE(TAG, "tcgetattr (after): errno=%d", errno);
    ESP_LOGI(TAG, "termios after:  c_iflag=0x%08lx c_oflag=0x%08lx", (unsigned long)tios.c_iflag, (unsigned long)tios.c_oflag);

    wendy_com_uart_init(&s_com_uart, fd);

    int link_id = wcom_add_uart_link(&s_com_uart);
    if (link_id < 0) {
        close(fd);
        s_com_uart.fd = -1;
        atomic_store(&s_mode, USJ_MODE_OFF);
        return;
    }
    s_com_link_id = link_id;
}

static void _handle_esc_command(uint8_t cmd)
{
    static struct wcom_operation op;
    switch (cmd) {
        case WENDY_COM_UART_ESC_CMD_CONSOLE:
            ESP_LOGI(TAG, "mode -> console");
            atomic_store(&s_mode, USJ_MODE_CONSOLE);
            break;
        case WENDY_COM_UART_ESC_CMD_ECHO:
            ESP_LOGI(TAG, "mode -> echo");
            atomic_store(&s_mode, USJ_MODE_ECHO);
            break;
        case WENDY_COM_UART_ESC_CMD_COM:
            ESP_LOGI(TAG, "mode -> com");
            atomic_store(&s_mode, USJ_MODE_COM);
            op.func = _enter_com_exec;
            wcom_exec(&op);
            break;
        case WENDY_COM_UART_ESC_CMD_OFF:
            ESP_LOGI(TAG, "mode -> off");
            atomic_store(&s_mode, USJ_MODE_OFF);
            break;
        case WENDY_COM_UART_ESC_CMD_KEEP_ALIVE:
        case WENDY_COM_UART_ESC_CMD_ESC:
            // not applicable here, ignore
            break;
        default:
            break;
    }
}

static void _task_main(void *arg)
{
    uint8_t buf[256];
    bool esc_pending = false;

    for (;;) {
        usj_mode_t mode = atomic_load(&s_mode);

        if (mode == USJ_MODE_COM) {
            vTaskDelay(pdMS_TO_TICKS(POLL_INTERVAL_MS));
            continue;
        }

        int n = usb_serial_jtag_read_bytes(buf, sizeof(buf), pdMS_TO_TICKS(POLL_INTERVAL_MS));
        if (n <= 0)
            continue;

        for (int i = 0; i < n; i++) {
            uint8_t b = buf[i];
            if (b == ESC) {
                esc_pending = true;
            } else if (esc_pending) {
                _handle_esc_command(b);
                esc_pending = false;
                mode = atomic_load(&s_mode);
            } else if (mode == USJ_MODE_ECHO) {
                usb_serial_jtag_write_bytes(&b, 1, pdMS_TO_TICKS(1000));
            }
        }
    }
}

static int _log_printf(const char *fmt, va_list args)
{
    va_list copy;
    va_copy(copy, args);
    int ret = s_orig_vprintf(fmt, copy);
    va_end(copy);

    char buf[LOG_BUF_SIZE];
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    if (len >= (int)sizeof(buf)) {
        char *buf = malloc(len + 1);
        if (buf) {
            vsnprintf(buf, len + 1, fmt, args);
            wendy_usj_write(buf, (size_t)len);
            free(buf);
        }
    } else if (len > 0) {
        wendy_usj_write(buf, (size_t)len);
    }
    return ret;
}

esp_err_t wendy_usj_init(void)
{
    usb_serial_jtag_driver_config_t cfg = {
        .tx_buffer_size = TX_BUF_SIZE,
        .rx_buffer_size = RX_BUF_SIZE,
    };
    esp_err_t err = usb_serial_jtag_driver_install(&cfg);
    if (err != ESP_OK)
        return err;

    err = usb_serial_jtag_vfs_register();
    if (err != ESP_OK)
        return err;

    usb_serial_jtag_vfs_use_driver();
    s_com_uart.fd = -1;
    atomic_store(&s_mode, USJ_MODE_CONSOLE);
    s_orig_vprintf = esp_log_set_vprintf(_log_printf);

    BaseType_t ret = xTaskCreate(_task_main, "wendy_usj", 4096, NULL,
                                 tskIDLE_PRIORITY + 1, NULL);
    if (ret != pdPASS)
        return ESP_ERR_NO_MEM;

    return ESP_OK;
}

void wendy_usj_write(const void *data, size_t len)
{
    if (atomic_load(&s_mode) != USJ_MODE_CONSOLE)
        return;
    if (s_host_disconnected) {
        if (usb_serial_jtag_write_ready() && usb_serial_jtag_write_bytes("...", 3, 1) == 3) {
            s_host_disconnected = false;
        }
    } else {
        int rv = usb_serial_jtag_write_bytes(data, len, pdMS_TO_TICKS(TX_TIMEOUT_MS));
        if (rv == 0) {
            s_host_disconnected = true;
        }
    }
}
