#include "usb_management.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>
#include "esp_vfs_eventfd.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "tinyusb.h"
#include "tinyusb_cdc_acm.h"
#include "wendy_com.h"
#include "wendy_com_link.h"
#include "wendy_com_uart.h"
#include "wendy_stdio.h"

enum usb_mode { USB_OFF, USB_CONSOLE, USB_ECHO, USB_COM };
static atomic_int mode = USB_CONSOLE;
static atomic_int wake_fd = -1;
static wendy_com_uart_t wire;
static SemaphoreHandle_t tx_lock;
static StaticSemaphore_t tx_lock_storage;
static wendy_stdio_out_data_handler_t previous_output;

static void wake_reader(void)
{
    int fd = atomic_load(&wake_fd);
    if (fd >= 0) {
        uint64_t one = 1;
        write(fd, &one, sizeof one);
    }
}

static void usb_event(int itf, cdcacm_event_t *event)
{
    (void)itf;
    (void)event;
    wake_reader();
}

static ssize_t usb_read(void *data, size_t size)
{
    if (!tud_cdc_n_connected(0)) return 0;
    size_t n = 0;
    if (tinyusb_cdcacm_read(0, data, size, &n) != ESP_OK) {
        errno = EIO;
        return -1;
    }
    if (n) return (ssize_t)n;
    errno = EAGAIN;
    return -1;
}

static bool usb_read_ready(void)
{
    return !tud_cdc_n_connected(0) || tud_cdc_n_available(0) > 0;
}

static bool usb_write_ready(void)
{
    return tud_cdc_n_connected(0) && tud_cdc_n_write_available(0) > 0;
}

static ssize_t usb_write(const void *data, size_t size)
{
    if (!tud_cdc_n_connected(0)) return WENDY_COM_UART_ERR_UNKNOWN;
    if (xSemaphoreTake(tx_lock, 0) != pdTRUE) return WENDY_COM_UART_ERR_WANT_WRITE;
    size_t n = tinyusb_cdcacm_write_queue(0, data, size);
    tinyusb_cdcacm_write_flush(0, 0);
    xSemaphoreGive(tx_lock);
    return n ? (ssize_t)n : WENDY_COM_UART_ERR_WANT_WRITE;
}

static void set_mode(enum usb_mode value)
{
    /* Stop console output before publishing a binary protocol connection. */
    xSemaphoreTake(tx_lock, portMAX_DELAY);
    atomic_store(&mode, value);
    xSemaphoreGive(tx_lock);
}

static void command(uint8_t byte);

static void interrupted(int link, enum wcom_interruption_reason reason)
{
    (void)reason;
    uint8_t next = wire.last_esc_cmd;
    wcom_remove_link(link);
    set_mode(USB_OFF);
    if (next) command(next);
}

static void enter_com(struct wcom_operation *op)
{
    (void)op;
    int fd = atomic_load(&wake_fd);
    if (fd < 0) {
        fd = eventfd(0, 0);
        if (fd < 0) { set_mode(USB_OFF); return; }
        atomic_store(&wake_fd, fd);
    }
    wendy_com_uart_init(&wire, fd);
    wire.read_bytes = usb_read;
    wire.read_ready = usb_read_ready;
    wire.write_bytes = usb_write;
    wire.write_ready = usb_write_ready;
    if (wcom_add_uart_link(&wire, interrupted) < 0) set_mode(USB_OFF);
    wake_reader();
}

static void command(uint8_t byte)
{
    static struct wcom_operation op = {.func = enter_com};
    switch (byte) {
    case WENDY_COM_UART_ESC_CMD_CONSOLE: set_mode(USB_CONSOLE); break;
    case WENDY_COM_UART_ESC_CMD_OFF: set_mode(USB_OFF); break;
    case WENDY_COM_UART_ESC_CMD_ECHO:
        set_mode(wcom_is_running() ? USB_ECHO : USB_OFF);
        break;
    case WENDY_COM_UART_ESC_CMD_COM:
        if (!wcom_is_running()) { set_mode(USB_OFF); break; }
        set_mode(USB_COM);
        wcom_exec(&op);
        break;
    default: break;
    }
}

static void console_output(const void *data, size_t size)
{
    if (previous_output) previous_output(data, size);
    if (xSemaphoreTake(tx_lock, 0) != pdTRUE) return;
    if (atomic_load(&mode) == USB_CONSOLE && tud_cdc_n_connected(0)) {
        tinyusb_cdcacm_write_queue(0, data, size);
        tinyusb_cdcacm_write_flush(0, 0);
    }
    xSemaphoreGive(tx_lock);
}

static void usb_task(void *arg)
{
    (void)arg;
    bool escaped = false;
    for (;;) {
        if (atomic_load(&mode) == USB_COM) {
            /* Also covers TX completion and cable removal without an RX event. */
            wake_reader();
        } else if (tud_cdc_n_connected(0)) {
            uint8_t byte;
            while (atomic_load(&mode) != USB_COM && usb_read(&byte, 1) == 1) {
                if (byte == WENDY_COM_UART_ESC) escaped = true;
                else if (escaped) { escaped = false; command(byte); }
                else if (atomic_load(&mode) == USB_ECHO) usb_write(&byte, 1);
                else if (atomic_load(&mode) == USB_CONSOLE) wendy_stdio_put_stdin_data(&byte, 1);
            }
        } else escaped = false;
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

esp_err_t mosaico_usb_management_start(void)
{
    if (!tinyusb_cdcacm_initialized(0)) return ESP_ERR_INVALID_STATE;
    tx_lock = xSemaphoreCreateMutexStatic(&tx_lock_storage);
    tinyusb_cdcacm_register_callback(0, CDC_EVENT_RX, usb_event);
    tinyusb_cdcacm_register_callback(0, CDC_EVENT_LINE_STATE_CHANGED, usb_event);
    if (xTaskCreate(usb_task, "mosaico_com", 4096, NULL, 2, NULL) != pdPASS)
        return ESP_ERR_NO_MEM;
    previous_output = wendy_stdio_set_out_data_handler(console_output);
    return ESP_OK;
}
