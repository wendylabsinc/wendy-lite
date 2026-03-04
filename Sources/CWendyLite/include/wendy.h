/**
 * wendy.h — C header for WASM applications targeting Wendy MCU.
 *
 * This header declares all host-imported functions from the "wendy"
 * module. Include this in your WASM app source files.
 *
 * Build your app with:
 *   clang --target=wasm32 -O2 -nostdlib \
 *     -I path/to/wasm_apps/include \
 *     -Wl,--no-entry -Wl,--export=_start \
 *     -Wl,--allow-undefined \
 *     -o app.wasm app.c
 */

#pragma once

/* ── GPIO ───────────────────────────────────────────────────────────── */

#define WENDY_GPIO_INPUT        0
#define WENDY_GPIO_OUTPUT       1
#define WENDY_GPIO_INPUT_OUTPUT 2

#define WENDY_GPIO_PULL_NONE    0
#define WENDY_GPIO_PULL_UP      1
#define WENDY_GPIO_PULL_DOWN    2

#define WENDY_GPIO_INTR_RISING  1
#define WENDY_GPIO_INTR_FALLING 2
#define WENDY_GPIO_INTR_ANYEDGE 3

__attribute__((import_module("wendy"), import_name("gpio_configure")))
int gpio_configure(int pin, int mode, int pull);

__attribute__((import_module("wendy"), import_name("gpio_read")))
int gpio_read(int pin);

__attribute__((import_module("wendy"), import_name("gpio_write")))
int gpio_write(int pin, int level);

__attribute__((import_module("wendy"), import_name("gpio_set_pwm")))
int gpio_set_pwm(int pin, int freq_hz, int duty_pct);

__attribute__((import_module("wendy"), import_name("gpio_analog_read")))
int gpio_analog_read(int pin);

__attribute__((import_module("wendy"), import_name("gpio_set_interrupt")))
int gpio_set_interrupt(int pin, int edge_type, int handler_id);

__attribute__((import_module("wendy"), import_name("gpio_clear_interrupt")))
int gpio_clear_interrupt(int pin);

/* ── I2C ────────────────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("i2c_init")))
int i2c_init(int bus, int sda, int scl, int freq_hz);

__attribute__((import_module("wendy"), import_name("i2c_scan")))
int i2c_scan(int bus, unsigned char *addrs_out, int max_addrs);

__attribute__((import_module("wendy"), import_name("i2c_write")))
int i2c_write(int bus, int addr, const unsigned char *data, int len);

__attribute__((import_module("wendy"), import_name("i2c_read")))
int i2c_read(int bus, int addr, unsigned char *buf, int len);

__attribute__((import_module("wendy"), import_name("i2c_write_read")))
int i2c_write_read(int bus, int addr,
                    const unsigned char *wr, int wr_len,
                    unsigned char *rd, int rd_len);

/* ── RMT (timing-buffer) ───────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("rmt_configure")))
int rmt_configure(int pin, int resolution_hz);

__attribute__((import_module("wendy"), import_name("rmt_transmit")))
int rmt_transmit(int channel_id, const unsigned char *buf, int len);

__attribute__((import_module("wendy"), import_name("rmt_release")))
int rmt_release(int channel_id);

/* ── NeoPixel (WS2812) ─────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("neopixel_init")))
int neopixel_init(int pin, int num_leds);

__attribute__((import_module("wendy"), import_name("neopixel_set")))
int neopixel_set(int index, int r, int g, int b);

__attribute__((import_module("wendy"), import_name("neopixel_clear")))
int neopixel_clear(void);

/* ── Timer ──────────────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("timer_delay_ms")))
void timer_delay_ms(int ms);

__attribute__((import_module("wendy"), import_name("timer_millis")))
long long timer_millis(void);

__attribute__((import_module("wendy"), import_name("timer_set_timeout")))
int timer_set_timeout(int ms, int handler_id);

__attribute__((import_module("wendy"), import_name("timer_set_interval")))
int timer_set_interval(int ms, int handler_id);

__attribute__((import_module("wendy"), import_name("timer_cancel")))
int timer_cancel(int timer_id);

/* ── Console output ─────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("wendy_print")))
int wendy_print(const char *buf, int len);

/* ── System ─────────────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("sys_uptime_ms")))
long long sys_uptime_ms(void);

__attribute__((import_module("wendy"), import_name("sys_reboot")))
void sys_reboot(void);

__attribute__((import_module("wendy"), import_name("sys_firmware_version")))
int sys_firmware_version(char *buf, int len);

__attribute__((import_module("wendy"), import_name("sys_device_id")))
int sys_device_id(char *buf, int len);

__attribute__((import_module("wendy"), import_name("sys_sleep_ms")))
void sys_sleep_ms(int ms);

__attribute__((import_module("wendy"), import_name("sys_yield")))
void sys_yield(void);

/* ── Storage (NVS) ──────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("storage_get")))
int storage_get(const char *key, int key_len, char *val, int val_len);

__attribute__((import_module("wendy"), import_name("storage_set")))
int storage_set(const char *key, int key_len, const char *val, int val_len);

__attribute__((import_module("wendy"), import_name("storage_delete")))
int storage_delete(const char *key, int key_len);

__attribute__((import_module("wendy"), import_name("storage_exists")))
int storage_exists(const char *key, int key_len);

/* ── UART ───────────────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("uart_open")))
int uart_open(int port, int tx_pin, int rx_pin, int baud);

__attribute__((import_module("wendy"), import_name("uart_close")))
int uart_close(int port);

__attribute__((import_module("wendy"), import_name("uart_write")))
int uart_write(int port, const char *data, int len);

__attribute__((import_module("wendy"), import_name("uart_read")))
int uart_read(int port, char *buf, int len);

__attribute__((import_module("wendy"), import_name("uart_available")))
int uart_available(int port);

__attribute__((import_module("wendy"), import_name("uart_flush")))
int uart_flush(int port);

__attribute__((import_module("wendy"), import_name("uart_set_on_receive")))
int uart_set_on_receive(int port, int handler_id);

/* ── SPI ────────────────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("spi_open")))
int spi_open(int host, int mosi, int miso, int sclk, int cs, int clock_hz);

__attribute__((import_module("wendy"), import_name("spi_close")))
int spi_close(int dev_id);

__attribute__((import_module("wendy"), import_name("spi_transfer")))
int spi_transfer(int dev_id, unsigned char *tx_buf, unsigned char *rx_buf, int len);

/* ── OpenTelemetry ──────────────────────────────────────────────────── */

#define WENDY_OTEL_ERROR 1
#define WENDY_OTEL_WARN  2
#define WENDY_OTEL_INFO  3
#define WENDY_OTEL_DEBUG 4

__attribute__((import_module("wendy"), import_name("otel_log")))
int otel_log(int level, const char *msg, int msg_len);

__attribute__((import_module("wendy"), import_name("otel_metric_counter_add")))
int otel_metric_counter_add(const char *name, int name_len, long long value);

__attribute__((import_module("wendy"), import_name("otel_metric_gauge_set")))
int otel_metric_gauge_set(const char *name, int name_len, double value);

__attribute__((import_module("wendy"), import_name("otel_metric_histogram_record")))
int otel_metric_histogram_record(const char *name, int name_len, double value);

__attribute__((import_module("wendy"), import_name("otel_span_start")))
int otel_span_start(const char *name, int name_len);

__attribute__((import_module("wendy"), import_name("otel_span_set_attribute")))
int otel_span_set_attribute(int span_id, const char *key, int key_len,
                             const char *val, int val_len);

__attribute__((import_module("wendy"), import_name("otel_span_set_status")))
int otel_span_set_status(int span_id, int status);

__attribute__((import_module("wendy"), import_name("otel_span_end")))
int otel_span_end(int span_id);

/* ── BLE ────────────────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("ble_init")))
int ble_init(void);

__attribute__((import_module("wendy"), import_name("ble_advertise_start")))
int ble_advertise_start(const char *name, int name_len);

__attribute__((import_module("wendy"), import_name("ble_advertise_stop")))
int ble_advertise_stop(void);

__attribute__((import_module("wendy"), import_name("ble_scan_start")))
int ble_scan_start(int duration_ms, int handler_id);

__attribute__((import_module("wendy"), import_name("ble_scan_stop")))
int ble_scan_stop(void);

__attribute__((import_module("wendy"), import_name("ble_connect")))
int ble_connect(int addr_type, const char *addr, int addr_len, int handler_id);

__attribute__((import_module("wendy"), import_name("ble_disconnect")))
int ble_disconnect(int conn_handle);

__attribute__((import_module("wendy"), import_name("ble_gatts_add_service")))
int ble_gatts_add_service(const char *uuid, int uuid_len);

__attribute__((import_module("wendy"), import_name("ble_gatts_add_characteristic")))
int ble_gatts_add_characteristic(int svc_id, const char *uuid, int uuid_len, int flags);

__attribute__((import_module("wendy"), import_name("ble_gatts_set_value")))
int ble_gatts_set_value(int chr_id, const char *data, int data_len);

__attribute__((import_module("wendy"), import_name("ble_gatts_notify")))
int ble_gatts_notify(int chr_id, int conn_handle);

__attribute__((import_module("wendy"), import_name("ble_gatts_on_write")))
int ble_gatts_on_write(int chr_id, int handler_id);

__attribute__((import_module("wendy"), import_name("ble_gattc_discover")))
int ble_gattc_discover(int conn_handle, int handler_id);

__attribute__((import_module("wendy"), import_name("ble_gattc_read")))
int ble_gattc_read(int conn_handle, int attr_handle, int handler_id);

__attribute__((import_module("wendy"), import_name("ble_gattc_write")))
int ble_gattc_write(int conn_handle, int attr_handle, const char *data, int data_len);

/* ── WiFi (app-facing) ──────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("wifi_connect")))
int wifi_connect(const char *ssid, int ssid_len, const char *pass, int pass_len);

__attribute__((import_module("wendy"), import_name("wifi_disconnect")))
int wifi_disconnect(void);

__attribute__((import_module("wendy"), import_name("wifi_status")))
int wifi_status(void);

__attribute__((import_module("wendy"), import_name("wifi_get_ip")))
int wifi_get_ip(char *buf, int len);

__attribute__((import_module("wendy"), import_name("wifi_rssi")))
int wifi_rssi(void);

__attribute__((import_module("wendy"), import_name("wifi_ap_start")))
int wifi_ap_start(const char *ssid, int ssid_len,
                   const char *pass, int pass_len, int channel);

__attribute__((import_module("wendy"), import_name("wifi_ap_stop")))
int wifi_ap_stop(void);

/* ── Sockets ────────────────────────────────────────────────────────── */

#define WENDY_AF_INET     2
#define WENDY_SOCK_STREAM 1
#define WENDY_SOCK_DGRAM  2

__attribute__((import_module("wendy"), import_name("net_socket")))
int net_socket(int domain, int type, int protocol);

__attribute__((import_module("wendy"), import_name("net_connect")))
int net_connect(int fd, const char *ip, int ip_len, int port);

__attribute__((import_module("wendy"), import_name("net_bind")))
int net_bind(int fd, int port);

__attribute__((import_module("wendy"), import_name("net_listen")))
int net_listen(int fd, int backlog);

__attribute__((import_module("wendy"), import_name("net_accept")))
int net_accept(int fd);

__attribute__((import_module("wendy"), import_name("net_send")))
int net_send(int fd, const char *data, int len);

__attribute__((import_module("wendy"), import_name("net_recv")))
int net_recv(int fd, char *buf, int len);

__attribute__((import_module("wendy"), import_name("net_close")))
int net_close(int fd);

/* ── DNS ────────────────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("dns_resolve")))
int dns_resolve(const char *hostname, int hostname_len,
                 char *result_buf, int result_len);

/* ── TLS ────────────────────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("tls_connect")))
int tls_connect(const char *host, int host_len, int port);

__attribute__((import_module("wendy"), import_name("tls_send")))
int tls_send(int fd, const char *data, int len);

__attribute__((import_module("wendy"), import_name("tls_recv")))
int tls_recv(int fd, char *buf, int len);

__attribute__((import_module("wendy"), import_name("tls_close")))
int tls_close(int fd);

/* ── USB (app-facing) ───────────────────────────────────────────────── */

__attribute__((import_module("wendy"), import_name("usb_cdc_write")))
int usb_cdc_write(const char *data, int len);

__attribute__((import_module("wendy"), import_name("usb_cdc_read")))
int usb_cdc_read(char *buf, int len);

__attribute__((import_module("wendy"), import_name("usb_hid_send_report")))
int usb_hid_send_report(int report_id, const char *data, int len);

/* ── Callback handler (WASM app must export this) ───────────────────── */

/*
 * Your WASM app should export this function to receive async callbacks
 * (timer, GPIO interrupts, BLE events, etc.):
 *
 * void wendy_handle_callback(int handler_id, int arg0, int arg1, int arg2);
 *
 * Callbacks are dispatched when you call sys_yield().
 */
