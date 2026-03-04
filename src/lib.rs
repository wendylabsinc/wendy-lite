//! Wendy Lite — Rust bindings for WASM apps targeting Wendy MCU.
//!
//! Provides safe wrappers and raw FFI for all host-imported functions
//! from the `"wendy"` WASM module.
//!
//! # Example
//! ```no_run
//! use wendy_lite::gpio;
//!
//! #[no_mangle]
//! pub extern "C" fn _start() {
//!     gpio::configure(8, gpio::Mode::Output, gpio::Pull::None);
//!     loop {
//!         gpio::write(8, 1);
//!         wendy_lite::sys::sleep_ms(500);
//!         gpio::write(8, 0);
//!         wendy_lite::sys::sleep_ms(500);
//!     }
//! }
//! ```

#![no_std]

// ── Raw FFI ────────────────────────────────────────────────────────────

#[link(wasm_import_module = "wendy")]
extern "C" {
    // GPIO
    fn gpio_configure(pin: i32, mode: i32, pull: i32) -> i32;
    fn gpio_read(pin: i32) -> i32;
    fn gpio_write(pin: i32, level: i32) -> i32;
    fn gpio_set_pwm(pin: i32, freq_hz: i32, duty_pct: i32) -> i32;
    fn gpio_analog_read(pin: i32) -> i32;
    fn gpio_set_interrupt(pin: i32, edge_type: i32, handler_id: i32) -> i32;
    fn gpio_clear_interrupt(pin: i32) -> i32;

    // I2C
    fn i2c_init(bus: i32, sda: i32, scl: i32, freq_hz: i32) -> i32;
    fn i2c_scan(bus: i32, addrs_out: *mut u8, max_addrs: i32) -> i32;
    fn i2c_write(bus: i32, addr: i32, data: *const u8, len: i32) -> i32;
    fn i2c_read(bus: i32, addr: i32, buf: *mut u8, len: i32) -> i32;
    fn i2c_write_read(
        bus: i32, addr: i32,
        wr: *const u8, wr_len: i32,
        rd: *mut u8, rd_len: i32,
    ) -> i32;

    // RMT
    fn rmt_configure(pin: i32, resolution_hz: i32) -> i32;
    fn rmt_transmit(channel_id: i32, buf: *const u8, len: i32) -> i32;
    fn rmt_release(channel_id: i32) -> i32;

    // NeoPixel
    fn neopixel_init(pin: i32, num_leds: i32) -> i32;
    fn neopixel_set(index: i32, r: i32, g: i32, b: i32) -> i32;
    fn neopixel_clear() -> i32;

    // Timer
    fn timer_delay_ms(ms: i32);
    fn timer_millis() -> i64;
    fn timer_set_timeout(ms: i32, handler_id: i32) -> i32;
    fn timer_set_interval(ms: i32, handler_id: i32) -> i32;
    fn timer_cancel(timer_id: i32) -> i32;

    // Console
    fn wendy_print(buf: *const u8, len: i32) -> i32;

    // System
    fn sys_uptime_ms() -> i64;
    fn sys_reboot();
    fn sys_firmware_version(buf: *mut u8, len: i32) -> i32;
    fn sys_device_id(buf: *mut u8, len: i32) -> i32;
    fn sys_sleep_ms(ms: i32);
    fn sys_yield();

    // Storage (NVS)
    fn storage_get(key: *const u8, key_len: i32, val: *mut u8, val_len: i32) -> i32;
    fn storage_set(key: *const u8, key_len: i32, val: *const u8, val_len: i32) -> i32;
    fn storage_delete(key: *const u8, key_len: i32) -> i32;
    fn storage_exists(key: *const u8, key_len: i32) -> i32;

    // UART
    fn uart_open(port: i32, tx_pin: i32, rx_pin: i32, baud: i32) -> i32;
    fn uart_close(port: i32) -> i32;
    fn uart_write(port: i32, data: *const u8, len: i32) -> i32;
    fn uart_read(port: i32, buf: *mut u8, len: i32) -> i32;
    fn uart_available(port: i32) -> i32;
    fn uart_flush(port: i32) -> i32;
    fn uart_set_on_receive(port: i32, handler_id: i32) -> i32;

    // SPI
    fn spi_open(host: i32, mosi: i32, miso: i32, sclk: i32, cs: i32, clock_hz: i32) -> i32;
    fn spi_close(dev_id: i32) -> i32;
    fn spi_transfer(dev_id: i32, tx_buf: *const u8, rx_buf: *mut u8, len: i32) -> i32;

    // OpenTelemetry
    fn otel_log(level: i32, msg: *const u8, msg_len: i32) -> i32;
    fn otel_metric_counter_add(name: *const u8, name_len: i32, value: i64) -> i32;
    fn otel_metric_gauge_set(name: *const u8, name_len: i32, value: f64) -> i32;
    fn otel_metric_histogram_record(name: *const u8, name_len: i32, value: f64) -> i32;
    fn otel_span_start(name: *const u8, name_len: i32) -> i32;
    fn otel_span_set_attribute(
        span_id: i32,
        key: *const u8, key_len: i32,
        val: *const u8, val_len: i32,
    ) -> i32;
    fn otel_span_set_status(span_id: i32, status: i32) -> i32;
    fn otel_span_end(span_id: i32) -> i32;

    // BLE
    fn ble_init() -> i32;
    fn ble_advertise_start(name: *const u8, name_len: i32) -> i32;
    fn ble_advertise_stop() -> i32;
    fn ble_scan_start(duration_ms: i32, handler_id: i32) -> i32;
    fn ble_scan_stop() -> i32;
    fn ble_connect(addr_type: i32, addr: *const u8, addr_len: i32, handler_id: i32) -> i32;
    fn ble_disconnect(conn_handle: i32) -> i32;
    fn ble_gatts_add_service(uuid: *const u8, uuid_len: i32) -> i32;
    fn ble_gatts_add_characteristic(
        svc_id: i32, uuid: *const u8, uuid_len: i32, flags: i32,
    ) -> i32;
    fn ble_gatts_set_value(chr_id: i32, data: *const u8, data_len: i32) -> i32;
    fn ble_gatts_notify(chr_id: i32, conn_handle: i32) -> i32;
    fn ble_gatts_on_write(chr_id: i32, handler_id: i32) -> i32;
    fn ble_gattc_discover(conn_handle: i32, handler_id: i32) -> i32;
    fn ble_gattc_read(conn_handle: i32, attr_handle: i32, handler_id: i32) -> i32;
    fn ble_gattc_write(conn_handle: i32, attr_handle: i32, data: *const u8, data_len: i32) -> i32;

    // WiFi
    fn wifi_connect(ssid: *const u8, ssid_len: i32, pass: *const u8, pass_len: i32) -> i32;
    fn wifi_disconnect() -> i32;
    fn wifi_status() -> i32;
    fn wifi_get_ip(buf: *mut u8, len: i32) -> i32;
    fn wifi_rssi() -> i32;
    fn wifi_ap_start(
        ssid: *const u8, ssid_len: i32,
        pass: *const u8, pass_len: i32,
        channel: i32,
    ) -> i32;
    fn wifi_ap_stop() -> i32;

    // Sockets
    fn net_socket(domain: i32, r#type: i32, protocol: i32) -> i32;
    fn net_connect(fd: i32, ip: *const u8, ip_len: i32, port: i32) -> i32;
    fn net_bind(fd: i32, port: i32) -> i32;
    fn net_listen(fd: i32, backlog: i32) -> i32;
    fn net_accept(fd: i32) -> i32;
    fn net_send(fd: i32, data: *const u8, len: i32) -> i32;
    fn net_recv(fd: i32, buf: *mut u8, len: i32) -> i32;
    fn net_close(fd: i32) -> i32;

    // DNS
    fn dns_resolve(
        hostname: *const u8, hostname_len: i32,
        result_buf: *mut u8, result_len: i32,
    ) -> i32;

    // TLS
    fn tls_connect(host: *const u8, host_len: i32, port: i32) -> i32;
    fn tls_send(fd: i32, data: *const u8, len: i32) -> i32;
    fn tls_recv(fd: i32, buf: *mut u8, len: i32) -> i32;
    fn tls_close(fd: i32) -> i32;

    // USB
    fn usb_cdc_write(data: *const u8, len: i32) -> i32;
    fn usb_cdc_read(buf: *mut u8, len: i32) -> i32;
    fn usb_hid_send_report(report_id: i32, data: *const u8, len: i32) -> i32;
}

// ── GPIO ───────────────────────────────────────────────────────────────

pub mod gpio {
    use super::*;

    #[repr(i32)]
    #[derive(Clone, Copy)]
    pub enum Mode {
        Input = 0,
        Output = 1,
        InputOutput = 2,
    }

    #[repr(i32)]
    #[derive(Clone, Copy)]
    pub enum Pull {
        None = 0,
        Up = 1,
        Down = 2,
    }

    #[repr(i32)]
    #[derive(Clone, Copy)]
    pub enum InterruptEdge {
        Rising = 1,
        Falling = 2,
        AnyEdge = 3,
    }

    #[inline(always)]
    pub fn configure(pin: i32, mode: Mode, pull: Pull) -> i32 {
        unsafe { gpio_configure(pin, mode as i32, pull as i32) }
    }

    #[inline(always)]
    pub fn read(pin: i32) -> i32 {
        unsafe { gpio_read(pin) }
    }

    #[inline(always)]
    pub fn write(pin: i32, level: i32) -> i32 {
        unsafe { gpio_write(pin, level) }
    }

    #[inline(always)]
    pub fn set_pwm(pin: i32, freq_hz: i32, duty_pct: i32) -> i32 {
        unsafe { gpio_set_pwm(pin, freq_hz, duty_pct) }
    }

    #[inline(always)]
    pub fn analog_read(pin: i32) -> i32 {
        unsafe { gpio_analog_read(pin) }
    }

    #[inline(always)]
    pub fn set_interrupt(pin: i32, edge: InterruptEdge, handler_id: i32) -> i32 {
        unsafe { gpio_set_interrupt(pin, edge as i32, handler_id) }
    }

    #[inline(always)]
    pub fn clear_interrupt(pin: i32) -> i32 {
        unsafe { gpio_clear_interrupt(pin) }
    }
}

// ── I2C ────────────────────────────────────────────────────────────────

pub mod i2c {
    use super::*;

    #[inline(always)]
    pub fn init(bus: i32, sda: i32, scl: i32, freq_hz: i32) -> i32 {
        unsafe { i2c_init(bus, sda, scl, freq_hz) }
    }

    #[inline(always)]
    pub fn scan(bus: i32, addrs_out: &mut [u8]) -> i32 {
        unsafe { i2c_scan(bus, addrs_out.as_mut_ptr(), addrs_out.len() as i32) }
    }

    #[inline(always)]
    pub fn write(bus: i32, addr: i32, data: &[u8]) -> i32 {
        unsafe { i2c_write(bus, addr, data.as_ptr(), data.len() as i32) }
    }

    #[inline(always)]
    pub fn read(bus: i32, addr: i32, buf: &mut [u8]) -> i32 {
        unsafe { i2c_read(bus, addr, buf.as_mut_ptr(), buf.len() as i32) }
    }

    #[inline(always)]
    pub fn write_read(bus: i32, addr: i32, wr: &[u8], rd: &mut [u8]) -> i32 {
        unsafe {
            i2c_write_read(
                bus, addr,
                wr.as_ptr(), wr.len() as i32,
                rd.as_mut_ptr(), rd.len() as i32,
            )
        }
    }
}

// ── RMT ────────────────────────────────────────────────────────────────

pub mod rmt {
    use super::*;

    #[inline(always)]
    pub fn configure(pin: i32, resolution_hz: i32) -> i32 {
        unsafe { rmt_configure(pin, resolution_hz) }
    }

    #[inline(always)]
    pub fn transmit(channel_id: i32, buf: &[u8]) -> i32 {
        unsafe { rmt_transmit(channel_id, buf.as_ptr(), buf.len() as i32) }
    }

    #[inline(always)]
    pub fn release(channel_id: i32) -> i32 {
        unsafe { rmt_release(channel_id) }
    }
}

// ── NeoPixel ───────────────────────────────────────────────────────────

pub mod neopixel {
    use super::*;

    #[inline(always)]
    pub fn init(pin: i32, num_leds: i32) -> i32 {
        unsafe { neopixel_init(pin, num_leds) }
    }

    #[inline(always)]
    pub fn set(index: i32, r: i32, g: i32, b: i32) -> i32 {
        unsafe { neopixel_set(index, r, g, b) }
    }

    #[inline(always)]
    pub fn clear() -> i32 {
        unsafe { neopixel_clear() }
    }
}

// ── Timer ──────────────────────────────────────────────────────────────

pub mod timer {
    use super::*;

    #[inline(always)]
    pub fn delay_ms(ms: i32) {
        unsafe { timer_delay_ms(ms) }
    }

    #[inline(always)]
    pub fn millis() -> i64 {
        unsafe { timer_millis() }
    }

    #[inline(always)]
    pub fn set_timeout(ms: i32, handler_id: i32) -> i32 {
        unsafe { timer_set_timeout(ms, handler_id) }
    }

    #[inline(always)]
    pub fn set_interval(ms: i32, handler_id: i32) -> i32 {
        unsafe { timer_set_interval(ms, handler_id) }
    }

    #[inline(always)]
    pub fn cancel(timer_id: i32) -> i32 {
        unsafe { timer_cancel(timer_id) }
    }
}

// ── Console ────────────────────────────────────────────────────────────

pub mod console {
    use super::*;

    #[inline(always)]
    pub fn print(buf: &[u8]) -> i32 {
        unsafe { wendy_print(buf.as_ptr(), buf.len() as i32) }
    }
}

// ── System ─────────────────────────────────────────────────────────────

pub mod sys {
    use super::*;

    #[inline(always)]
    pub fn uptime_ms() -> i64 {
        unsafe { sys_uptime_ms() }
    }

    pub fn reboot() -> ! {
        unsafe { sys_reboot() };
        loop {}
    }

    #[inline(always)]
    pub fn firmware_version(buf: &mut [u8]) -> i32 {
        unsafe { sys_firmware_version(buf.as_mut_ptr() as *mut u8, buf.len() as i32) }
    }

    #[inline(always)]
    pub fn device_id(buf: &mut [u8]) -> i32 {
        unsafe { sys_device_id(buf.as_mut_ptr() as *mut u8, buf.len() as i32) }
    }

    #[inline(always)]
    pub fn sleep_ms(ms: i32) {
        unsafe { sys_sleep_ms(ms) }
    }

    #[inline(always)]
    pub fn yield_now() {
        unsafe { sys_yield() }
    }
}

// ── Storage (NVS) ──────────────────────────────────────────────────────

pub mod storage {
    use super::*;

    #[inline(always)]
    pub fn get(key: &[u8], val: &mut [u8]) -> i32 {
        unsafe { storage_get(key.as_ptr(), key.len() as i32, val.as_mut_ptr() as *mut u8, val.len() as i32) }
    }

    #[inline(always)]
    pub fn set(key: &[u8], val: &[u8]) -> i32 {
        unsafe { storage_set(key.as_ptr(), key.len() as i32, val.as_ptr(), val.len() as i32) }
    }

    #[inline(always)]
    pub fn delete(key: &[u8]) -> i32 {
        unsafe { storage_delete(key.as_ptr(), key.len() as i32) }
    }

    #[inline(always)]
    pub fn exists(key: &[u8]) -> i32 {
        unsafe { storage_exists(key.as_ptr(), key.len() as i32) }
    }
}

// ── UART ───────────────────────────────────────────────────────────────

pub mod uart {
    use super::*;

    #[inline(always)]
    pub fn open(port: i32, tx_pin: i32, rx_pin: i32, baud: i32) -> i32 {
        unsafe { uart_open(port, tx_pin, rx_pin, baud) }
    }

    #[inline(always)]
    pub fn close(port: i32) -> i32 {
        unsafe { uart_close(port) }
    }

    #[inline(always)]
    pub fn write(port: i32, data: &[u8]) -> i32 {
        unsafe { uart_write(port, data.as_ptr() as *const u8, data.len() as i32) }
    }

    #[inline(always)]
    pub fn read(port: i32, buf: &mut [u8]) -> i32 {
        unsafe { uart_read(port, buf.as_mut_ptr() as *mut u8, buf.len() as i32) }
    }

    #[inline(always)]
    pub fn available(port: i32) -> i32 {
        unsafe { uart_available(port) }
    }

    #[inline(always)]
    pub fn flush(port: i32) -> i32 {
        unsafe { uart_flush(port) }
    }

    #[inline(always)]
    pub fn set_on_receive(port: i32, handler_id: i32) -> i32 {
        unsafe { uart_set_on_receive(port, handler_id) }
    }
}

// ── SPI ────────────────────────────────────────────────────────────────

pub mod spi {
    use super::*;

    #[inline(always)]
    pub fn open(host: i32, mosi: i32, miso: i32, sclk: i32, cs: i32, clock_hz: i32) -> i32 {
        unsafe { spi_open(host, mosi, miso, sclk, cs, clock_hz) }
    }

    #[inline(always)]
    pub fn close(dev_id: i32) -> i32 {
        unsafe { spi_close(dev_id) }
    }

    #[inline(always)]
    pub fn transfer(dev_id: i32, tx: &[u8], rx: &mut [u8]) -> i32 {
        let len = tx.len().min(rx.len()) as i32;
        unsafe { spi_transfer(dev_id, tx.as_ptr() as *const u8, rx.as_mut_ptr(), len) }
    }

    /// Transmit-only SPI transfer (no receive buffer).
    #[inline(always)]
    pub fn transmit(dev_id: i32, tx: &[u8]) -> i32 {
        unsafe { spi_transfer(dev_id, tx.as_ptr() as *const u8, core::ptr::null_mut(), tx.len() as i32) }
    }
}

// ── OpenTelemetry ──────────────────────────────────────────────────────

pub mod otel {
    use super::*;

    #[repr(i32)]
    #[derive(Clone, Copy)]
    pub enum LogLevel {
        Error = 1,
        Warn = 2,
        Info = 3,
        Debug = 4,
    }

    #[inline(always)]
    pub fn log(level: LogLevel, msg: &[u8]) -> i32 {
        unsafe { otel_log(level as i32, msg.as_ptr() as *const u8, msg.len() as i32) }
    }

    #[inline(always)]
    pub fn counter_add(name: &[u8], value: i64) -> i32 {
        unsafe { otel_metric_counter_add(name.as_ptr() as *const u8, name.len() as i32, value) }
    }

    #[inline(always)]
    pub fn gauge_set(name: &[u8], value: f64) -> i32 {
        unsafe { otel_metric_gauge_set(name.as_ptr() as *const u8, name.len() as i32, value) }
    }

    #[inline(always)]
    pub fn histogram_record(name: &[u8], value: f64) -> i32 {
        unsafe { otel_metric_histogram_record(name.as_ptr() as *const u8, name.len() as i32, value) }
    }

    #[inline(always)]
    pub fn span_start(name: &[u8]) -> i32 {
        unsafe { otel_span_start(name.as_ptr() as *const u8, name.len() as i32) }
    }

    #[inline(always)]
    pub fn span_set_attribute(span_id: i32, key: &[u8], val: &[u8]) -> i32 {
        unsafe {
            otel_span_set_attribute(
                span_id,
                key.as_ptr() as *const u8, key.len() as i32,
                val.as_ptr() as *const u8, val.len() as i32,
            )
        }
    }

    #[inline(always)]
    pub fn span_set_status(span_id: i32, status: i32) -> i32 {
        unsafe { otel_span_set_status(span_id, status) }
    }

    #[inline(always)]
    pub fn span_end(span_id: i32) -> i32 {
        unsafe { otel_span_end(span_id) }
    }
}

// ── BLE ────────────────────────────────────────────────────────────────

pub mod ble {
    use super::*;

    #[inline(always)]
    pub fn init() -> i32 {
        unsafe { ble_init() }
    }

    #[inline(always)]
    pub fn advertise_start(name: &[u8]) -> i32 {
        unsafe { ble_advertise_start(name.as_ptr() as *const u8, name.len() as i32) }
    }

    #[inline(always)]
    pub fn advertise_stop() -> i32 {
        unsafe { ble_advertise_stop() }
    }

    #[inline(always)]
    pub fn scan_start(duration_ms: i32, handler_id: i32) -> i32 {
        unsafe { ble_scan_start(duration_ms, handler_id) }
    }

    #[inline(always)]
    pub fn scan_stop() -> i32 {
        unsafe { ble_scan_stop() }
    }

    #[inline(always)]
    pub fn connect(addr_type: i32, addr: &[u8], handler_id: i32) -> i32 {
        unsafe { ble_connect(addr_type, addr.as_ptr() as *const u8, addr.len() as i32, handler_id) }
    }

    #[inline(always)]
    pub fn disconnect(conn_handle: i32) -> i32 {
        unsafe { ble_disconnect(conn_handle) }
    }

    pub mod gatts {
        use super::*;

        #[inline(always)]
        pub fn add_service(uuid: &[u8]) -> i32 {
            unsafe { ble_gatts_add_service(uuid.as_ptr() as *const u8, uuid.len() as i32) }
        }

        #[inline(always)]
        pub fn add_characteristic(svc_id: i32, uuid: &[u8], flags: i32) -> i32 {
            unsafe { ble_gatts_add_characteristic(svc_id, uuid.as_ptr() as *const u8, uuid.len() as i32, flags) }
        }

        #[inline(always)]
        pub fn set_value(chr_id: i32, data: &[u8]) -> i32 {
            unsafe { ble_gatts_set_value(chr_id, data.as_ptr() as *const u8, data.len() as i32) }
        }

        #[inline(always)]
        pub fn notify(chr_id: i32, conn_handle: i32) -> i32 {
            unsafe { ble_gatts_notify(chr_id, conn_handle) }
        }

        #[inline(always)]
        pub fn on_write(chr_id: i32, handler_id: i32) -> i32 {
            unsafe { ble_gatts_on_write(chr_id, handler_id) }
        }
    }

    pub mod gattc {
        use super::*;

        #[inline(always)]
        pub fn discover(conn_handle: i32, handler_id: i32) -> i32 {
            unsafe { ble_gattc_discover(conn_handle, handler_id) }
        }

        #[inline(always)]
        pub fn read(conn_handle: i32, attr_handle: i32, handler_id: i32) -> i32 {
            unsafe { ble_gattc_read(conn_handle, attr_handle, handler_id) }
        }

        #[inline(always)]
        pub fn write(conn_handle: i32, attr_handle: i32, data: &[u8]) -> i32 {
            unsafe { ble_gattc_write(conn_handle, attr_handle, data.as_ptr() as *const u8, data.len() as i32) }
        }
    }
}

// ── WiFi ───────────────────────────────────────────────────────────────

pub mod wifi {
    use super::*;

    #[inline(always)]
    pub fn connect(ssid: &[u8], pass: &[u8]) -> i32 {
        unsafe { wifi_connect(ssid.as_ptr() as *const u8, ssid.len() as i32, pass.as_ptr() as *const u8, pass.len() as i32) }
    }

    #[inline(always)]
    pub fn disconnect() -> i32 {
        unsafe { wifi_disconnect() }
    }

    #[inline(always)]
    pub fn status() -> i32 {
        unsafe { wifi_status() }
    }

    #[inline(always)]
    pub fn get_ip(buf: &mut [u8]) -> i32 {
        unsafe { wifi_get_ip(buf.as_mut_ptr() as *mut u8, buf.len() as i32) }
    }

    #[inline(always)]
    pub fn rssi() -> i32 {
        unsafe { wifi_rssi() }
    }

    #[inline(always)]
    pub fn ap_start(ssid: &[u8], pass: &[u8], channel: i32) -> i32 {
        unsafe {
            wifi_ap_start(
                ssid.as_ptr() as *const u8, ssid.len() as i32,
                pass.as_ptr() as *const u8, pass.len() as i32,
                channel,
            )
        }
    }

    #[inline(always)]
    pub fn ap_stop() -> i32 {
        unsafe { wifi_ap_stop() }
    }
}

// ── Sockets ────────────────────────────────────────────────────────────

pub mod net {
    use super::*;

    pub const AF_INET: i32 = 2;
    pub const SOCK_STREAM: i32 = 1;
    pub const SOCK_DGRAM: i32 = 2;

    #[inline(always)]
    pub fn socket(domain: i32, sock_type: i32, protocol: i32) -> i32 {
        unsafe { net_socket(domain, sock_type, protocol) }
    }

    #[inline(always)]
    pub fn connect(fd: i32, ip: &[u8], port: i32) -> i32 {
        unsafe { net_connect(fd, ip.as_ptr() as *const u8, ip.len() as i32, port) }
    }

    #[inline(always)]
    pub fn bind(fd: i32, port: i32) -> i32 {
        unsafe { net_bind(fd, port) }
    }

    #[inline(always)]
    pub fn listen(fd: i32, backlog: i32) -> i32 {
        unsafe { net_listen(fd, backlog) }
    }

    #[inline(always)]
    pub fn accept(fd: i32) -> i32 {
        unsafe { net_accept(fd) }
    }

    #[inline(always)]
    pub fn send(fd: i32, data: &[u8]) -> i32 {
        unsafe { net_send(fd, data.as_ptr() as *const u8, data.len() as i32) }
    }

    #[inline(always)]
    pub fn recv(fd: i32, buf: &mut [u8]) -> i32 {
        unsafe { net_recv(fd, buf.as_mut_ptr() as *mut u8, buf.len() as i32) }
    }

    #[inline(always)]
    pub fn close(fd: i32) -> i32 {
        unsafe { net_close(fd) }
    }
}

// ── DNS ────────────────────────────────────────────────────────────────

pub mod dns {
    use super::*;

    #[inline(always)]
    pub fn resolve(hostname: &[u8], result_buf: &mut [u8]) -> i32 {
        unsafe {
            dns_resolve(
                hostname.as_ptr() as *const u8, hostname.len() as i32,
                result_buf.as_mut_ptr() as *mut u8, result_buf.len() as i32,
            )
        }
    }
}

// ── TLS ────────────────────────────────────────────────────────────────

pub mod tls {
    use super::*;

    #[inline(always)]
    pub fn connect(host: &[u8], port: i32) -> i32 {
        unsafe { tls_connect(host.as_ptr() as *const u8, host.len() as i32, port) }
    }

    #[inline(always)]
    pub fn send(fd: i32, data: &[u8]) -> i32 {
        unsafe { tls_send(fd, data.as_ptr() as *const u8, data.len() as i32) }
    }

    #[inline(always)]
    pub fn recv(fd: i32, buf: &mut [u8]) -> i32 {
        unsafe { tls_recv(fd, buf.as_mut_ptr() as *mut u8, buf.len() as i32) }
    }

    #[inline(always)]
    pub fn close(fd: i32) -> i32 {
        unsafe { tls_close(fd) }
    }
}

// ── USB ────────────────────────────────────────────────────────────────

pub mod usb {
    use super::*;

    #[inline(always)]
    pub fn cdc_write(data: &[u8]) -> i32 {
        unsafe { usb_cdc_write(data.as_ptr() as *const u8, data.len() as i32) }
    }

    #[inline(always)]
    pub fn cdc_read(buf: &mut [u8]) -> i32 {
        unsafe { usb_cdc_read(buf.as_mut_ptr() as *mut u8, buf.len() as i32) }
    }

    #[inline(always)]
    pub fn hid_send_report(report_id: i32, data: &[u8]) -> i32 {
        unsafe { usb_hid_send_report(report_id, data.as_ptr() as *const u8, data.len() as i32) }
    }
}
