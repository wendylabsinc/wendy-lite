//! Wendy HAL bindings for Rust WASM apps.
//!
//! These functions are imported from the "wendy" host module
//! and map directly to the ESP32 HAL layer.

#[link(wasm_import_module = "wendy")]
extern "C" {
    // RMT (timing-buffer)
    #[link_name = "rmt_configure"]
    pub fn rmt_configure(pin: i32, resolution_hz: i32) -> i32;

    #[link_name = "rmt_transmit"]
    pub fn rmt_transmit(channel_id: i32, buf: *const u8, len: i32) -> i32;

    // System
    #[link_name = "sys_sleep_ms"]
    pub fn sys_sleep_ms(ms: i32);
}
