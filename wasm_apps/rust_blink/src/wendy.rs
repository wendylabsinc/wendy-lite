//! Wendy HAL bindings for Rust WASM apps.
//!
//! These functions are imported from the "wendy" host module
//! and map directly to the ESP32 HAL layer.
//!
//! Host signatures include two extra i32 parameters (context + error)
//! added by Swift Embedded. Non-Swift apps pass 0 for both.

#[link(wasm_import_module = "wendy")]
extern "C" {
    // NeoPixel (WS2812)
    #[link_name = "neopixel_init"]
    fn _neopixel_init(pin: i32, num_leds: i32, ctx: i32, err: i32) -> i32;

    #[link_name = "neopixel_set"]
    fn _neopixel_set(index: i32, r: i32, g: i32, b: i32, ctx: i32, err: i32) -> i32;

    #[link_name = "neopixel_clear"]
    fn _neopixel_clear(ctx: i32, err: i32) -> i32;

    // Timer
    #[link_name = "timer_delay_ms"]
    fn _timer_delay_ms(ms: i32, ctx: i32, err: i32);
}

pub fn neopixel_init(pin: i32, num_leds: i32) -> i32 {
    unsafe { _neopixel_init(pin, num_leds, 0, 0) }
}

pub fn neopixel_set(index: i32, r: i32, g: i32, b: i32) -> i32 {
    unsafe { _neopixel_set(index, r, g, b, 0, 0) }
}

pub fn neopixel_clear() -> i32 {
    unsafe { _neopixel_clear(0, 0) }
}

pub fn timer_delay_ms(ms: i32) {
    unsafe { _timer_delay_ms(ms, 0, 0) }
}
