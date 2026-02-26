//! Wendy MCU — Rust WASM NeoPixel RGB Demo
//!
//! Cycles the onboard WS2812 RGB LED (GPIO 8) through colors.
//!
//! Build with:
//!   cargo build --release

#![no_std]

mod wendy;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() {
    // Initialize the onboard NeoPixel on GPIO 8 (1 LED)
    wendy::neopixel_init(8, 1);

    // Cycle through colors
    for _ in 0..10 {
        wendy::neopixel_set(0, 255, 0, 0); // red
        wendy::timer_delay_ms(500);

        wendy::neopixel_set(0, 0, 255, 0); // green
        wendy::timer_delay_ms(500);

        wendy::neopixel_set(0, 0, 0, 255); // blue
        wendy::timer_delay_ms(500);
    }

    wendy::neopixel_clear();
}
