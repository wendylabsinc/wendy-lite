//! Wendy MCU — Rust WASM Blink Demo
//!
//! Cycles through colors on the onboard NeoPixel (GPIO 8, ESP32-C6)
//! using the raw RMT timing-buffer API for precise WS2812 waveforms.
//!
//! Build with:
//!   cargo build --release

#![no_std]

mod wendy;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Pack one RMT symbol: two (level, duration) pairs into a u32.
/// bits[14:0]=duration0, bit[15]=level0, bits[30:16]=duration1, bit[31]=level1
#[inline(always)]
const fn rmt_symbol(level0: u32, dur0: u32, level1: u32, dur1: u32) -> u32 {
    (dur0 & 0x7FFF) | ((level0 & 1) << 15)
        | ((dur1 & 0x7FFF) << 16) | ((level1 & 1) << 31)
}

/// Encode one byte (MSB-first) into 8 RMT symbols in the buffer.
/// WS2812 at 10 MHz: bit-0 = high 3 / low 9, bit-1 = high 9 / low 3.
#[inline(always)]
fn encode_byte(byte: u8, buf: &mut [u32], offset: usize) {
    const BIT1: u32 = rmt_symbol(1, 9, 0, 3);
    const BIT0: u32 = rmt_symbol(1, 3, 0, 9);
    for i in 0..8 {
        buf[offset + i] = if (byte >> (7 - i)) & 1 != 0 { BIT1 } else { BIT0 };
    }
}

/// Encode one GRB pixel and transmit via RMT.
/// Uses a 25-element stack buffer (24 data symbols + 1 reset).
fn ws2812_send(channel: i32, r: u8, g: u8, b: u8) {
    let mut buf = [0u32; 25];

    // WS2812 expects GRB byte order
    encode_byte(g, &mut buf, 0);
    encode_byte(r, &mut buf, 8);
    encode_byte(b, &mut buf, 16);

    // Reset symbol: low for >50 us (500+500 ticks at 10 MHz = 100 us)
    buf[24] = rmt_symbol(0, 500, 0, 500);

    unsafe {
        wendy::rmt_transmit(
            channel,
            buf.as_ptr() as *const u8,
            (25 * 4) as i32,
        );
    }
}

#[no_mangle]
pub extern "C" fn _start() {
    let channel = unsafe { wendy::rmt_configure(8, 10_000_000) }; // 10 MHz
    if channel < 0 {
        return;
    }

    loop {
        ws2812_send(channel, 255, 0,   0);     // red
        unsafe { wendy::sys_sleep_ms(500) };
        ws2812_send(channel, 0,   255, 0);     // green
        unsafe { wendy::sys_sleep_ms(500) };
        ws2812_send(channel, 0,   0,   255);   // blue
        unsafe { wendy::sys_sleep_ms(500) };
        ws2812_send(channel, 255, 255, 0);     // yellow
        unsafe { wendy::sys_sleep_ms(500) };
        ws2812_send(channel, 0,   255, 255);   // cyan
        unsafe { wendy::sys_sleep_ms(500) };
        ws2812_send(channel, 255, 0,   255);   // purple
        unsafe { wendy::sys_sleep_ms(500) };
        ws2812_send(channel, 255, 255, 255);   // white
        unsafe { wendy::sys_sleep_ms(500) };
        ws2812_send(channel, 0,   0,   0);     // off
        unsafe { wendy::sys_sleep_ms(500) };
    }
}
