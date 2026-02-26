/// Wendy MCU — Swift WASM Blink Demo
///
/// Cycles through colors on the onboard NeoPixel (GPIO 8, ESP32-C6)
/// using the raw RMT timing-buffer API for precise WS2812 waveforms.

import CWendy

/// Pack one RMT symbol: two (level, duration) pairs into a UInt32.
/// bits[14:0]=duration0, bit[15]=level0, bits[30:16]=duration1, bit[31]=level1
@inline(__always)
private func rmtSymbol(
    _ level0: UInt32, _ dur0: UInt32,
    _ level1: UInt32, _ dur1: UInt32
) -> UInt32 {
    (dur0 & 0x7FFF) | ((level0 & 1) << 15) |
    ((dur1 & 0x7FFF) << 16) | ((level1 & 1) << 31)
}

/// Encode one byte (MSB-first) into 8 RMT symbols at ptr[offset..<offset+8].
/// WS2812 at 10 MHz: bit-0 = high 3 / low 9, bit-1 = high 9 / low 3.
@inline(__always)
private func encodeByte(_ byte: UInt8, _ ptr: UnsafeMutablePointer<UInt32>, _ offset: Int) {
    let bit1 = rmtSymbol(1, 9, 0, 3)
    let bit0 = rmtSymbol(1, 3, 0, 9)
    ptr[offset + 0] = (byte & 0x80) != 0 ? bit1 : bit0
    ptr[offset + 1] = (byte & 0x40) != 0 ? bit1 : bit0
    ptr[offset + 2] = (byte & 0x20) != 0 ? bit1 : bit0
    ptr[offset + 3] = (byte & 0x10) != 0 ? bit1 : bit0
    ptr[offset + 4] = (byte & 0x08) != 0 ? bit1 : bit0
    ptr[offset + 5] = (byte & 0x04) != 0 ? bit1 : bit0
    ptr[offset + 6] = (byte & 0x02) != 0 ? bit1 : bit0
    ptr[offset + 7] = (byte & 0x01) != 0 ? bit1 : bit0
}

/// Encode one GRB pixel and transmit via RMT.
/// Uses a 25-element stack buffer (24 data symbols + 1 reset).
private func ws2812Send(_ channel: Int32, _ r: UInt8, _ g: UInt8, _ b: UInt8) {
    // 25 UInt32 symbols = 100 bytes on the stack
    var buf: (
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32,
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32,
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32,
        UInt32
    ) = (
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0
    )

    withUnsafeMutablePointer(to: &buf) { tuplePtr in
        let ptr = UnsafeMutableRawPointer(tuplePtr)
            .assumingMemoryBound(to: UInt32.self)

        // WS2812 expects GRB byte order
        encodeByte(g, ptr, 0)
        encodeByte(r, ptr, 8)
        encodeByte(b, ptr, 16)

        // Reset symbol: low for >50 µs (500+500 ticks at 10 MHz = 100 µs)
        ptr[24] = rmtSymbol(0, 500, 0, 500)

        _ = rmt_transmit(channel,
                         UnsafeRawPointer(ptr).assumingMemoryBound(to: UInt8.self),
                         25 * 4)
    }
}

@_cdecl("_start")
func start() {
    let channel = rmt_configure(8, 10_000_000)  // 10 MHz
    if channel < 0 {
        return
    }

    while true {
        ws2812Send(channel, 255, 0,   0)      // red
        sys_sleep_ms(500)
        ws2812Send(channel, 0,   255, 0)      // green
        sys_sleep_ms(500)
        ws2812Send(channel, 0,   0,   255)    // blue
        sys_sleep_ms(500)
        ws2812Send(channel, 255, 255, 0)      // yellow
        sys_sleep_ms(500)
        ws2812Send(channel, 0,   255, 255)    // cyan
        sys_sleep_ms(500)
        ws2812Send(channel, 255, 0,   255)    // purple
        sys_sleep_ms(500)
        ws2812Send(channel, 255, 255, 255)    // white
        sys_sleep_ms(500)
        ws2812Send(channel, 0,   0,   0)      // off
        sys_sleep_ms(500)
    }
}
