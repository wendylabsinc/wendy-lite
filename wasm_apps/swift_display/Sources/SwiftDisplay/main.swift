/// Wendy MCU — Swift WASM Display Demo
///
/// Drives the ST7789 LCD on the Waveshare ESP32-C6-LCD-1.47 board
/// (172×320, SPI) entirely from Swift WASM using the Wendy SPI + GPIO
/// host functions.  Prints "Swifty Steve" in white on a Swift-orange
/// background at 3× scale.

import CWendy

// ── Low-level SPI helpers ───────────────────────────────────────────

/// Send one byte in command mode (DC low).
@inline(__always)
func sendCmd(_ spi: Int32, _ dc: Int32, _ cmd: UInt8) {
    gpio_write(dc, 0)
    var b = cmd
    withUnsafeMutablePointer(to: &b) { ptr in
        _ = spi_transfer(spi,
                         UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: UInt8.self),
                         nil, 1)
    }
}

/// Send one data byte (DC high).
@inline(__always)
func sendDataByte(_ spi: Int32, _ dc: Int32, _ val: UInt8) {
    gpio_write(dc, 1)
    var b = val
    withUnsafeMutablePointer(to: &b) { ptr in
        _ = spi_transfer(spi,
                         UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: UInt8.self),
                         nil, 1)
    }
}

/// Send a buffer of data bytes (DC high).
@inline(__always)
func sendData(_ spi: Int32, _ dc: Int32,
              _ ptr: UnsafeMutablePointer<UInt8>, _ len: Int32) {
    gpio_write(dc, 1)
    _ = spi_transfer(spi, ptr, nil, len)
}

// ── ST7789 driver ───────────────────────────────────────────────────

func st7789Init(_ spi: Int32, _ dc: Int32, _ rst: Int32, _ bl: Int32) {
    // Hardware reset
    gpio_write(rst, 0)
    timer_delay_ms(10)
    gpio_write(rst, 1)
    timer_delay_ms(120)

    sendCmd(spi, dc, 0x01)          // SWRESET
    timer_delay_ms(150)

    sendCmd(spi, dc, 0x11)          // SLPOUT
    timer_delay_ms(120)

    sendCmd(spi, dc, 0x3A)          // COLMOD — 16-bit RGB565
    sendDataByte(spi, dc, 0x55)

    sendCmd(spi, dc, 0x36)          // MADCTL — portrait, RGB
    sendDataByte(spi, dc, 0x00)

    sendCmd(spi, dc, 0x21)          // INVON  (required for correct colours)

    sendCmd(spi, dc, 0x13)          // NORON
    timer_delay_ms(10)

    sendCmd(spi, dc, 0x29)          // DISPON
    timer_delay_ms(10)

    gpio_write(bl, 1)               // backlight on
}

/// Set the column/row window for the next RAMWR.
func setWindow(_ spi: Int32, _ dc: Int32,
               _ x: Int32, _ y: Int32, _ w: Int32, _ h: Int32) {
    let colOffset: Int32 = 34       // 172 centred in 240-wide framebuffer
    let x0 = x + colOffset
    let x1 = x + w - 1 + colOffset
    let y0 = y
    let y1 = y + h - 1

    sendCmd(spi, dc, 0x2A)          // CASET
    var ca: (UInt8, UInt8, UInt8, UInt8) = (
        UInt8(x0 >> 8), UInt8(x0 & 0xFF),
        UInt8(x1 >> 8), UInt8(x1 & 0xFF))
    withUnsafeMutablePointer(to: &ca) { ptr in
        sendData(spi, dc,
                 UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: UInt8.self), 4)
    }

    sendCmd(spi, dc, 0x2B)          // RASET
    var ra: (UInt8, UInt8, UInt8, UInt8) = (
        UInt8(y0 >> 8), UInt8(y0 & 0xFF),
        UInt8(y1 >> 8), UInt8(y1 & 0xFF))
    withUnsafeMutablePointer(to: &ra) { ptr in
        sendData(spi, dc,
                 UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: UInt8.self), 4)
    }

    sendCmd(spi, dc, 0x2C)          // RAMWR
}

/// Push `count` identical RGB565 pixels after a RAMWR.
func fillColor(_ spi: Int32, _ dc: Int32,
               _ color: UInt16, _ count: Int32) {
    let hi = UInt8(color >> 8)
    let lo = UInt8(color & 0xFF)

    // 128-byte stack buffer = 64 pixels per SPI transaction
    var buf: (
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32,
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32,
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32,
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32
    ) = (0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0)

    withUnsafeMutablePointer(to: &buf) { tuplePtr in
        let p = UnsafeMutableRawPointer(tuplePtr)
            .assumingMemoryBound(to: UInt8.self)

        var i: Int32 = 0
        while i < 128 {
            p[Int(i)]     = hi
            p[Int(i + 1)] = lo
            i += 2
        }

        gpio_write(dc, 1)
        var remaining = count
        while remaining > 0 {
            let chunk: Int32 = remaining > 64 ? 64 : remaining
            _ = spi_transfer(spi, p, nil, chunk * 2)
            remaining -= chunk
        }
    }
}

func clear(_ spi: Int32, _ dc: Int32, _ color: UInt16) {
    setWindow(spi, dc, 0, 0, 172, 320)
    fillColor(spi, dc, color, 172 * 320)
}

func fillRect(_ spi: Int32, _ dc: Int32,
              _ x: Int32, _ y: Int32,
              _ w: Int32, _ h: Int32, _ color: UInt16) {
    setWindow(spi, dc, x, y, w, h)
    fillColor(spi, dc, color, w * h)
}

// ── Text rendering (8×16 font, scaled) ──────────────────────────────

@inline(never)
func drawChar(_ spi: Int32, _ dc: Int32,
              _ ch: UInt8, _ x: Int32, _ y: Int32,
              _ fg: UInt16, _ scale: Int32) {
    for row: Int32 in 0 ..< 16 {
        let bits = Int32(font8x16_get(Int32(ch), row))
        if bits == 0 { continue }
        for col: Int32 in 0 ..< 8 {
            if bits & (0x80 >> col) != 0 {
                fillRect(spi, dc,
                         x + col * scale,
                         y + row * scale,
                         scale, scale, fg)
            }
        }
    }
}

@inline(never)
func drawString(_ spi: Int32, _ dc: Int32,
                _ ptr: UnsafePointer<UInt8>, _ len: Int32,
                _ x: Int32, _ y: Int32,
                _ fg: UInt16, _ scale: Int32) {
    let charW: Int32 = 8 * scale
    for i: Int32 in 0 ..< len {
        drawChar(spi, dc, ptr[Int(i)], x + i * charW, y, fg, scale)
    }
}

// ── Entry point ─────────────────────────────────────────────────────

@_cdecl("_start")
func start() {
    // Waveshare ESP32-C6-LCD-1.47 pins
    let pinMOSI: Int32 = 6
    let pinSCK:  Int32 = 7
    let pinCS:   Int32 = 14
    let pinDC:   Int32 = 15
    let pinRST:  Int32 = 21
    let pinBL:   Int32 = 22

    let scale: Int32 = 3
    let white: UInt16 = 0xFFFF
    let swiftOrange: UInt16 = 0xF287    // #F05138

    // Configure DC / RST / BL as GPIO outputs
    gpio_configure(pinDC,  WENDY_GPIO_OUTPUT, WENDY_GPIO_PULL_NONE)
    gpio_configure(pinRST, WENDY_GPIO_OUTPUT, WENDY_GPIO_PULL_NONE)
    gpio_configure(pinBL,  WENDY_GPIO_OUTPUT, WENDY_GPIO_PULL_NONE)

    // Open SPI to ST7789 (host 1 = SPI2, no MISO, 40 MHz)
    let spi = spi_open(1, pinMOSI, -1, pinSCK, pinCS, 40_000_000)
    if spi < 0 { return }

    // Bring up the display
    st7789Init(spi, pinDC, pinRST, pinBL)

    // Swift-orange background
    clear(spi, pinDC, swiftOrange)

    // "Swifty" — 6 chars × 24 px = 144 px wide
    // centred x = (172 − 144) / 2 = 14
    // two lines total: 48 + 12 gap + 48 = 108, start y = (320−108)/2 = 106
    var line1: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) =
        (0x53, 0x77, 0x69, 0x66, 0x74, 0x79)       // S w i f t y

    withUnsafePointer(to: &line1) { ptr in
        drawString(spi, pinDC,
                   UnsafeRawPointer(ptr).assumingMemoryBound(to: UInt8.self),
                   6, 14, 106, white, scale)
    }

    // "Steve" — 5 chars × 24 px = 120 px wide
    // centred x = (172 − 120) / 2 = 26,  y = 106 + 48 + 12 = 166
    var line2: (UInt8, UInt8, UInt8, UInt8, UInt8) =
        (0x53, 0x74, 0x65, 0x76, 0x65)             // S t e v e

    withUnsafePointer(to: &line2) { ptr in
        drawString(spi, pinDC,
                   UnsafeRawPointer(ptr).assumingMemoryBound(to: UInt8.self),
                   5, 26, 166, white, scale)
    }
}
