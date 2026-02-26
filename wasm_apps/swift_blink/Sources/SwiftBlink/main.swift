/// Wendy MCU — Swift WASM Blink Demo
///
/// Cycles through colors on the onboard NeoPixel (GPIO 8, ESP32-C6).

import CWendy

@_cdecl("_start")
func start() {
    _ = neopixel_init(8, 1)

    while true {
        _ = neopixel_set(0, 255, 0,   0)      // red
        sys_sleep_ms(500)
        _ = neopixel_set(0, 0,   255, 0)      // green
        sys_sleep_ms(500)
        _ = neopixel_set(0, 0,   0,   255)    // blue
        sys_sleep_ms(500)
        _ = neopixel_set(0, 255, 255, 0)      // yellow
        sys_sleep_ms(500)
        _ = neopixel_set(0, 0,   255, 255)    // cyan
        sys_sleep_ms(500)
        _ = neopixel_set(0, 255, 0,   255)    // purple
        sys_sleep_ms(500)
        _ = neopixel_set(0, 255, 255, 255)    // white
        sys_sleep_ms(500)
        _ = neopixel_clear()                   // off
        sys_sleep_ms(500)
    }
}
