import CWendyLite

public enum NeoPixel {
    @inline(__always)
    public static func initialize(pin: Int32, numLeds: Int32) -> Int32 {
        neopixel_init(pin, numLeds)
    }

    @discardableResult
    @inline(__always)
    public static func set(index: Int32, r: Int32, g: Int32, b: Int32) -> Int32 {
        neopixel_set(index, r, g, b)
    }

    @discardableResult
    @inline(__always)
    public static func clear() -> Int32 {
        neopixel_clear()
    }
}
