import CWendyLite

public enum RMT {
    @inline(__always)
    public static func configure(pin: Int32, resolutionHz: Int32) -> Int32 {
        rmt_configure(pin, resolutionHz)
    }

    @discardableResult
    @inline(__always)
    public static func transmit(channelId: Int32, buffer: UnsafePointer<UInt8>, length: Int32) -> Int32 {
        rmt_transmit(channelId, buffer, length)
    }

    @discardableResult
    @inline(__always)
    public static func release(channelId: Int32) -> Int32 {
        rmt_release(channelId)
    }
}
