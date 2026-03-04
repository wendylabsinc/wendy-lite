import CWendyLite

public enum Timer {
    @inline(__always)
    public static func delayMs(_ ms: Int32) {
        timer_delay_ms(ms)
    }

    @inline(__always)
    public static func millis() -> Int64 {
        timer_millis()
    }

    @inline(__always)
    public static func setTimeout(ms: Int32, handlerId: Int32) -> Int32 {
        timer_set_timeout(ms, handlerId)
    }

    @inline(__always)
    public static func setInterval(ms: Int32, handlerId: Int32) -> Int32 {
        timer_set_interval(ms, handlerId)
    }

    @discardableResult
    @inline(__always)
    public static func cancel(timerId: Int32) -> Int32 {
        timer_cancel(timerId)
    }
}
