import CWendyLite

public enum System {
    @inline(__always)
    public static func uptimeMs() -> Int64 {
        sys_uptime_ms()
    }

    public static func reboot() -> Never {
        sys_reboot()
        while true {}
    }

    @inline(__always)
    public static func firmwareVersion(buffer: UnsafeMutablePointer<CChar>, length: Int32) -> Int32 {
        sys_firmware_version(buffer, length)
    }

    @inline(__always)
    public static func deviceId(buffer: UnsafeMutablePointer<CChar>, length: Int32) -> Int32 {
        sys_device_id(buffer, length)
    }

    @inline(__always)
    public static func sleepMs(_ ms: Int32) {
        sys_sleep_ms(ms)
    }

    @inline(__always)
    public static func yield() {
        sys_yield()
    }
}

public enum Console {
    @discardableResult
    @inline(__always)
    public static func print(_ buffer: UnsafePointer<CChar>, length: Int32) -> Int32 {
        wendy_print(buffer, length)
    }
}
