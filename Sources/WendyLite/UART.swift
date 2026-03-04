import CWendyLite

public enum UART {
    @inline(__always)
    public static func open(port: Int32, txPin: Int32, rxPin: Int32, baud: Int32) -> Int32 {
        uart_open(port, txPin, rxPin, baud)
    }

    @discardableResult
    @inline(__always)
    public static func close(port: Int32) -> Int32 {
        uart_close(port)
    }

    @discardableResult
    @inline(__always)
    public static func write(port: Int32, data: UnsafePointer<CChar>, length: Int32) -> Int32 {
        uart_write(port, data, length)
    }

    @inline(__always)
    public static func read(port: Int32, buffer: UnsafeMutablePointer<CChar>, length: Int32) -> Int32 {
        uart_read(port, buffer, length)
    }

    @inline(__always)
    public static func available(port: Int32) -> Int32 {
        uart_available(port)
    }

    @discardableResult
    @inline(__always)
    public static func flush(port: Int32) -> Int32 {
        uart_flush(port)
    }

    @discardableResult
    @inline(__always)
    public static func setOnReceive(port: Int32, handlerId: Int32) -> Int32 {
        uart_set_on_receive(port, handlerId)
    }
}
