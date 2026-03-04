import CWendyLite

public enum I2C {
    @discardableResult
    @inline(__always)
    public static func initialize(bus: Int32, sda: Int32, scl: Int32, frequencyHz: Int32) -> Int32 {
        i2c_init(bus, sda, scl, frequencyHz)
    }

    @inline(__always)
    public static func scan(bus: Int32, addresses: UnsafeMutablePointer<UInt8>, maxAddresses: Int32) -> Int32 {
        i2c_scan(bus, addresses, maxAddresses)
    }

    @discardableResult
    @inline(__always)
    public static func write(bus: Int32, address: Int32, data: UnsafePointer<UInt8>, length: Int32) -> Int32 {
        i2c_write(bus, address, data, length)
    }

    @inline(__always)
    public static func read(bus: Int32, address: Int32, buffer: UnsafeMutablePointer<UInt8>, length: Int32) -> Int32 {
        i2c_read(bus, address, buffer, length)
    }

    @inline(__always)
    public static func writeRead(
        bus: Int32,
        address: Int32,
        writeData: UnsafePointer<UInt8>,
        writeLength: Int32,
        readBuffer: UnsafeMutablePointer<UInt8>,
        readLength: Int32
    ) -> Int32 {
        i2c_write_read(bus, address, writeData, writeLength, readBuffer, readLength)
    }
}
