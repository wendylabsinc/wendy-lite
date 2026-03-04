import CWendyLite

public enum SPI {
    @inline(__always)
    public static func open(
        host: Int32,
        mosi: Int32,
        miso: Int32,
        sclk: Int32,
        cs: Int32,
        clockHz: Int32
    ) -> Int32 {
        spi_open(host, mosi, miso, sclk, cs, clockHz)
    }

    @discardableResult
    @inline(__always)
    public static func close(deviceId: Int32) -> Int32 {
        spi_close(deviceId)
    }

    @discardableResult
    @inline(__always)
    public static func transfer(
        deviceId: Int32,
        txBuffer: UnsafeMutablePointer<UInt8>?,
        rxBuffer: UnsafeMutablePointer<UInt8>?,
        length: Int32
    ) -> Int32 {
        spi_transfer(deviceId, txBuffer, rxBuffer, length)
    }
}
