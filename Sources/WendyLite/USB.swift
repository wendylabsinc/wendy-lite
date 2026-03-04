import CWendyLite

public enum USB {
    @inline(__always)
    public static func cdcWrite(data: UnsafePointer<CChar>, length: Int32) -> Int32 {
        usb_cdc_write(data, length)
    }

    @inline(__always)
    public static func cdcRead(buffer: UnsafeMutablePointer<CChar>, length: Int32) -> Int32 {
        usb_cdc_read(buffer, length)
    }

    @discardableResult
    @inline(__always)
    public static func hidSendReport(reportId: Int32, data: UnsafePointer<CChar>, length: Int32) -> Int32 {
        usb_hid_send_report(reportId, data, length)
    }
}
