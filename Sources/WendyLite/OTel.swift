import CWendyLite

public enum OTelLogLevel: Int32 {
    case error = 1
    case warn = 2
    case info = 3
    case debug = 4
}

public enum OTel {
    @discardableResult
    @inline(__always)
    public static func log(level: OTelLogLevel, message: UnsafePointer<CChar>, messageLength: Int32) -> Int32 {
        otel_log(level.rawValue, message, messageLength)
    }

    @discardableResult
    @inline(__always)
    public static func counterAdd(name: UnsafePointer<CChar>, nameLength: Int32, value: Int64) -> Int32 {
        otel_metric_counter_add(name, nameLength, value)
    }

    @discardableResult
    @inline(__always)
    public static func gaugeSet(name: UnsafePointer<CChar>, nameLength: Int32, value: Double) -> Int32 {
        otel_metric_gauge_set(name, nameLength, value)
    }

    @discardableResult
    @inline(__always)
    public static func histogramRecord(name: UnsafePointer<CChar>, nameLength: Int32, value: Double) -> Int32 {
        otel_metric_histogram_record(name, nameLength, value)
    }

    @inline(__always)
    public static func spanStart(name: UnsafePointer<CChar>, nameLength: Int32) -> Int32 {
        otel_span_start(name, nameLength)
    }

    @discardableResult
    @inline(__always)
    public static func spanSetAttribute(
        spanId: Int32,
        key: UnsafePointer<CChar>,
        keyLength: Int32,
        value: UnsafePointer<CChar>,
        valueLength: Int32
    ) -> Int32 {
        otel_span_set_attribute(spanId, key, keyLength, value, valueLength)
    }

    @discardableResult
    @inline(__always)
    public static func spanSetStatus(spanId: Int32, status: Int32) -> Int32 {
        otel_span_set_status(spanId, status)
    }

    @discardableResult
    @inline(__always)
    public static func spanEnd(spanId: Int32) -> Int32 {
        otel_span_end(spanId)
    }
}
