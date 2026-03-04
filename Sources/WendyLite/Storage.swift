import CWendyLite

public enum Storage {
    @inline(__always)
    public static func get(
        key: UnsafePointer<CChar>,
        keyLength: Int32,
        value: UnsafeMutablePointer<CChar>,
        valueLength: Int32
    ) -> Int32 {
        storage_get(key, keyLength, value, valueLength)
    }

    @discardableResult
    @inline(__always)
    public static func set(
        key: UnsafePointer<CChar>,
        keyLength: Int32,
        value: UnsafePointer<CChar>,
        valueLength: Int32
    ) -> Int32 {
        storage_set(key, keyLength, value, valueLength)
    }

    @discardableResult
    @inline(__always)
    public static func delete(key: UnsafePointer<CChar>, keyLength: Int32) -> Int32 {
        storage_delete(key, keyLength)
    }

    @inline(__always)
    public static func exists(key: UnsafePointer<CChar>, keyLength: Int32) -> Int32 {
        storage_exists(key, keyLength)
    }
}
