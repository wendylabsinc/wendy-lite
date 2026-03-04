import CWendyLite

public enum BLE {
    @discardableResult
    @inline(__always)
    public static func initialize() -> Int32 {
        ble_init()
    }

    @discardableResult
    @inline(__always)
    public static func startAdvertising(name: UnsafePointer<CChar>, nameLength: Int32) -> Int32 {
        ble_advertise_start(name, nameLength)
    }

    @discardableResult
    @inline(__always)
    public static func stopAdvertising() -> Int32 {
        ble_advertise_stop()
    }

    @discardableResult
    @inline(__always)
    public static func startScan(durationMs: Int32, handlerId: Int32) -> Int32 {
        ble_scan_start(durationMs, handlerId)
    }

    @discardableResult
    @inline(__always)
    public static func stopScan() -> Int32 {
        ble_scan_stop()
    }

    @inline(__always)
    public static func connect(
        addressType: Int32,
        address: UnsafePointer<CChar>,
        addressLength: Int32,
        handlerId: Int32
    ) -> Int32 {
        ble_connect(addressType, address, addressLength, handlerId)
    }

    @discardableResult
    @inline(__always)
    public static func disconnect(connHandle: Int32) -> Int32 {
        ble_disconnect(connHandle)
    }
}

// MARK: - GATT Server

public enum GATTS {
    @inline(__always)
    public static func addService(uuid: UnsafePointer<CChar>, uuidLength: Int32) -> Int32 {
        ble_gatts_add_service(uuid, uuidLength)
    }

    @inline(__always)
    public static func addCharacteristic(
        serviceId: Int32,
        uuid: UnsafePointer<CChar>,
        uuidLength: Int32,
        flags: Int32
    ) -> Int32 {
        ble_gatts_add_characteristic(serviceId, uuid, uuidLength, flags)
    }

    @discardableResult
    @inline(__always)
    public static func setValue(characteristicId: Int32, data: UnsafePointer<CChar>, dataLength: Int32) -> Int32 {
        ble_gatts_set_value(characteristicId, data, dataLength)
    }

    @discardableResult
    @inline(__always)
    public static func notify(characteristicId: Int32, connHandle: Int32) -> Int32 {
        ble_gatts_notify(characteristicId, connHandle)
    }

    @discardableResult
    @inline(__always)
    public static func onWrite(characteristicId: Int32, handlerId: Int32) -> Int32 {
        ble_gatts_on_write(characteristicId, handlerId)
    }
}

// MARK: - GATT Client

public enum GATTC {
    @discardableResult
    @inline(__always)
    public static func discover(connHandle: Int32, handlerId: Int32) -> Int32 {
        ble_gattc_discover(connHandle, handlerId)
    }

    @discardableResult
    @inline(__always)
    public static func read(connHandle: Int32, attrHandle: Int32, handlerId: Int32) -> Int32 {
        ble_gattc_read(connHandle, attrHandle, handlerId)
    }

    @discardableResult
    @inline(__always)
    public static func write(
        connHandle: Int32,
        attrHandle: Int32,
        data: UnsafePointer<CChar>,
        dataLength: Int32
    ) -> Int32 {
        ble_gattc_write(connHandle, attrHandle, data, dataLength)
    }
}
