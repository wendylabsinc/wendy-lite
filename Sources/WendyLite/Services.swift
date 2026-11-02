import CWendyLite

/// Desired publications live in the guest's bounded memory. The host may
/// discard its catalogue when mesh is disabled; the normal guest event pump
/// replays these declarations after the catalogue incarnation changes.
public enum Services {
    private struct Entry {
        var id: String
        var payload: [UInt8]
        var withdrawing: Bool
        var serial: UInt64
        var replay = wendy_service_replay()
        var bytes: Int { id.utf8.count + payload.count }
    }
    private struct State {
        var entries: [Entry] = []
        var bytes = 0
        var next: UInt64 = 1
        var cursor = 0
        var polling = false
    }
    private static let state = _LockedBox(State())

    private static func alnum(_ value: UInt8) -> Bool {
        (48...57).contains(value) || (65...90).contains(value) || (97...122).contains(value)
    }
    private static func validID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return !bytes.isEmpty && bytes.count <= 63 && alnum(bytes[0]) &&
            bytes.allSatisfy { alnum($0) || $0 == 45 || $0 == 95 }
    }
    private static func quoted(_ value: String) -> String {
        let hex = Array("0123456789abcdef".utf8)
        var bytes: [UInt8] = [34]
        for byte in value.utf8 {
            switch byte {
            case 34, 92: bytes.append(92); bytes.append(byte)
            case 0..<32: bytes.append(contentsOf: [92, 117, 48, 48, hex[Int(byte >> 4)], hex[Int(byte & 15)]])
            default: bytes.append(byte)
            }
        }
        bytes.append(34)
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Accept desired intent, including while mesh is OFF. True means the
    /// guest retained it, not that a signed publication has reached any peer.
    /// The declaration must name a TCP/UDP listener owned by this guest.
    @discardableResult
    public static func publish(serviceID: String, type: String, instance: String,
                               port: UInt16, txt: [String] = []) -> Bool {
        let components = type.split(separator: ".", omittingEmptySubsequences: false)
        guard validID(serviceID), port != 0, components.count == 2,
              components[0].first == "_", components[0].utf8.count >= 2,
              components[0].utf8.count <= 16,
              components[1] == "_tcp" || components[1] == "_udp",
              instance.utf8.count <= 255, txt.count <= 16,
              txt.allSatisfy({ $0.utf8.count <= 255 }),
              txt.reduce(0, { $0 + $1.utf8.count }) <= 1200 else { return false }
        let name = Array(components[0].utf8.dropFirst())
        guard alnum(name[0]), name.allSatisfy({ alnum($0) || $0 == 45 }) else { return false }
        let records = txt.map { quoted($0) }.joined(separator: ",")
        let json = "{\"serviceId\":\(quoted(serviceID)),\"type\":\(quoted(type)),\"instance\":\(quoted(instance)),\"port\":\(port),\"txt\":[\(records)]}"
        let payload = Array(json.utf8)
        guard payload.count <= 8192 else { return false }
        return state.withLockedValue { s in
            let index = s.entries.firstIndex { $0.id == serviceID }
            if let index, !s.entries[index].withdrawing && s.entries[index].payload == payload { return true }
            let oldBytes = index.map { s.entries[$0].bytes } ?? 0
            let bytes = serviceID.utf8.count + payload.count
            guard (index != nil || s.entries.count < 64), s.bytes - oldBytes + bytes <= 32768 else { return false }
            var entry = Entry(id: serviceID, payload: payload, withdrawing: false, serial: s.next)
            wendy_service_replay_changed(&entry.replay)
            s.next &+= 1
            if s.next == 0 { s.next = 1 }
            if let index { s.entries[index] = entry } else { s.entries.append(entry) }
            s.bytes = s.bytes - oldBytes + bytes
            return true
        }
    }

    /// Stop retaining the full declaration immediately. A bounded service-ID
    /// tombstone remains across OFF until a new ON catalogue signs withdrawal.
    public static func withdraw(serviceID: String) {
        state.withLockedValue { s in
            guard let index = s.entries.firstIndex(where: { $0.id == serviceID }) else { return }
            let oldBytes = s.entries[index].bytes
            s.entries[index].payload = Array(serviceID.utf8)
            s.entries[index].withdrawing = true
            s.entries[index].serial = s.next
            s.next &+= 1
            if s.next == 0 { s.next = 1 }
            wendy_service_replay_changed(&s.entries[index].replay)
            s.bytes += s.entries[index].bytes - oldBytes
        }
    }

    /// Last replay result: zero acknowledges this catalogue incarnation; -2
    /// means pending/OFF. Other values are native validation/admission results.
    public static func lastResult(serviceID: String) -> Int32? {
        state.withLockedValue { s in s.entries.first { $0.id == serviceID }?.replay.last_result }
    }

    /// Bounded to one declaration per pump. Explicit loops may call this too;
    /// per-entry native checks and temporary retries are capped at once/second.
    public static func poll() {
        let now = UInt64(bitPattern: sys_uptime_ms())
        let work: Entry? = state.withLockedValue { s in
            guard !s.polling, !s.entries.isEmpty else { return nil }
            for _ in 0..<s.entries.count {
                s.cursor %= s.entries.count
                let entry = s.entries[s.cursor]
                s.cursor += 1
                if entry.replay.next_check_ms <= now { s.polling = true; return entry }
            }
            return nil
        }
        guard var work else { return }
        let result = work.payload.withUnsafeBytes { bytes in
            wendy_service_replay_step(&work.replay, bytes.baseAddress, Int32(bytes.count), work.withdrawing ? 1 : 0, now)
        }
        state.withLockedValue { s in
            defer { s.polling = false }
            guard let index = s.entries.firstIndex(where: { $0.serial == work.serial }) else { return }
            if work.withdrawing && result == 0 {
                s.bytes -= s.entries[index].bytes
                s.entries.remove(at: index)
                if s.entries.isEmpty { s.entries = []; s.cursor = 0 }
            } else { s.entries[index].replay = work.replay }
        }
    }
}
