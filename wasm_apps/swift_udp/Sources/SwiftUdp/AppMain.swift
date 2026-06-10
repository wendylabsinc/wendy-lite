@_spi(ExperimentalCustomExecutors)
import WendyLite
import WendyNet
import _Concurrency

// Use the async executor optimized for Wendy Lite
typealias DefaultExecutorFactory = WendyExecutorFactory

// Client and server in one process. Every board runs the same app, listens on
// `listenPort`, and sends a periodic hello to a hardcoded hub. Peer discovery
// will be introduced later.
private let peerHost = "10.1.1.217"
private let peerPort: UInt16 = 9000
private let listenPort: UInt16 = 9000
private let helloIntervalSeconds = 15
private let retryDelaySeconds = 5

@main
struct Main: WendyLiteApp {
    let clock = WendyClock()

    mutating func setup() async {
        Task { await runListener() }
        Task { await runSender() }
    }

    mutating func loop() async {
        try? await clock.sleep(for: .seconds(60))
    }
}

// MARK: - Server half

private func runListener() async {
    let clock = WendyClock()
    while true {
        do throws(WendyNetError) {
            let net = WendyNet()
            let listener = try await ServerBootstrap(wendyNet: net)
                .security(.insecure)
                .reliability(.unreliable)
                .bind(port: listenPort)
            print("[udp] listening on UDP \(listenPort)")

            try await listener.executeThenClose { (accepted: Accepted<ByteBuffer>) throws(WendyNetError) -> Void in
                await withTaskGroup(of: Void.self) { group in
                    do throws(WendyNetError) {
                        while let channel = try await accepted.next() {
                            group.addTask {
                                await logInbound(channel: channel)
                            }
                        }
                    } catch {
                        // .closed or .cancelled -- fall through and tear the
                        // group down.
                    }
                    group.cancelAll()
                }
            }
        } catch {
            print("[udp] listener failed; retrying")
        }
        try? await clock.sleep(for: .seconds(retryDelaySeconds))
    }
}

/// Log every datagram from one peer. The association lives until the listener
/// closes; UDP has no peer-initiated close.
private func logInbound(channel: Channel<ByteBuffer>) async {
    _ = try? await channel.executeThenClose { (inbound: Inbound<ByteBuffer>, _: Outbound<ByteBuffer>) throws(WendyNetError) -> Void in
        while var msg = try await inbound.next() {
            let bytes = msg.readBytes(length: msg.readableBytes) ?? []
            print("[udp] recv: \(String(decoding: bytes, as: UTF8.self))")
        }
    }
}

// MARK: - Client half

private func runSender() async {
    let clock = WendyClock()
    let startedAt = clock.now
    let ownId = readDeviceId()

    while true {
        do throws(WendyNetError) {
            let net = WendyNet()
            // One long-lived connected-UDP channel: a stable source port means
            // the hub sees a single peer association per board, rather than
            // leaking a fresh one per hello.
            let channel = try await ClientBootstrap(wendyNet: net)
                .security(.insecure)
                .reliability(.unreliable)
                .connect(to: Endpoint(hostname: peerHost, port: peerPort))

            try await channel.executeThenClose { (_: Inbound<ByteBuffer>, outbound: Outbound<ByteBuffer>) throws(WendyNetError) -> Void in
                while true {
                    let seconds = startedAt.duration(to: clock.now).components.seconds
                    let message = "Hello from \(ownId), up \(seconds)s"
                    _ = try await outbound.write(ByteBuffer(bytes: Array(message.utf8)))
                    print("[udp] sent -> \(peerHost):\(peerPort): \(message)")
                    try? await clock.sleep(for: .seconds(helloIntervalSeconds))
                }
            }
        } catch {
            print("[udp] sender failed; reconnecting")
        }
        try? await clock.sleep(for: .seconds(retryDelaySeconds))
    }
}

// MARK: - Device identity

/// Hex-MAC device id (e.g. "a1b2c3d4e5f6") so hellos are attributable in logs.
private func readDeviceId() -> String {
    var buf = [CChar](repeating: 0, count: 16)
    let n = buf.withUnsafeMutableBufferPointer { ptr -> Int32 in
        guard let base = ptr.baseAddress else { return -1 }
        return System.deviceId(buffer: base, length: Int32(ptr.count))
    }
    if n <= 0 { return "unknown" }
    return buf.withUnsafeBufferPointer { ptr -> String in
        guard let base = ptr.baseAddress else { return "unknown" }
        let bytes = UnsafeBufferPointer<UInt8>(
            start: UnsafeRawPointer(base).assumingMemoryBound(to: UInt8.self),
            count: Int(n)
        )
        return String(decoding: bytes, as: UTF8.self)
    }
}
