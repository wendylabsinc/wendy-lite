@_spi(ExperimentalCustomExecutors)
import WendyLite
import WendyNet
import _Concurrency

// Use the async executor optimized for Wendy Lite
typealias DefaultExecutorFactory = WendyExecutorFactory

// Client and server in one process. Every board runs the same app, listens on
// `listenPort`, and sends a periodic hello to a hardcoded hub. Peer discovery
// will be introduced later.
private let peerHost = "192.168.1.61"
private let peerPort: UInt16 = 9000
private let listenPort: UInt16 = 9000
private let helloIntervalSeconds = 15
private let retryDelaySeconds = 5

@main
struct Main: WendyLiteApp {
    func loop() async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await runListener() }
            group.addTask { await runSender() }
        }
    }
}

// MARK: - Server half

private func runListener() async {
    let clock = WendyClock()
    while !Task.isCancelled {
        do throws(WendyNetError) {
            let net = WendyNet()
            let listener = try await ServerBootstrap(wendyNet: net)
                .security(.insecure)
                .reliability(.unreliable)
                .bind(port: listenPort)
            print("[udp] listening on UDP \(listenPort)")

            try await listener.executeThenClose { (accepted: Accepted<ByteBuffer>) throws(WendyNetError) -> Void in
                await withTaskGroup(of: Void.self) { group in
                    while let channel = try? await accepted.next() {
                        group.addTask {
                            await logInbound(channel: channel)
                        }
                    }
                    // Listener closed or errored
                    group.cancelAll()
                }
            }
        } catch {
            print("[udp] listener failed; retrying")
        }
        try? await clock.sleep(for: .seconds(retryDelaySeconds))
    }
}

/// Log every datagram from one peer
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
    // Random per-run tag so messages from different boards are distinguishable
    let ownId = UInt16.random(in: 0...9999)

    while !Task.isCancelled {
        do throws(WendyNetError) {
            let net = WendyNet()
            // One long-lived connected-UDP channel. Using a stable source port means
            // the hub sees a single peer association per board.
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
