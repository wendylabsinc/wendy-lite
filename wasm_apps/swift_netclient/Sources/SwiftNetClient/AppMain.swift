@_spi(ExperimentalCustomExecutors)
import WendyLite
import WendyNet
import _Concurrency

// Use the async executor optimized for Wendy Lite
typealias DefaultExecutorFactory = WendyExecutorFactory

private let targetHost = "192.168.1.253"
private let targetPort: UInt16 = 4000
private let lineEnding = "\n"

@main
struct Main: WendyLiteApp {
    let clock = WendyClock()
    let startedAt: WendyClock.Instant

    init() {
        startedAt = clock.now
    }

    mutating func setup() async {}

    mutating func loop() async {
        await sendUptimeMessage()
        try? await clock.sleep(for: .seconds(60))
    }

    private func sendUptimeMessage() async {
        let uptime = startedAt.duration(to: clock.now)
        let seconds = uptime.components.seconds
        let message = "Swift has been up for \(seconds) seconds"

        do throws(WendyNetError) {
            let net = WendyNet()
            let channel = try await ClientBootstrap(wendyNet: net)
                .security(.insecure)
                .pipeline { LineCodec() }
                .connect(to: Endpoint(hostname: targetHost, port: targetPort))

            try await channel.executeThenClose { (_: Inbound<String>, outbound: Outbound<String>) throws(WendyNetError) -> Void in
                _ = try await outbound.write(message)
            }
        } catch {
            _ = error
        }
    }
}

final class LineCodec: PipelineStage {
    typealias Input = ByteBuffer
    typealias Output = String

    func decode(_ input: ByteBuffer, _ emit: (String) -> Void, _ fail: (WendyNetError) -> Void) {
        _ = input
    }

    func encode(_ output: String) -> ByteBuffer {
        ByteBuffer(bytes: Array((output + lineEnding).utf8))
    }
}
