import WendyLite
import WendyNet
import _Concurrency

private let lineEnding = "\n"

@main
struct Main: WendyLiteApp {
    let clock = WendyClock()

    mutating func setup() async {
        Task {
            try? await chatServer()
        }
    }

    mutating func loop() async {
        try? await clock.sleep(for: .seconds(60))
    }
}

// MARK: - Chat Example: Pipeline Stages

/// Converts a newline-delimited byte stream into String messages.
final class LineCodec: PipelineStage, @unchecked Sendable {
    typealias Input = ByteBuffer
    typealias Output = String

    private var buffer = ByteBuffer()

    func decode(_ input: ByteBuffer, _ emit: (String) -> Void, _ fail: (WendyNetError) -> Void) {
        buffer.writeBuffer(input)
        while let line = extractLine() {
            emit(line)
        }
        buffer.discardReadBytes()
    }

    func encode(_ output: String) -> ByteBuffer {
        ByteBuffer(bytes: Array((output + lineEnding).utf8))
    }

    private func extractLine() -> String? {
        guard let newline = lineEnding.utf8.first else {
            return nil
        }

        for i in 0 ..< buffer.readableBytes {
            if buffer.getInteger(at: buffer.readerIndex + i, as: UInt8.self) == newline {
                guard var line = buffer.readSlice(length: i) else {
                    return nil
                }
                buffer.moveReaderIndex(by: 1)
                let bytes = line.readBytes(length: line.readableBytes) ?? []
                return String(decoding: bytes, as: UTF8.self)
            }
        }
        return nil
    }
}

// MARK: - Chat Server

final class ChatRoom: @unchecked Sendable {
    var clients: [Channel<String>] = []

    func add(_ client: Channel<String>) {
        clients.append(client)
    }

    func remove(_ client: Channel<String>) {
        var index = 0
        while index < clients.count {
            if clients[index] === client {
                clients.remove(at: index)
            } else {
                index += 1
            }
        }
    }

    private func openClients(excluding sender: Channel<String>? = nil) -> [Channel<String>] {
        var open: [Channel<String>] = []
        var index = 0
        while index < clients.count {
            let client = clients[index]
            if !client.isOpen {
                clients.remove(at: index)
                continue
            }
            if sender == nil || client !== sender {
                open.append(client)
            }
            index += 1
        }
        return open
    }

    func broadcast(_ message: String, from sender: Channel<String>) async {
        let outbound = "> \(message)"
        let recipients = openClients(excluding: sender)
        for client in recipients {
            _ = try? await client.send(outbound)
        }
    }

    func broadcastStatus() async {
        let recipients = openClients()
        let status = "peers connected: \(recipients.count)"
        for client in recipients {
            _ = try? await client.send(status)
        }
    }
}

func chatServer() async throws(WendyNetError) {
    let net = WendyNet()
    let room = ChatRoom()

    let server = ServerBootstrap(wendyNet: net)
        .security(.insecure)
        .pipeline { LineCodec() }

    let listener = try await server.bind(port: 9000)

    Task { [room] in
        let clock = WendyClock()
        while true {
            try? await clock.sleep(for: .seconds(30))
            await room.broadcastStatus()
        }
    }

    while let channel = try await listener.accept() {
        room.add(channel)

        Task { [room, channel] in
            do throws(WendyNetError) {
                while let msg = try await channel.receive() {
                    await room.broadcast(msg, from: channel)
                }
            } catch {
                _ = error
            }
            room.remove(channel)
        }
    }
}
