@_spi(ExperimentalCustomExecutors)
import WendyLite
import WendyNet
import _Concurrency

// Use the async executor optimized for Wendy Lite
typealias DefaultExecutorFactory = WendyExecutorFactory

private let lineEnding = "\n"

@main
struct Main: WendyLiteApp {
    let clock = WendyClock()

    mutating func loop() async {
        try? await chatServer()
    }
}

// MARK: - Pipeline

final class LineCodec: PipelineStage {
    typealias Input = ByteBuffer
    typealias Output = String

    private var buffer = ByteBuffer()

    func decode(_ input: ByteBuffer, _ emit: (String) -> Void, _ fail: (WendyNetError) -> Void) {
        var input = input
        buffer.writeBuffer(&input)
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
                buffer.moveReaderIndex(forwardBy: 1)
                let bytes = line.readBytes(length: line.readableBytes) ?? []
                return String(decoding: bytes, as: UTF8.self)
            }
        }
        return nil
    }
}

// MARK: - Inbox
//
// Per-connection message queue.

actor Inbox {
    private var queue: [String] = []
    private var waiter: CheckedContinuation<String?, Never>?
    private var closed = false

    func push(_ msg: String) {
        if closed { return }
        if let w = waiter {
            waiter = nil
            w.resume(returning: msg)
        } else {
            queue.append(msg)
        }
    }

    func close() {
        closed = true
        if let w = waiter {
            waiter = nil
            w.resume(returning: nil)
        }
    }

    func pop() async -> String? {
        if !queue.isEmpty {
            return queue.removeFirst()
        }
        if closed {
            return nil
        }
        return await withCheckedContinuation { cont in
            waiter = cont
        }
    }
}

// MARK: - Chat Room

actor ChatRoom {
    private struct Subscriber {
        let id: Int
        let inbox: Inbox
    }

    private var subscribers: [Subscriber] = []
    private var nextID = 0

    func subscribe() -> (id: Int, inbox: Inbox) {
        let id = nextID
        nextID += 1
        let inbox = Inbox()
        subscribers.append(Subscriber(id: id, inbox: inbox))
        return (id, inbox)
    }

    func unsubscribe(id: Int) async {
        if let i = subscribers.firstIndex(where: { $0.id == id }) {
            let inbox = subscribers[i].inbox
            subscribers.remove(at: i)
            await inbox.close()
        }
    }

    func broadcast(_ message: String, from senderID: Int) async {
        let outbound = "> \(message)"
        // Snapshot the recipients so the actor re-entrant gap between pushes
        // doesn't accidentally include subscribers added mid-broadcast.
        let recipients = subscribers.filter { $0.id != senderID }.map { $0.inbox }
        for inbox in recipients {
            await inbox.push(outbound)
        }
    }

    func broadcastStatus() async {
        let recipients = subscribers.map { $0.inbox }
        let status = "peers connected: \(recipients.count)"
        for inbox in recipients {
            await inbox.push(status)
        }
    }
}

// MARK: - Chat Server

func chatServer() async throws(WendyNetError) {
    let net = WendyNet()
    let room = ChatRoom()

    let server = ServerBootstrap(wendyNet: net)
        .security(.insecure)
        .pipeline { LineCodec() }

    let listener = try await server.bind(port: 9000)

    try await listener.executeThenClose { (accepted: Accepted<String>) throws(WendyNetError) -> Void in
        // Embedded Swift forbids existential `any Error` values, so we can't use
        // `withThrowingTaskGroup` here.
        await withTaskGroup(of: Void.self) { group in
            // Heartbeat -- a structured child of the listener's scope.
            group.addTask { [room] in
                let clock = WendyClock()
                while !Task.isCancelled {
                    do throws(CancellationError) {
                        try await clock.sleep(for: .seconds(30))
                    } catch {
                        return
                    }
                    await room.broadcastStatus()
                }
            }

            // Accept loop drives the group. When this loop exits -- by the
            // listener closing or the surrounding task being cancelled --
            // the heartbeat child is cancelled and the group unwinds.
            do throws(WendyNetError) {
                while let channel = try await accepted.next() {
                    group.addTask { [room] in
                        await handleAcceptedChannel(channel: channel, room: room)
                    }
                }
            } catch {
                // .closed (listener torn down) or .cancelled (task cancelled);
                // either way, fall through to tear down the group.
            }

            group.cancelAll()
        }
    }
}

/// Wraps `channel.executeThenClose` for one accepted connection. Body is
/// explicitly typed-throws because Swift won't infer `throws(WendyNetError)`
/// for trailing closures captured into Task contexts.
private func handleAcceptedChannel(channel: Channel<String>, room: ChatRoom) async {
    let (id, inbox) = await room.subscribe()
    _ = try? await channel.executeThenClose { (inbound: Inbound<String>, outbound: Outbound<String>) throws(WendyNetError) -> Void in
        await runConnection(inbound: inbound, outbound: outbound, room: room, id: id, inbox: inbox)
    }
    await room.unsubscribe(id: id)
}

/// Drives a single accepted connection. Reads from `inbound` and broadcasts to
/// peers; concurrently pumps from `inbox` to `outbound`. When either side ends
/// (peer disconnect, write error) the other is cancelled via group teardown.
private func runConnection(
    inbound: Inbound<String>,
    outbound: Outbound<String>,
    room: ChatRoom,
    id: Int,
    inbox: Inbox
) async {
    await withTaskGroup(of: Void.self) { group in
        // Read messages from this peer and broadcast to others.
        group.addTask {
            do throws(WendyNetError) {
                while let msg = try await inbound.next() {
                    await room.broadcast(msg, from: id)
                }
            } catch {
                // Connection torn down -- fall through and
                // cancel the outbound pump.
            }
        }

        // Pump broadcast messages destined for this peer to outbound.
        group.addTask {
            while let msg = await inbox.pop() {
                do throws(WendyNetError) {
                    _ = try await outbound.write(msg)
                } catch {
                    return
                }
            }
        }

        // Wait for either child to finish, then tear down the other.
        _ = await group.next()
        group.cancelAll()
    }
}
