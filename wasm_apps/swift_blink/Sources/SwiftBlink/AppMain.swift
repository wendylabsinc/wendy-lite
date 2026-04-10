import WendyLite

@inline(__always)
private func rmtSymbol(
    _ level0: UInt32, _ dur0: UInt32,
    _ level1: UInt32, _ dur1: UInt32
) -> UInt32 {
    (dur0 & 0x7FFF) | ((level0 & 1) << 15) |
    ((dur1 & 0x7FFF) << 16) | ((level1 & 1) << 31)
}

@inline(__always)
private func encodeByte(_ byte: UInt8, _ ptr: UnsafeMutablePointer<UInt32>, _ offset: Int) {
    let bit1 = rmtSymbol(1, 9, 0, 3)
    let bit0 = rmtSymbol(1, 3, 0, 9)
    ptr[offset + 0] = (byte & 0x80) != 0 ? bit1 : bit0
    ptr[offset + 1] = (byte & 0x40) != 0 ? bit1 : bit0
    ptr[offset + 2] = (byte & 0x20) != 0 ? bit1 : bit0
    ptr[offset + 3] = (byte & 0x10) != 0 ? bit1 : bit0
    ptr[offset + 4] = (byte & 0x08) != 0 ? bit1 : bit0
    ptr[offset + 5] = (byte & 0x04) != 0 ? bit1 : bit0
    ptr[offset + 6] = (byte & 0x02) != 0 ? bit1 : bit0
    ptr[offset + 7] = (byte & 0x01) != 0 ? bit1 : bit0
}

private func ws2812Send(_ channel: Int32, _ r: UInt8, _ g: UInt8, _ b: UInt8) {
    var buf: (
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32,
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32,
        UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32,
        UInt32
    ) = (
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0
    )

    withUnsafeMutablePointer(to: &buf) { tuplePtr in
        let ptr = UnsafeMutableRawPointer(tuplePtr)
            .assumingMemoryBound(to: UInt32.self)

        encodeByte(g, ptr, 0)
        encodeByte(r, ptr, 8)
        encodeByte(b, ptr, 16)
        ptr[24] = rmtSymbol(0, 500, 0, 500)

        _ = RMT.transmit(
            channelId: channel,
            buffer: UnsafeRawPointer(ptr).assumingMemoryBound(to: UInt8.self),
            length: 25 * 4
        )
    }
}

private func sleepMs(_ ms: Int64, clock: WendyClock) async {
    try? await clock.sleep(for: .milliseconds(ms))
}

private func blinkLoop(channel: Int32, clock: WendyClock) async {
    while true {
        ws2812Send(channel, 255, 0, 0)
        await sleepMs(500, clock: clock)
        ws2812Send(channel, 0, 255, 0)
        await sleepMs(500, clock: clock)
        ws2812Send(channel, 0, 0, 255)
        await sleepMs(500, clock: clock)
        ws2812Send(channel, 255, 255, 0)
        await sleepMs(500, clock: clock)
        ws2812Send(channel, 0, 255, 255)
        await sleepMs(500, clock: clock)
        ws2812Send(channel, 255, 0, 255)
        await sleepMs(500, clock: clock)
        ws2812Send(channel, 255, 255, 255)
        await sleepMs(500, clock: clock)
        ws2812Send(channel, 0, 0, 0)
        await sleepMs(500, clock: clock)
    }
}

@main
struct Main {
    static func main() async {
        WendyRuntime.initAsyncRuntime()

        let clock = WendyClock()
        let channel = RMT.configure(pin: 8, resolutionHz: 10_000_000)
        if channel < 0 {
            return
        }

        await blinkLoop(channel: channel, clock: clock)
    }
}
