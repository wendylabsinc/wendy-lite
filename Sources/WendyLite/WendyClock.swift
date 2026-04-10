import CWendyLite
import _Concurrency

// Embedded Swift cannot satisfy Clock's untyped throwing requirement here,
// so WendyClock remains a concrete async-sleep API instead of conforming to Clock.
public struct WendyClock: Sendable {
    public struct Instant: Comparable, Hashable, Sendable {
        fileprivate let uptime: Duration

        fileprivate init(_ uptime: Duration) {
            self.uptime = uptime
        }

        public func advanced(by duration: Duration) -> Instant {
            Instant(uptime + duration)
        }

        public func duration(to other: Instant) -> Duration {
            other.uptime - uptime
        }

        public static func == (lhs: Instant, rhs: Instant) -> Bool {
            lhs.uptime == rhs.uptime
        }

        public static func < (lhs: Instant, rhs: Instant) -> Bool {
            lhs.uptime < rhs.uptime
        }

        public func hash(into hasher: inout Hasher) {
            hasher.combine(uptime)
        }
    }

    public init() {}

    public var now: Instant {
        Instant(.milliseconds(System.uptimeMs()))
    }

    public var minimumResolution: Duration {
        .milliseconds(1)
    }

    public func sleep(until deadline: Instant, tolerance: Duration? = nil) async throws(CancellationError) {
        try await TimerState.shared.sleep(until: deadline)
    }

    public func sleep(for duration: Duration, tolerance: Duration? = nil) async throws(CancellationError) {
        try await sleep(until: now.advanced(by: duration), tolerance: tolerance)
    }
}

// MARK: - Timer callback registration

private let timerCallbackHandlerID: Int32 = 1

/// Called by WendyRuntime.initAsyncRuntime() to wire up timer events.
func registerTimerCallback() {
    CallbackDispatch.register(timerCallbackHandlerID) { _, _, _ in
        TimerState.shared.timerFired()
    }
}

// MARK: - Timer hub internals

private let attosecondsPerMillisecond: Int64 = 1_000_000_000_000_000

private final class SleepRegistration: @unchecked Sendable {
    var waiterID: UInt64?
    var isCancelled = false
}

internal enum TimerState {
    nonisolated(unsafe) static var shared = TimerHub()
}

internal final class TimerHub {
    struct Waiter {
        let id: UInt64
        let deadline: WendyClock.Instant
        let continuation: CheckedContinuation<Void, Never>
    }

    var waiters: [Waiter] = []
    var readyWaiters: [Waiter] = []
    var activeTimerID: Int32 = 0
    var activeTimerDeadline: WendyClock.Instant?
    var nextWaiterID: UInt64 = 1

    func sleep(until deadline: WendyClock.Instant) async throws(CancellationError) {
        if deadline <= WendyClock().now {
            if Task.isCancelled {
                throw CancellationError()
            }
            return
        }

        // Safety: the registration fields are accessed unsynchronized from
        // the operation and onCancel closures. This is correct on the WASM
        // single-threaded cooperative executor where onCancel cannot interleave
        // with the synchronous continuation body. The isCancelled check after
        // setting waiterID handles the case where cancellation arrived before
        // the continuation was created.
        let registration = SleepRegistration()
        await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let waiter = Waiter(id: nextWaiterID, deadline: deadline, continuation: continuation)
                nextWaiterID &+= 1
                insert(waiter)
                registration.waiterID = waiter.id
                rescheduleForEarliestDeadline()

                if registration.isCancelled {
                    cancelSleep(id: waiter.id)
                }
            }
        }, onCancel: {
            registration.isCancelled = true
            if let waiterID = registration.waiterID {
                TimerState.shared.cancelSleep(id: waiterID)
            }
        })

        if Task.isCancelled {
            throw CancellationError()
        }
    }

    func cancelSleep(id: UInt64) {
        if let index = waiters.firstIndex(where: { $0.id == id }) {
            let waiter = waiters.remove(at: index)
            rescheduleForEarliestDeadline()
            waiter.continuation.resume()
            return
        }

        if let index = readyWaiters.firstIndex(where: { $0.id == id }) {
            let waiter = readyWaiters.remove(at: index)
            waiter.continuation.resume()
        }
    }

    func timerFired() {
        activeTimerID = 0
        activeTimerDeadline = nil

        let now = WendyClock().now
        var remaining: [Waiter] = []
        remaining.reserveCapacity(waiters.count)
        readyWaiters.reserveCapacity(readyWaiters.count + waiters.count)

        for waiter in waiters {
            if waiter.deadline <= now {
                readyWaiters.append(waiter)
            } else {
                remaining.append(waiter)
            }
        }

        waiters = remaining
        rescheduleForEarliestDeadline()
    }

    func drainReady() {
        guard !readyWaiters.isEmpty else {
            return
        }

        let waiters = readyWaiters
        readyWaiters.removeAll(keepingCapacity: true)
        for waiter in waiters {
            waiter.continuation.resume()
        }
    }

    private func insert(_ waiter: Waiter) {
        let index = waiters.firstIndex(where: { waiter.deadline < $0.deadline }) ?? waiters.endIndex
        waiters.insert(waiter, at: index)
    }

    private func rescheduleForEarliestDeadline() {
        guard let nextDeadline = waiters.first?.deadline else {
            cancelActiveTimerIfNeeded()
            return
        }

        if activeTimerID != 0, activeTimerDeadline == nextDeadline {
            return
        }

        cancelActiveTimerIfNeeded()

        let now = WendyClock().now
        let delay = now.duration(to: nextDeadline)
        let delayMs = max(1, durationToMillisecondsRoundedUp(delay))

        // A negative timer ID means the host could not allocate or start an ESP timer
        // (for example, no free slots or esp_timer_create/start failure). We do not
        // recover from that in this environment; pending sleepers may stall.
        activeTimerID = Timer.setTimeout(ms: Int32(delayMs), handlerId: timerCallbackHandlerID)
        activeTimerDeadline = nextDeadline
    }

    private func cancelActiveTimerIfNeeded() {
        if activeTimerID != 0 {
            Timer.cancel(timerId: activeTimerID)
            activeTimerID = 0
        }
        activeTimerDeadline = nil
    }

    private func durationToMillisecondsRoundedUp(_ duration: Duration) -> Int64 {
        let components = duration.components
        let totalAttoseconds = components.seconds &* 1_000 &* attosecondsPerMillisecond + components.attoseconds
        if totalAttoseconds <= 0 {
            return 0
        }
        return (totalAttoseconds + attosecondsPerMillisecond - 1) / attosecondsPerMillisecond
    }
}
