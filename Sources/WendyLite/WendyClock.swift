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

/// Called during WendyLiteApp bootstrap to wire up timer events.
func registerTimerCallback() {
    CallbackDispatch.register(timerCallbackHandlerID) { _, _, _ in
        TimerState.shared.timerFired()
    }
}

// MARK: - Timer hub internals

private let attosecondsPerMillisecond: Int64 = 1_000_000_000_000_000

/// Per-call cancellation handshake state. Lives between the `operation` and
/// `onCancel` closures of `withTaskCancellationHandler` for one `sleep()` call.
fileprivate final class SleepRegistration: Sendable {
    private struct State {
        var waiterID: UInt64? = nil
        var isCancelled = false
    }
    private let state = _LockedBox(State())

    func setWaiterID(_ id: UInt64) {
        state.withLockedValue { $0.waiterID = id }
    }

    func waiterID() -> UInt64? {
        state.withLockedValue { $0.waiterID }
    }

    func markCancelledAndExchangeWaiterID() -> UInt64? {
        state.withLockedValue { s in
            s.isCancelled = true
            return s.waiterID
        }
    }

    func isCancelled() -> Bool {
        state.withLockedValue { $0.isCancelled }
    }
}

internal enum TimerState {
    static let shared = TimerHub()
}

internal final class TimerHub: Sendable {
    fileprivate struct Waiter {
        let id: UInt64
        let deadline: WendyClock.Instant
        let continuation: CheckedContinuation<Void, Never>
    }

    private struct State {
        var waiters: [Waiter] = []
        var readyWaiters: [Waiter] = []
        var activeTimerID: Int32 = 0
        var activeTimerDeadline: WendyClock.Instant? = nil
        var nextWaiterID: UInt64 = 1
    }
    private let state = _LockedBox(State())

    func sleep(until deadline: WendyClock.Instant) async throws(CancellationError) {
        if deadline <= WendyClock().now {
            if Task.isCancelled {
                throw CancellationError()
            }
            return
        }

        let registration = SleepRegistration()
        await withTaskCancellationHandler(operation: { [self] in
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let cancelled: Bool = state.withLockedValue { s in
                    let id = s.nextWaiterID
                    s.nextWaiterID &+= 1
                    insertLocked(Waiter(id: id, deadline: deadline, continuation: continuation), into: &s)
                    registration.setWaiterID(id)
                    rescheduleForEarliestDeadlineLocked(state: &s)
                    return registration.isCancelled()
                }
                if cancelled {
                    if let waiterID = registration.waiterID() {
                        cancelSleep(id: waiterID)
                    }
                }
            }
        }, onCancel: { [self] in
            if let waiterID = registration.markCancelledAndExchangeWaiterID() {
                cancelSleep(id: waiterID)
            }
        })

        if Task.isCancelled {
            throw CancellationError()
        }
    }

    func cancelSleep(id: UInt64) {
        let toResume: Waiter? = state.withLockedValue { s in
            if let index = s.waiters.firstIndex(where: { $0.id == id }) {
                let waiter = s.waiters.remove(at: index)
                rescheduleForEarliestDeadlineLocked(state: &s)
                return waiter
            }
            if let index = s.readyWaiters.firstIndex(where: { $0.id == id }) {
                return s.readyWaiters.remove(at: index)
            }
            return nil
        }
        toResume?.continuation.resume()
    }

    func timerFired() {
        let now = WendyClock().now
        state.withLockedValue { s in
            s.activeTimerID = 0
            s.activeTimerDeadline = nil

            var remaining: [Waiter] = []
            remaining.reserveCapacity(s.waiters.count)
            s.readyWaiters.reserveCapacity(s.readyWaiters.count + s.waiters.count)

            for waiter in s.waiters {
                if waiter.deadline <= now {
                    s.readyWaiters.append(waiter)
                } else {
                    remaining.append(waiter)
                }
            }
            s.waiters = remaining
            rescheduleForEarliestDeadlineLocked(state: &s)
        }
        // Ready waiters are resumed by `drainReady`, called from the host
        // tick after `timerFired` returns.
    }

    func drainReady() {
        let toResume: [Waiter] = state.withLockedValue { s in
            let ready = s.readyWaiters
            s.readyWaiters.removeAll(keepingCapacity: true)
            return ready
        }
        for waiter in toResume {
            waiter.continuation.resume()
        }
    }

    private func insertLocked(_ waiter: Waiter, into s: inout State) {
        let index = s.waiters.firstIndex(where: { waiter.deadline < $0.deadline }) ?? s.waiters.endIndex
        s.waiters.insert(waiter, at: index)
    }

    private func rescheduleForEarliestDeadlineLocked(state s: inout State) {
        guard let nextDeadline = s.waiters.first?.deadline else {
            cancelActiveTimerIfNeededLocked(state: &s)
            return
        }

        if s.activeTimerID != 0, s.activeTimerDeadline == nextDeadline {
            return
        }

        cancelActiveTimerIfNeededLocked(state: &s)

        let now = WendyClock().now
        let delay = now.duration(to: nextDeadline)
        let delayMs = max(1, durationToMillisecondsRoundedUp(delay))

        // A negative timer ID means the host could not allocate or start an ESP timer
        // (for example, no free slots or esp_timer_create/start failure). We do not
        // recover from that in this environment; pending sleepers may stall.
        s.activeTimerID = Timer.setTimeout(ms: Int32(delayMs), handlerId: timerCallbackHandlerID)
        s.activeTimerDeadline = nextDeadline
    }

    private func cancelActiveTimerIfNeededLocked(state s: inout State) {
        if s.activeTimerID != 0 {
            Timer.cancel(timerId: s.activeTimerID)
            s.activeTimerID = 0
        }
        s.activeTimerDeadline = nil
    }

    private func durationToMillisecondsRoundedUp(_ duration: Duration) -> Int64 {
        if duration <= .zero {
            return 0
        }

        let components = duration.components
        if components.seconds > Int64.max / 1_000 {
            return Int64.max
        }

        var milliseconds = components.seconds * 1_000
        if components.attoseconds > 0 {
            let extraMilliseconds = (components.attoseconds + attosecondsPerMillisecond - 1) / attosecondsPerMillisecond
            if milliseconds > Int64.max - extraMilliseconds {
                return Int64.max
            }
            milliseconds += extraMilliseconds
        }

        return milliseconds
    }
}
