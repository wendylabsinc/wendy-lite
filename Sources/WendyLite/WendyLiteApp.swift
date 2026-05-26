@_spi(ExperimentalCustomExecutors)
import _Concurrency

private let runtimeWaitMs: Int32 = 250

private enum RuntimeBootstrapState {
    private struct State {
        var started = false
    }
    private static let state = _LockedBox(State())

    /// Atomically check-and-set the `started` flag. Returns `true` if this
    /// caller is the first to call it (i.e. should perform bootstrap work).
    static func claim() -> Bool {
        state.withLockedValue { s in
            if s.started { return false }
            s.started = true
            return true
        }
    }
}

private func pumpAsyncRuntimeOnce(timeoutMs: Int32) {
    _ = System.waitForEvent(timeoutMs: timeoutMs)
    TimerState.shared.drainReady()
}

private func bootstrapAsyncRuntime() {
    if !RuntimeBootstrapState.claim() {
        return
    }

    // If the app opted into `WendyMainExecutor` (via a top-level
    // `DefaultExecutorFactory` typealias), the executor itself registers the
    // timer callback and pumps host events from its own run loop.
    if Task.defaultExecutor is WendyMainExecutor {
        return
    }

    registerTimerCallback()

    // Drain any events that arrived before user code starts its main loop.
    pumpAsyncRuntimeOnce(timeoutMs: 0)

    _ = Task(priority: .background) {
        while true {
            pumpAsyncRuntimeOnce(timeoutMs: runtimeWaitMs)
            await Task.yield()
        }
    }
}

/// Entrypoint for Wendy Lite apps.
///
/// Conform a `@main` type to `WendyLiteApp`, use `setup()` for one-time startup
/// work, and implement `loop()` for one iteration of your application.
public protocol WendyLiteApp {
    init()

    /// Runs once after Wendy Lite bootstraps.
    ///
    /// Use this for startup work such as configuring hardware, connecting to
    /// services, or any other initialization that may need to `await`.
    mutating func setup() async

    /// Runs repeatedly after `setup()` completes.
    ///
    /// Implement one iteration of your application's steady-state behavior
    /// here. Wendy Lite calls this in a loop for the lifetime of the app.
    mutating func loop() async
}

extension WendyLiteApp {
    public mutating func setup() async {}

    public static func main() async {
        bootstrapAsyncRuntime()

        var app = Self()
        await app.setup()

        while true {
            await app.loop()
        }
    }
}
