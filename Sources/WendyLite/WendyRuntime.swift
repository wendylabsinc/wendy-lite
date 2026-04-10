import CWendyLite
import _Concurrency

private let runtimeWaitMs: Int32 = 250

private enum RuntimeState {
    nonisolated(unsafe) static var started = false
}

public enum WendyRuntime {
    public static func poll() {
        TimerState.shared.drainReady()
    }

    public static func initAsyncRuntime() {
        if RuntimeState.started {
            return
        }

        RuntimeState.started = true
        registerTimerCallback()

        _ = Task(priority: .background) {
            while true {
                _ = System.waitForEvent(timeoutMs: runtimeWaitMs)
                poll()
                await Task.yield()
            }
        }
    }
}
