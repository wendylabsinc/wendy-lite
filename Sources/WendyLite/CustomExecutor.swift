// Custom cooperative executor for WendyLite apps.
//
// This exists to provide custom behavior for when no Swift tasks are runnable:
// we automatically yield to the host to wait for incoming events, such as I/O
// and timers. This is safe to do because once all tasks are suspended (at an
// await point), only an external trigger will make them resume again.
//
// It has the same shape as the stdlib's `CooperativeExecutor`: `runUntil`
// snapshots the priority queue each iteration and drains the snapshot.
// Anything enqueued during the drain lands in the _next_ snapshot, so a job
// already queued always runs before any freshly-arrived work, even if the new
// work is higher priority, to avoid starving low-priority tasks under heavy
// load.
//
// If an app is using the default executor instead of this one, WendyLite
// installs a background "yield pump" task that yields to the host regularly.
// Due to the design of the default scheduler, priority inversion can still
// occur and awaits between user tasks/actors can be artificially delayed.
// In practice this shows up as oddly high latency in interactive networking
// software.

@_spi(ExperimentalCustomExecutors)
import _Concurrency

/// Maximum time the runtime will block on the host callback queue when no
/// Swift work is runnable.
internal let hostEventWaitCapMs: Int32 = 250

// MARK: - Priority-ordered run queue

fileprivate struct _PendingJob {
    let job: UnownedJob
    let priority: UInt8
}

// Max-heap on UInt8 priority.
fileprivate struct _RunQueue {
    private var storage: [_PendingJob] = []

    var isEmpty: Bool { storage.isEmpty }

    mutating func push(_ entry: _PendingJob) {
        storage.append(entry)
        upHeap(from: storage.count - 1)
    }

    mutating func pop() -> _PendingJob? {
        if storage.isEmpty { return nil }
        storage.swapAt(0, storage.count - 1)
        let result = storage.removeLast()
        if !storage.isEmpty {
            downHeap(from: 0)
        }
        return result
    }

    private mutating func upHeap(from ndx: Int) {
        var i = ndx
        while i > 0 {
            let parent = (i - 1) / 2
            if storage[i].priority > storage[parent].priority {
                storage.swapAt(i, parent)
                i = parent
            } else {
                break
            }
        }
    }

    private mutating func downHeap(from ndx: Int) {
        var i = ndx
        let n = storage.count
        while true {
            let left = 2 * i + 1
            let right = 2 * i + 2
            var largest = i
            if left < n && storage[left].priority > storage[largest].priority {
                largest = left
            }
            if right < n && storage[right].priority > storage[largest].priority {
                largest = right
            }
            if largest == i { break }
            storage.swapAt(i, largest)
            i = largest
        }
    }
}

// MARK: - Executor

@_spi(ExperimentalCustomExecutors)
public final class WendyMainExecutor: @unchecked Sendable {
    private struct State {
        var queue = _RunQueue()
        var shouldStop = false
        var timerCallbackRegistered = false
    }
    private let state = _LockedBox(State())

    public init() {}

    fileprivate func push(_ entry: _PendingJob) {
        state.withLockedValue { $0.queue.push(entry) }
    }

    /// Atomically swap the run queue out for a fresh empty one. The caller
    /// drains the returned snapshot; concurrent `enqueue`s land in `state.queue`
    /// and become the next iteration's batch.
    fileprivate func takeBatch() -> _RunQueue {
        state.withLockedValue { s in
            let snapshot = s.queue
            s.queue = _RunQueue()
            return snapshot
        }
    }
}

extension WendyMainExecutor: Executor {
    public func enqueue(_ job: UnownedJob) {
        push(_PendingJob(job: job, priority: job.priority.rawValue))
    }

    public func enqueue(_ job: consuming ExecutorJob) {
        let priority = job.priority.rawValue
        push(_PendingJob(job: UnownedJob(job), priority: priority))
    }
}

extension WendyMainExecutor: SerialExecutor {
    public func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        UnownedSerialExecutor(ordinary: self)
    }
}

extension WendyMainExecutor: TaskExecutor {}

extension WendyMainExecutor: RunLoopExecutor {
    public func run() {
        runUntil { false }
    }

    public func runUntil(_ condition: () -> Bool) {
        // Lazily register the timer callback the first time the run loop spins.
        // We can't do this in `init()` because the callback dispatch table is
        // initialised later. Doing it here means whatever ordering the runtime
        // chooses, the registration happens before the first job runs.
        let needRegister: Bool = state.withLockedValue { s in
            if s.timerCallbackRegistered { return false }
            s.timerCallbackRegistered = true
            return true
        }
        if needRegister {
            registerTimerCallback()
        }

        while true {
            if state.withLockedValue({ $0.shouldStop }) { break }
            if condition() { break }

            // Snapshot-and-drain. Anything enqueued by jobs in this batch
            // (continuation resumptions, actor hops, new Tasks) accumulates
            // in `state.queue` and is processed by the next iteration. That
            // is what keeps low-priority work from starving when the system
            // is under sustained high-priority load.
            var batch = takeBatch()
            while let entry = batch.pop() {
                ExecutorJob(entry.job).runSynchronously(on: asUnownedSerialExecutor())
            }

            // If draining the batch enqueued more work, loop back immediately
            // and process it as the next batch. Each await in a hot path
            // typically resumes one continuation into the next snapshot, and
            // we want zero idle-wait latency between those batches.
            if !state.withLockedValue({ $0.queue.isEmpty }) { continue }

            // Genuinely idle. Block on the host callback queue;
            // `xQueueReceive` wakes us as soon as anything is posted, so this
            // isn't polling. The `hostEventWaitCapMs` cap exists so
            // live-reload's "stop the wasm" handshake doesn't have to wait
            // arbitrarily long for us to surface from the block.
            //
            // `waitForEvent` also unconditionally trails a `vTaskDelay(1)` on
            // the C side to let lower-priority FreeRTOS tasks (Wi-Fi, the
            // wendy_net I/O loop, etc.) run. By calling it only on the idle
            // branch we keep that yield off the hot path: a chain of Swift
            // continuations completes without paying a tick per `await`.
            // Host callbacks that arrive while Swift is busy queue in the C
            // callback queue and are dispatched here on the next idle pass,
            // which is reached as soon as no Swift task is runnable.
            _ = System.waitForEvent(timeoutMs: hostEventWaitCapMs)
            TimerState.shared.drainReady()
        }
    }

    public func stop() {
        state.withLockedValue { $0.shouldStop = true }
    }
}

extension WendyMainExecutor: MainExecutor {
    public var isMainExecutor: Bool { true }
}

// MARK: - Factory

@_spi(ExperimentalCustomExecutors)
public struct WendyExecutorFactory: ExecutorFactory {
    public static let executor = WendyMainExecutor()
    public static var mainExecutor: any MainExecutor { executor }
    public static var defaultExecutor: any TaskExecutor { executor }
}
