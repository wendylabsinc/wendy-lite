import Synchronization

// MARK: - Internal lock primitive
//
// This is the only `@unchecked Sendable` declaration in the WendyLite library.
// It plays the combined role of SwiftNIO's `NIOLockedValueBox` (lock-protected
// mutation of `Sendable` state) and `NIOLoopBoundBox` (carrier of non-`Sendable`
// state confined by external discipline). We have only the lock, so the box
// accepts non-`Sendable` `T` and trusts callers to keep the value inside
// `withLockedValue`.
//
// ## Why `@unchecked Sendable` rather than plain `Sendable`?
//
// The class has a `var value: T` of arbitrary `T`. The compiler cannot prove
// a stored mutable property is safe to share across isolation without knowing
// the synchronization mechanism. We assert it manually: the value is only ever
// touched while the spinlock is held, so concurrent calls to `withLockedValue`
// are serialised even when `T` itself is not `Sendable`.
//
// ## Why this is safe with non-Sendable `T` (e.g. WendyNet pipeline stages)
//
// Users implement `PipelineStage` as plain non-`Sendable` classes (mirroring
// SwiftNIO's `ChannelHandler`). The framework captures their `decode`/`encode`
// into non-`@Sendable` closures and stores them inside this box. Because the
// lock serialises every entry to those closures, the user's stage methods are
// invoked from at most one task at a time -- providing the same effective
// guarantee SwiftNIO's `EventLoop` provides to its handlers.
//
// The hazard `@unchecked Sendable` does NOT protect against: extracting the
// value out of `withLockedValue` and using it from outside the lock. Don't do
// that with non-`Sendable` `T`. Audit any `withLockedValue { ... return x }`
// where `x` is non-`Sendable`.
//
// ## Lock implementation
//
// `Synchronization.Atomic<Bool>` spinlock. On WASM's single-threaded
// cooperative executor the spin loop will never iterate -- there is no other
// thread to contend with, and synchronous code cannot interleave at the lock
// boundary. The lock is logically a no-op there, but writing it as a real lock
// (rather than no synchronization at all) means:
//
//   * The `@unchecked Sendable` claim is grounded in lock discipline, not in
//     "trust the executor"; if WASI ever gains pre-emptive scheduling or
//     multi-threaded executors, the code still works.
//   * The code reads honestly -- a reader sees a lock and understands the
//     guarantee, not a phantom no-op pretending to be one.
//
// We avoid `Synchronization.Mutex` here because its `withLock` body returns
// `sending Result`, which is incompatible with returning non-`Sendable`
// values out of `withLockedValue` -- defeating our ability to wrap non-Sendable
// `T`. The atomic-spinlock pattern has no such constraint.

final class _LockedBox<T>: @unchecked Sendable {
    private let locked = Atomic<Bool>(false)
    private var value: T

    init(_ value: T) {
        self.value = value
    }

    func withLockedValue<R, E: Error>(_ body: (inout T) throws(E) -> R) throws(E) -> R {
        // Acquire: CAS false->true. On WASM single-thread, no iteration.
        while !locked.compareExchange(
            expected: false,
            desired: true,
            ordering: .acquiring
        ).exchanged {
            // Spin. Unreachable on single-threaded cooperative executors.
        }
        defer { locked.store(false, ordering: .releasing) }
        return try body(&value)
    }
}
