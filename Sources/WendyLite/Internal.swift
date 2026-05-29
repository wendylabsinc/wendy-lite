import Synchronization

// MARK: - Internal lock primitive
//
// TODO (Swift 6.4): drop this whole file in favour of `Synchronization.Mutex`.
// Mutex is not exposed by the embedded `Synchronization` module in our pinned
// Swift 6.3.x SDK -- the gate was added on `release/6.4.x` in swiftlang/swift
// commit bfa88573f73 ("Embedded Synchronization: enable `Mutex` for Wasm").
// Every WendyLite use site holds `Sendable` state and can move to `Mutex`
// directly once 6.4 ships; `CallbackDispatch` would also need its handler
// parameter to gain `@Sendable`, which is fine for all in-tree callers.
// (WendyNet's separate copy in `Backend+WendyLite.swift` stays -- it
// genuinely needs to wrap non-`Sendable` user pipeline-stage closures.)
//
// `_LockedBox<T>` is a lock-protected carrier for mutable `Sendable` state,
// the same shape SwiftNIO ships as `NIOLockedValueBox`. The class is marked
// `@unchecked Sendable` because it contains a mutable stored property
// (`var value: T`); the compiler can't see that all writes happen inside
// the lock, so we assert it manually.
//
// ## Lock implementation
//
// `Synchronization.Atomic<Bool>` spinlock. On WASM's single-threaded
// cooperative executor the spin loop will never iterate -- there is no other
// thread to contend with, and synchronous code cannot interleave at the lock
// boundary. The lock is logically a no-op there, but writing it as a real
// lock (rather than no synchronization at all) means the `@unchecked Sendable`
// claim is grounded in lock discipline, not in "trust the executor": if WASI
// ever gains pre-emptive scheduling or multi-threaded executors, the code
// still works.

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
