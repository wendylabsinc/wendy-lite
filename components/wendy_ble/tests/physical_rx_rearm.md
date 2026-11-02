# Physical L2CAP receive rearm under ordinary pressure

Previously DATA_RECEIVED ignored a failed receive-buffer handoff, while read()
cleared the owed flag before the handoff and also ignored its result. A temporary
six-block private-pool shortage could therefore leave the peer with no receive
buffer/credits and no retained intent to recover.

The adapter now records owed state until a successful SDK handoff. Subsequent
receive attempts execute through one coalesced event on the existing NimBLE host
queue. The host rechecks the current channel and available ring capacity; it holds
the adapter mutex during recv_ready (which does not invoke an application callback)
so the I/O session owner cannot release that channel halfway through the handoff.
Queued events contain no stale channel pointer. Read() only records/posts work.

Transient pressure retains owed state and uses the already existing10ms TX
backoff timer to retry RX as well. That timer still handles transmit hold-off;
an already armed timer is sufficient for both directions. No task or timer is
added. On this pinned SDK the event uses a4B RV32 handle and one existing fixed
NPL event-pool slot (12B); the RX retry flag is1B. Optional diagnostics add a4B
counter and rate-limit failure logs (first/every64), reporting return code, owed
state, private-pool free count and ring bytes, followed by recovery. These are
physical BLE baseline resources and remain outside the mesh allocation ledger.
The actual final linked static alignment delta is measured by the SDK image.

The SDK rejects EBUSY before adopting the caller's mbuf, so it is freed; an
already armed slot retains receive capability. Other SDK errors may occur after
adoption and must not double-free that buffer. Disconnect/end_session clear owed
and retry flags; later events safely observe current channel state.

The host fixture extracts the actual production adapter functions and transports
25,646 exact opaque bytes through245-byte SDUs and73-byte reads. It injects normal
bounded private-pool pressure and releases that capacity, verifies ring
backpressure, repeated recovery, SDK busy-buffer ownership and queued close/
reconnect cleanup under ASan/UBSan. This is a transport-byte fixture, not a claim
that it performs TLS itself. The existing actual mixed87 TLS I/O-slot fixture
separately validates the25,352-byte DER operator chain with short BIO operations.
C5/C6 actual SDK translation units pass with diagnostics enabled and disabled.

Hardware16c50dc/b9eebee physical management has both successes and repeatable
large-client-Certificate stalls at16,384+3,678 buffered bytes, without low heap.
This source-level rearm hole is real, but it has not yet been attributed as the
cause of those particular captures. No timeout or authentication policy changed.
