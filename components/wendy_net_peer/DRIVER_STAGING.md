# Native actor and outer driver

One preemptible actor owns carrier, Babel, gossip and established TLS state.
The separate serialized crypto worker owns each lent heavy operation until
completion. All I/O readiness, timer waits and work completions belong to the
outer driver; the portable actor core performs no sockets/timers/tasks.
No delegated endpoint implementation, operator proof or diagnostic task is
part of this layer. VIP adapters and persisted settings are explicitly inactive
until their separate delivery layers. Runtime remains OFF by default.

The existing baseline server must register work_enable after it is ready and
poll CPU and I/O work for its lifetime; no extra I/O task is required. The new
driver must quiesce submissions, drain crypto, and wait actual task reaping
before closing/reopening the ledger. Schema definitions are introduced here as
typed driver contracts; every existing nanopb/Go binding must regenerate in
this same branch before acceptance. Supported management delegates join last.

## Wire evolution boundaries

The carrier TLS ALPN `wendy-local-mesh-ble/2` selects the device-router
hello, five-byte frame header and packet subtypes. Its version1 hello keeps
required device/peer identity, role and capacity checks, while ignoring
additional map fields. Unknown outer frame types are drained through the
existing scratch buffer, within the control-frame size ceiling and ordinary
progress/deadline limits. Unknown datagram subtypes are discarded without
changing fragment reassembly. Malformed supported types retain their existing
validation. New incompatible subtypes use a fresh discriminator, while a
change to the framing header requires an explicitly negotiated ALPN.

Within a carrier, the `time` control map has its own `v` field. New messages
write1; missing or zero means the original version1. Unknown operations or
unsupported versions are ignored without modifying an outstanding timestamp
request. The four current operations are request, next, reply and error.
An incompatible timestamp schema can therefore evolve independently of the
carrier mux, and optional fields do not require a version change. Other
control families retain their own signed-object or protocol version scopes.

Optional CBOR fields stay within the shared definite-length map/array, text,
byte-string, integer, boolean and null profile and the existing byte, token
and depth bounds. Adding a different CBOR dialect requires explicit protocol
negotiation; it must not silently change the interpretation of an existing
version. Standard IPv6/TCP/UDP and guest-owned payloads keep their own
protocol contracts.
