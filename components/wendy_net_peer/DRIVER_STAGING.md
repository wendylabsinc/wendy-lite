# Mesh task and I/O driver

One preemptible task owns carrier connections, Babel, manifest exchange and
established TLS state. A separate, lower-priority crypto task processes one
heavy operation at a time. While a context is lent to that task, the mesh task
must not touch it; established connections using other contexts can continue.

The portable state machine performs no socket, timer or task operations.
Its outer driver supplies I/O readiness, timer deadlines and crypto completions.
Native and guest service adapters and WendyCom settings use the same bounded
runtime. It is off by default; disabling it releases its tasks and managed heap.

The existing management server registers `wendy_pki_work_enable()` when ready
and polls CPU and I/O work for its lifetime. Shutdown first quiesces submissions,
drains crypto and waits for actual task reaping before reopening the memory
owner. Settings that stop or restart the transport take effect after the
management response is sent, as described in [NATIVE_VIP.md](NATIVE_VIP.md).

For user configuration and resource limits, see
[Wendy Net on Wendy Lite](../../docs/wendy-net.md).

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

### Operator and application adapters

`wendy-net-operator-router/1` separately selects the operator hello and mux,
including its distinct control/datagram type numbers. The same bounded
unknown-frame draining and unsupported datagram discard rules apply.

Application TCP/UDP streams use the separate `wendy-app-mesh-tls/1` ALPN.
Their fixed requests are explicitly selected by `WAS1` (TCP) or `WAU3` (UDP),
with `WUA3` acknowledging the UDP capacity; subsequent TCP bytes are opaque
application data and UDP records have a two-byte length. An incompatible
fixed header requires a new supported magic/ALPN rather than an appended
field. An unsupported unframed application handshake ends only that
application connection because its body boundary is not otherwise known.
Native management is a different `wendy-com/2` TLS scope and hands plaintext
to WendyCom; it does not interpret management messages as app/carrier data.
BLE CoC exposes a byte stream beneath TLS and has no additional Wendy frame.
