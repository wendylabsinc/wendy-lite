# Signed routing sessions

One actor owns node state across authenticated carrier sessions. The component
starts no radio, actor, worker or public runtime by itself. Each carrier's outer
owner admits its verified TLS identity, supplies nonblocking send callbacks and
retains an input frame whenever a continuation returns positive. The outer
driver supplies timers and readiness. The existing baseline PKI provider polls
CPU and I/O work; the actor starts/binds the dedicated crypto worker and
quiesces it before waiting for the common task ledger to drain.

The sole gossiped artifact is a complete signed device manifest. Its services
share one inherited expiry: a 15-minute lease and five-minute quiet refresh,
bounded by certificate lifetime. The first edit publishes immediately; later
edits coalesce behind a one-second gate. An immutable draft survives its whole
crypto operation. New Babel sequences remain queued until their exact origin
proof is published; existing IP route processing remains available while that
happens. The directory marks only a newly accepted revision as awaiting its
optional RAM checkpoint, avoiding a mesh-sized stack snapshot on each update.
Firmware supplies no persistence callback. Peer bytes, projections and replay
receipts are RAM-only; the existing own boot-reserved revision counter is the
only publication-related durable state.

PSRAM nodes have a 512 KiB full-manifest FIFO, a 512 KiB certificate FIFO and
up to 512 KiB of derived service browse rows. These are ceilings, not eagerly
allocated arenas. SRAM uses an 8 KiB manifest/download pool, a 32 KiB public
certificate cache with eight parts/four descriptors, and the configured derived
browse capacity. Small meshes allocate only their observed entries. A supported
C6 profile has one authenticated gateway, no transit, eight retained verified
keys and up to 64 compact endpoint projections. Those projections survive key
FIFO eviction and permit outgoing VIP lookup when the individual manifest fits
the SRAM download bound. Larger individual manifests remain unavailable for
C6 outgoing lookup; incoming default-gateway traffic does not depend on them.
There is no independent service gossip, service signature or delegated leaf
protocol.

Raw FIFO eviction skips active transfers and the local proof, sends the
existing GONE/UNAVAILABLE messages, and retains bounded verified metadata rather
than refilling an evicted body. Exact already-verified certificate paths are
also not refilled solely because a hint repeats. One whole certificate part per
active carrier stays pinned through final-chunk queue admission. The worker's
own-DER read effect has one captured identity/epoch and never retains a node or
TLS pointer. Its read/verify APIs remain linkable without native activation.

A session resumes its startup inventory by UUID after backpressure; it never
restarts at the first origin on every pass. A later blocked edit schedules one
additional sweep after the current tail. Initial certificate-descriptor pressure
is deferred rather than rejecting an otherwise authenticated carrier. Unknown
control kinds, gossip operations and certificate variants are optional. Native
readers use their actual token storage. Unsupported signature schemes are
ignored without an identity fetch or carrier teardown; Lite supports P-256 and
ML-DSA-65 device keys, while WendyOS retains its broader verifier.

Signature jobs own immutable input copies. The main task cannot touch a lent
signing TLS context until `wncrypto_borrowed(connection)` becomes false, including
after cancellation. Verification jobs may outlive a closing protocol owner and
release their own copies. An allocation refusal recorded by the initiating
ledger converts a library's generic crypto failure into a bounded retry; this
never accepts an unverified input. A concurrent refusal can conservatively cause
one extra retry. Identity repair retains metadata only in the async runtime,
while the completed gossip download owns the full body; the old copied-body
8 KiB limit does not reject a PSRAM node's larger valid manifest.

## Protocol evolution

The routing-session hello version covers its framed control messages, including
identity/manifest requests and certificate exchange. Gossip additionally carries
its own version and operation in each envelope. Babel packets carry version 2
and length-delimited TLVs; unknown optional TLVs and sub-TLVs are skipped. An
unknown mandatory sub-TLV suppresses its enclosing message according to Babel's
rules. These scopes can evolve independently from management and application
sessions.

Complete device/operator manifests carry body version 4, which also scopes the
nested route, owner, app-endpoint and service structures. Unknown optional map
fields are ignored, including fields in the outer signature envelope. Receivers
verify and retain the exact signed principal/body bytes, including unknown body
fields; they must not reconstruct a signed body from their understood fields.
Optional capabilities may be added to `caps`. A change that affects how a route
or service must be interpreted belongs in the manifest's `requires` mechanism
or a new body version. Unsupported versions and required extensions leave the
artifact unavailable without closing the carrier or advancing its accepted
revision. Unknown optional endpoint transports and service/system kinds omit
only that local projection; supported siblings, the signed route and the exact
raw relay artifact remain available. Unknown agent protocols expose no usable
agent endpoint and never fall back to a known protocol. Common service identity,
uniqueness and overall entry bounds still apply; known entries retain their
full schema validation. Endpoint arrays permit at most 16 total entries, with
only understood transports consuming the two current endpoint slots.

Additive fields use the current bounded CBOR profile: definite maps/arrays,
text/byte strings, integers, booleans and null. Adding a new CBOR representation
(such as a tag or floating-point field) is a profile change rather than an
optional field understood by these readers. Existing size, token and nesting
bounds still apply. The local WASM JSON publication ABI validates its own input;
it is not a network envelope or a separate signed service protocol.

## Component validation

The host suite covers routing, coalescing, backpressure, allocation retry, upload
pins, cancellation and C/Go manifest interoperability. Configure
`WENDYOS_GO_ROOT` to the WendyOS `go` directory to include its independent fixture
generator; select `^(session_|format_)` in CTest. These tests exercise component
state and formats, not complete radio or firmware resource use. See
[the component README](README.md) for build instructions. Complete firmware
limits also depend on the selected build configuration and carrier drivers.
