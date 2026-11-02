# Signed routing sessions

One actor owns node state across authenticated carrier sessions. The component
starts no radio, actor, worker or public runtime by itself. Each carrier's outer
owner admits its verified TLS identity, supplies nonblocking send callbacks and
retains an input frame whenever a continuation returns positive. The outer
driver supplies timers and readiness. The existing baseline PKI provider polls
CPU and I/O work; the actor starts/binds the dedicated crypto worker and
quiesces it before waiting for the common task ledger to drain.

The sole gossiped artifact type carries complete signed device or operator
manifests. Services inherit their enclosing manifest's lifetime: the signed
`Expires - Issued`, positive and at most 15 minutes, with five-minute quiet
refresh. Signed `Issued` must be at or after the signing leaf's `NotBefore`;
signed `Expires` must not exceed the earliest `NotAfter` on the accepted path.
Issuer validity is checked separately at the receiver's certificate-policy
base time. Announcement dates do not establish its current time. The first
edit publishes immediately; later
edits coalesce behind a one-second gate. An immutable draft survives its whole
crypto operation. New Babel sequences remain queued until their exact origin
proof is published; existing IP route processing remains available while that
happens. The directory marks only a newly accepted revision as awaiting its
optional RAM checkpoint, avoiding a mesh-sized stack snapshot on each update.
Firmware supplies no persistence callback. Peer bytes, projections and replay
receipts are RAM-only; the existing own boot-reserved revision counter is the
only publication-related durable state.

Each first acceptance starts a receiver-monotonic deadline. The highest accepted
revision and exact body hash form a compact receipt; another signature or
envelope for the same body does not renew the deadline. Lower revisions do not
replace it, and a different body at the same revision is rejected. A higher
revision replaces the claim and starts its own lifetime. Withdrawal revokes the
live claim immediately.

An idle maintenance pass expunges expired full envelopes, gossip/export state,
route claims and foreign derived catalog/endpoint records. Local desired app
declarations remain for republishing, but their expired signed publication is
not browseable. A stalled upload cannot pin an expired payload. The compact
receipt remains until ten times the signed
duration has elapsed from that revision's first acceptance; duplicates do not
extend either deadline. Receipts are allocated individually as needed, rather
than evicting an older origin to fit a fixed receipt-slot count. Allocation
failure refuses new state without losing an existing receipt. Payload and
receipt cleanup are separate: a 15-minute body is removed at 15 minutes, while
its receipt is removed at 150 minutes.

Receipts belong to the mesh epoch and survive carrier retirement and neighbour
changes. Mesh OFF, enrollment/trust reset and reboot discard them. Once a
receipt is gone, a first-seen old record may be accepted for one new local
lifetime if its signer still passes current certificate checks. This is bounded
stale-state suppression, not proof that the
origin is currently online or that a first-seen announcement is recent in UTC.
Live Babel links and end-to-end TLS remain separate prerequisites for use;
management RPC and running application-port permissions remain independent.

The local TTL is an upper bound, not a substitute for continuing certificate
trust. A trusted public-time update or known certificate/issuer-window failure
can revoke an active claim, its gossip copy and derived service state sooner,
while retaining the compact receipt until its original 10x deadline. A missing
cached key or temporary repair failure is not itself proof of invalidity.

Mesh certificate verification has its own generation-bound time policy. Its base
is the later of actual wall time and a locally progressing anchor from the own
provisioned certificate and signed NVS floor. Selected issuers and all
`NotAfter` checks use this base. Only while boot time is explicitly uncertain,
the leaf's `NotBefore` can receive up to 24 hours of grace beyond the base.
Trusted public-time synchronization ends that grace for the generation; the
300-second fresh-TSA window aging out does not restore it. Own publications use
the same signing-leaf `NotBefore` and selected-path `NotAfter` bounds. This policy
applies to mesh carriers, mesh application TLS and routed native management, while Cloud
and direct LAN management keep their existing policy. It never writes a fake
fresh public-time proof.

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

These active-object/key cache ceilings do not cap the number of compact expiry
receipts. Receipts share the allocation ledger with the rest of mesh state;
the C6 profile can refuse new allocations when its memory budget is exhausted.

Raw FIFO eviction skips live active transfers and the local proof, sends the
existing GONE/UNAVAILABLE messages, and retains verified metadata rather than
refilling an evicted body. Expiry removes the payload even if an upload is
stalled; only its small transfer/digest bookkeeping can remain until completion
or closure. Exact already-verified certificate paths are
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

Clock-independent admission changes the receiver's lifetime policy without
changing the version-4 bytes or signature preimage. Legacy receivers can still
read the same artifacts but continue enforcing UTC freshness. They may reject
clock-uncertain bootstrap publications; mixed deployments need updated receivers
for the new bootstrap behavior. No origin-confirmation request, nonce exchange
or additional signed grant is part of this protocol.

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
