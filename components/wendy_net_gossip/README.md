Wire serialization now uses the breaking [binary CBOR format](../wendy_net_common/README.md),
including signed artifacts and certificate/timestamp payloads. No JSON/base64
fallback is accepted. FIFO/transfer policy below is independent of encoding.

# Native gossip cache

This actor-owned byte scheduler carries signed router artifacts (type 1) and
signed service records (type 2). Its caller verifies complete objects before
offering them. It does not grant identity, routing or service authority.

`HAVE` advertises an exact object digest. `WANT` starts a request; `DATA` carries
request-tagged chunks. `UNAVAILABLE` answers an individual request. The prototype
adds `GONE`, with the same digest and no request ID: it proactively withdraws
this session's supplier hint, allowing an alternate supplier to proceed without
waiting for the idle timeout. GONE does not withdraw the origin's signed record
or discard a copy held independently by the receiving node.

Upload and download limits apply across both categories and all sessions in a
pool. Pending download hints have a separate bounded FIFO, without reserving a
whole body per hint. Upload capacity exhaustion replies promptly with
UNAVAILABLE. A new HAVE can announce capacity again. Session-local limits remain
an additional bound, not a multiplier of the node-wide budget.

Optional `fifo` storage keeps separate payload quotas per category. It evicts the
oldest eligible idle object, including a still-valid one. Reads/re-observation do
not promote insertion order. Active outgoing transfers pin their exact object;
the small local route proof can also be excluded. Pins and incoming buffers
count within the same configured payload bounds. All-pinned pressure defers
admission. Metadata allocation and receive/verification workspace require their
own capacity accounting too.

An evicted object becomes a small retirement receipt through its original lease
plus the stale-HAVE hint lifetime. Repeated HAVEs and offers neither refill it nor
extend that receipt. Each existing session is sent GONE on its next polls;
backpressure does not consume notification progress. Category-specific cursors
avoid a separate notification allocation per peer/object. The object-count limit
also bounds receipt metadata; a full metadata table can refuse new objects.

The eviction observer runs before releasing the pool's immutable payload
reference. An adapter sharing that allocation must release its matching cache
reference too, retain useful verified projections/receipts, and stop generating
HAVEs for that body. Do not enable automatic eviction in an adapter that still
requires the full bytes for ordinary lookups or re-offers a retired object as
available. Local service liveness is independent of blob residency. Retiring a
local service blob preserves its verified endpoint/ownership state and origin
receipt; it neither withdraws the listener nor forces immediate republishing.
A later normal publication is a new generation. Metadata slots reserved for
the local route proof keep relay retirement churn from blocking that proof.

The firmware adapter enables FIFO with `WENDY_NET_TEST_BLOB_FIFO`, currently
default off while saturation is qualified. Catalogue projections and coordinated
release are wired. Current prototype parsers skip unknown
operations/control kinds while keeping validation for formats they understand.
Ignoring an unknown operation does not promise support for its semantics.
The CBOR wire replacement is explicitly breaking; no legacy compatibility layer
is planned.

Capacity refusal abandons a receive claim and ignores its already queued
remainder, allowing the next normal object on the same carrier. The planned
binary framing can carry size hints and cancellation to avoid that wasted
remainder. Verified adapter receipts suppress re-download after a body is
declined or its pool row expires. Payloads, receipts and pending hints all remain
bounded; an over-capacity node can have an incomplete catalogue or route view.
Expiry of a well-formed service publication is ordinary staleness, not grounds
to tear down its carrier. These caches do not guarantee every update reaches
every node before eviction, especially when an ESP is the only relay.
