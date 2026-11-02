# Native gossip cache

This standalone, single-owner byte scheduler depends only on
[common allocation helpers](../wendy_net_common/README.md). It has no PKI, actor,
service catalogue, flash persistence, transport, or wire parser. The integrating
runtime supplies digest identification, verifies complete artifacts before
offering them, and owns serialization. The scheduler does not grant identity,
routing, or service authority. The runtime uses the type-1 reserve for complete
signed manifests containing routing and services together. The scheduler's other
numeric categories retain their generic quota/hint policies; they do not imply
a separate service publication or signature. Type 3 uses the same shared bounds.

`HAVE` advertises an exact object digest. `WANT` starts a request; `DATA` carries
request-tagged chunks. `UNAVAILABLE` answers an individual request. `GONE`, with
the same digest and no request ID, proactively withdraws
this session's supplier hint, allowing an alternate supplier to proceed without
waiting for the idle timeout. GONE does not withdraw the origin's signed record
or discard a copy held independently by the receiving node.

Upload and download limits apply across all categories and all sessions in a
pool. Pending download hints have a separate bounded FIFO, without reserving a
whole body per hint. New announcements join the existing FIFO even when they
arrive between routing ticks. An admitted download uses its own idle timer;
expiry of its earlier HAVE does not cancel current progress. Upload capacity
exhaustion replies promptly with UNAVAILABLE. A new HAVE can announce capacity
again. Session-local limits remain an additional bound, not a multiplier of the
node-wide budget.

Optional `fifo` storage keeps separate payload quotas per category. It evicts the
oldest eligible idle object, including a still-valid one. Reads/re-observation do
not promote insertion order. Active outgoing transfers pin their exact object;
the small local route proof can also be excluded. Pins and incoming buffers
count within the same configured payload bounds. All-pinned pressure defers
admission. Metadata allocation and receive/verification workspace require their
own capacity accounting too. After verification, `wg_offer` of the callback's
exact bytes moves the existing receive allocation into the cache instead of
requiring a second full body. Its payload charge stays constant, and the body
remains pinned until that callback returns. Deferred verification retains the
same bounded allocation and download slot until resumed or pruned.

An evicted object becomes a small retirement receipt through its original lease
plus the stale-HAVE hint lifetime. Repeated HAVEs and offers neither refill it nor
extend that receipt. Each existing session is sent GONE on its next polls;
backpressure does not consume notification progress. Category-specific cursors
avoid a separate notification allocation per peer/object. The object-count limit
also bounds receipt metadata; a full metadata table can refuse new objects.
Critical and ordinary rows share the total table; ordinary rows alone obey the
smaller unreserved limit, independently of their arrival order.

The eviction observer runs before releasing the pool's immutable payload
reference. An adapter sharing that allocation must release its matching cache
reference too, retain useful verified projections/receipts, and stop generating
HAVEs for that body. Do not enable automatic eviction in an adapter that still
requires the full bytes for ordinary lookups or re-offers a retired object as
available. Integrations must keep local service liveness independent of blob
residency, preserving verified endpoint/ownership state and origin receipts when
a local blob is retired. Retirement must not withdraw a listener or force
immediate republishing. A later normal publication is a new generation. Metadata slots reserved for
the local route proof keep relay retirement churn from blocking that proof.

The integrating runtime chooses whether to enable FIFO and supplies demand,
protection, verified-receipt, and eviction callbacks as needed. This standalone
scheduler ignores unknown operations without applying current operations' field
rules or changing pool/session state. Known operations retain their validation.
Ignoring an unknown operation does not promise support for its semantics.

Capacity refusal abandons a receive claim and ignores its already queued
remainder, allowing the next normal object on the same carrier. A future
transport adapter can carry size hints and cancellation to avoid that wasted
remainder. Verified adapter receipts suppress re-download after a body is
declined or its pool row expires. Payloads, receipts and pending hints all remain
bounded; an over-capacity node can have an incomplete catalogue or route view.
Expiry of a well-formed service publication is ordinary staleness, not grounds
to tear down its carrier. These caches do not guarantee every update reaches
every node before eviction, especially when an ESP is the only relay.

## Standalone verification

Run `cmake -S tests -B <build-dir>`, build that directory, then
`ctest --test-dir <build-dir> --output-on-failure`. Host tests use OpenSSL only
for their SHA-256 identification callback; the component itself has no crypto
link dependency. The tests cover FIFO retirement and sticky receipts, proactive
withdrawal, shared payload ownership, bounded queues and transfers, demand and
route reservations, deferred completion, full-budget verified handoff, and
continued ordinary progress after pressure.
