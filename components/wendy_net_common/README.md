# Wendy Net binary protocol

This is a breaking replacement of JSON/base64 transport encoding. There is one
binary decoder, no JSON fallback and no old-ALPN negotiation. Update peers
together. Stream carriers use `wendy-local-mesh-ble/2`, constrained endpoint
carriers use `wendy-net-endpoint/2`, and QUIC router carriers use
`wendy-net-router/3`. The separate raw application TLS protocol is unchanged.

Encoding is definite, length-first deterministic CBOR ([RFC 8949, §4.2.3](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.3)).
Maps use the documented existing field names, ordered by encoded key length and
then bytes. Integers use their shortest encoding. The current schemas use text,
byte strings, integers, booleans, arrays and maps; tags and indefinite containers
are excluded. UUIDs/principals/IP prefixes retain their established textual
spelling. Certificate hashes, fingerprints, freshness nonces, signatures and all
binary payloads use native byte strings. Nothing is base64 on the mesh wire.

The reliable neighbour stream retains its 4-byte big-endian payload length and
64 KiB frame bound. Catalogue fragments retain their two big-endian 32-bit
numbers, total and offset, followed by raw bytes inside the `catalog` byte
string. Catalogue messages, signed artifacts and their signed metadata bodies
are all CBOR too; binary is not wrapped inside another JSON layer.

- Certificate `chain` descriptors contain `principal` and an array of raw 32-byte
  `hashes`; requests/chunks contain raw `hash`, integer offsets/totals and raw
  DER `data`. Chunk scheduling, exact hashes and independent path validation
  retain their existing semantics.
- Gossip carries the existing `v`, `op`, `type`, raw 32-byte `digest`, request,
  offset, total and raw data fields. Optional zero/empty fields may be absent.
  HAVE/WANT/DATA/UNAVAILABLE/GONE and the bounded shared transfer scheduler retain
  their existing semantics. GONE promptly removes that peer as a supplier.
- Signed manifests contain `principal`, an embedded CBOR metadata map `body`, and
  a raw signature. Signed services contain a raw 32-byte `fingerprint`, embedded
  metadata body, and raw signature. Existing signature domains/principal binding
  are retained; the exact CBOR body bytes are the signature preimage.
- Signed origin inventories contain embedded CBOR body and certificate-chain
  descriptor maps plus a raw signature. Receipt hashes/nonces are raw 32-byte
  values. Freshness chunks and TSA replies also carry raw binary data.

Unknown transport kinds and gossip operations are ignored before interpreting a
new payload schema; additive transport fields are allowed. They must not end an
otherwise healthy carrier. Origin-signed schemas retain exact field/lease/trust
validation, including bounds and independently verified identity metadata.

WendyOS uses fxamacker/cbor v2.9.0 with shared immutable modes. Lite uses a portable,
allocation-free wire parser over immutable spans and a caller-owned writer. Its
12-byte tokens retain their previous size; large inventories retain an array
span and iterate one receipt at a time. Bounded FIFO retirement, pinning during
uploads, metadata reservations and endpoint summaries are independent of encoding.

Local WASM service publication and browsing still use their JSON API. Lite
imports a guest definition once into binary registry storage and renders verified
metadata back to JSON for the app. Cloud issuance HTTP and host disk journals or
diagnostics also retain their respective formats. None is a mesh wire fallback.

## Allocation accounting

`include/wendy_net_memory.h` supplies a caller-owned bounded allocation ledger,
strict internal/PSRAM placement, task-stack-style reservation tokens and
close/drain lifecycle checks. Charged allocations include their aligned owner
prefix. Optional task-local scopes and universal calloc/free callbacks allow
library allocations to retain their mesh owner across actor/worker handoffs.
Install library callbacks once before any library allocation, not at mesh on/off.

The ledger bounds managed payloads, prefixes and declared reservations. It does
not automatically capture SDK/radio allocations or heap allocator bookkeeping.
Runtime integrations must account those separately before claiming a whole-mesh
memory cap. No arena is reserved; compiler scope storage adds a small fixed TLS
slot to each task's stack. The investigation's `psram-budget-design.md` documents
coverage and the remaining integration work.

Run the standalone normal-use tests with `cmake -S tests -B <build-dir>`, build
that directory, then `ctest --test-dir <build-dir> --output-on-failure`.

`wendy_net_alloc.h` adds the global runtime budget and allocation convenience
calls used by firmware protocol components. Open it before creating mesh state;
close and drain it during shutdown. Its admission ceiling is 2 MiB with PSRAM
and 1 MiB without it; physical SRAM can fail earlier on smaller devices. Host
wrappers preserve libc ownership and do not require runtime startup. Firmware
allocations never fall back to uncharged memory when the budget is closed/full.
