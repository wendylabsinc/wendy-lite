# Runtime certificate representation

Enrollment trust snapshots contain concatenated complete DER certificates, with
at most eight roots per trust role. PEM provisioning is decoded directly from
mapped flash at the configuration import boundary. No full PEM snapshot is
allocated. Build-time pins are also imported into DER before firmware embedding.
Certificate parsing and TLS call the explicit Mbed TLS DER APIs; DER is never
converted back to PEM. A borrowed bundle remains alive until its parsed anchors
are released. Root policy checks borrow one certificate at a time.

Provisioned-source hashes identify configuration-derived router state across
DER import. Live verification and TLS source memoization hash the exact DER
bytes instead. Learned peer state stays in RAM; no persistent peer route or
service journal is required.

Existing configuration partitions can still contain PEM as their provisioning
source; no flash configuration migration is performed by a firmware boot. Older
NVS certificate/authority records are imported into DER when loaded. New usable
issuance certificates and Lite-authority pins are stored as DER. Native device
identity caches retain indexed DER and bounded range readers. Certificate
arguments to TLS/HTTP carry explicit byte lengths, including broker and renewal
connections; no string length or PEM conversion is used for binary certificates.

Cloud CSR/issuance JSON and the retained, not-yet-admitted issuance response are
separate API/import boundaries. That retained response may still contain the
Cloud's PEM/header encoding, so recovery does not spend a consumed credential a
second time. It is decoded before verification/admission; TLS uses the resulting
DER material. Cloud API changes are outside this mesh wire replacement.

Native warm TLS setup transfers its already allocated input buffer directly
to Mbed TLS after the exact local key/certificate/trust path has passed the
existing memoized checks. The buffer is not freed and allocated again between
identity setup and handshake. Cold local verification can still borrow that
space and use the ordinary reservation/fallback path. The library consumes
ownership explicitly, and connection teardown releases it. Peer verification,
record/reassembly bounds and post-authentication compaction remain in force.
The positive reassembly fixture checks a 25 KiB fragmented message plus following
records without moving the adopted input buffer; normal mTLS/close tests
exercise cleanup under ASan/UBSan. Hardware pressure qualification is separate.

## Allocation ownership

Firmware installs one Mbed TLS allocator pair in the system-init stage before
ESP-IDF's PSA initialization. Both baseline and mesh allocations carry a common
ownership prefix; task-local mesh charging is enabled at `app_main`, after
compiler TLS becomes available. TLS contexts retain their initiating scope
through setup, record I/O and teardown. The mesh runtime submits heavy work to
its serialized crypto worker.
Callbacks stay installed throughout mesh enable/disable cycles. Uncharged
PKI/TLS baseline allocations use strict PSRAM when an external heap is registered,
preserving the C5 profile; before PSRAM registration or on SRAM-only boards they
use the ordinary default heap. Charged scopes retain their own strict placement
and never bypass a closed ledger.

Private DER-cache reads return PKI-owned buffers. Their matching consumers use
`pki_owned_free`, or transfer the same buffer directly to Mbed TLS through
`own_buffer`, without an intermediate DER copy. Enrollment configuration storage,
HTTP response outputs and trust-loader outputs retain their existing raw libc
ownership. A raw trust buffer retained by a mesh TLS connection is explicitly
reserved until its matching destructor releases it.

Certificate workspace borrowing matches the cache's original owner/placement.
Baseline management TLS may borrow the idle mesh-owned input reserve without
retagging it or allocating a second 26 KiB block. On mesh shutdown caching stops;
the original mesh ledger remains draining until that finite TLS loan returns,
then its matching destructor frees it, even if another service epoch has already
started. A foreign scope cannot refill the owner's cache. Other management allocations remain
baseline-owned.

The pinned liboqs ordinary allocator hooks and native ML-DSA heap-temporary
extension use the initiating scope too. Polynomial/vector temporaries receive
32-byte alignment with all padding charged in the same owned allocation. The
firmware still needs separate accounting for raw transient trust/HTTP inputs,
heap bookkeeping, and SDK/radio memory before claiming a whole-system heap cap.

## Native peer activation

Native peers use binary DER certificates and v4 binary manifests. The retired
leaf JSON/base64 protocol is not compiled. Issuer omission is negotiated with
binary ALPN fingerprints matching WendyOS; a locally held issuer is not assumed
to be present remotely without that negotiation. The selected root-first prefix
acknowledges which client intermediates the server holds.

The mesh actor borrows each heavyweight context exclusively to the serialized
crypto worker. Stored own DER certificates are read directly into TLS; there
is no DER-to-PEM conversion. Learned peer material stays in bounded RAM caches.
The optional own ML-DSA private-key backend remains off by default; supported
fixtures use P-256 own keys with P-256/ML-DSA issuer chains.
