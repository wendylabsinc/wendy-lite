# Runtime certificate representation

Enrollment trust snapshots contain concatenated complete DER certificates, with
at most eight roots per trust role. PEM provisioning is decoded directly from
mapped flash at the configuration import boundary. No full PEM snapshot is
allocated. Build-time pins are also imported into DER before firmware embedding.
Certificate parsing and TLS call the explicit Mbed TLS DER APIs; DER is never
converted back to PEM. A borrowed bundle remains alive until its parsed anchors
are released. Root policy checks borrow one certificate at a time.

Provisioned source bytes still identify the persistent route/service journal
scope. This preserves the existing generation history when a previously enrolled
board starts using DER snapshots. Live verification and TLS source memoization
hash the exact DER bytes instead.

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
records without moving the adopted input buffer; normal mTLS/reconnect tests
exercise cleanup under ASan/UBSan. Hardware pressure qualification is separate.

## Allocation ownership

Firmware installs one Mbed TLS allocator pair in the system-init stage before
ESP-IDF's PSA initialization. Both baseline and mesh allocations carry a common
ownership prefix; task-local mesh charging is enabled at `app_main`, after
compiler TLS becomes available. CPU and I/O jobs retain their initiating scope.
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
retagging it or allocating a second26 KiB block. On mesh shutdown caching stops;
the original mesh ledger remains draining until that finite TLS loan returns,
then its matching destructor frees it. Other management allocations remain
baseline-owned.

The pinned liboqs ordinary allocator hooks and native ML-DSA heap-temporary
extension use the initiating scope too. Polynomial/vector temporaries receive
32-byte alignment with all padding charged in the same owned allocation. The
firmware still needs separate accounting for raw transient trust/HTTP inputs,
heap bookkeeping, and SDK/radio memory before claiming a whole-system heap cap.

## Native mesh issuer ALPN

Native streamed-DER carrier/app TLS supports WendyOS's auxiliary
`wendy-net-issuers/<digest>` offer. The real service ALPN is unchanged; servers
never select the auxiliary identifier. Certificates remain binary DER.

Eligibility is computed per connection after complete local identity/path/key
verification and exact source pinning. Every presented issuer after the leaf
must match an explicitly enrolled anchor by DER size and SHA256. A valid path
to a root alone is insufficient. The digest matches WendyOS: sort the issuer
DER hashes, hash their concatenation, encode the first16bytes as the existing
22-character base64url ALPN identifier. This identifier is not certificate
material or a base64 certificate transport.

A server sends only its leaf when the client offered the identical eligible
issuer digest. A client sends only its leaf after the server's chain,
CertificateVerify and Finished have passed, the server actually sent one wire
certificate, and its issuer DN/AKI match this device's leaf. The wire count is
captured before later input reuse; parsed-chain compaction cannot manufacture
a one-certificate signal. During that decision Mbed TLS's public peer getter
still exposes only an established session, so the code reads the already
verified pending session under the existing exclusive handshake-context loan.
Normal full-chain fallback remains for absent hints, different issuer sets,
root-only enrollment trust, nonstreaming identities or optional allocation
pressure. Chain/principal/tenant/time validation is unchanged.

There is no global issuer cache or off-state arena. On current RV32 builds the
connection remains3288bytes (the pointer fits prior padding); eligible native
sessions add96bytes of optional state plus a32-byte ledger prefix. Ineligible
sessions add no allocation. The state follows its initiating connection owner,
uses PSRAM on the PSRAM profile and is released after TLS/config destruction.
Existing16KiB trust-input bounds remain unchanged.

The optional host test `pki_issuer_wos_interop_normal` uses the actual WendyOS
issuer helpers through temporary Go overlays, without editing that checkout.
Configure `WENDYOS_GO_ROOT` to its `go` module and run that selected test. It
covers both roles with matched pinned issuers, old/full-chain peers, different
issuers and root-only trust. Generated fixture padding keeps its legitimate CA
bundle inside the existing limit. Final firmware flash cost and ESP hardware
savings still require a built image/current enrolled trust measurement.
