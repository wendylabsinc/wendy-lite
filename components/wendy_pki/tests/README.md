# PKI interoperability tests

The host tests build the pinned esp-pqc mbedTLS 4 and liboqs libraries with
ML-DSA-65 identity signatures and ML-DSA-65/87 CA verification. The first
configuration fetches esp-pqc and its nested submodules at the revision in
`../idf_component.yml`. To use a local checkout, set `FETCHCONTENT_SOURCE_DIR_ESP_PQC`.
Set `IDF_PATH` to ESP-IDF 6.0.3, and install Go 1.27 or newer before configuring:

```sh
cmake -S components/wendy_pki/tests -B build-pki
cmake --build build-pki
ctest --test-dir build-pki --output-on-failure
```

`dependency_patches_in_checkout` reproduces a build directory inside a Git
checkout. It requires a patch to change the copied source on both initial
configuration and reconfiguration, without changing the dependency source.
This catches Git reporting success while silently skipping the security patches.

`crypto_test` verifies PSA initialization and P-256 private-key and CSR output
compatibility. Production firmware and host tests use the same crypto helper.

`verify_test` verifies the committed pki-core fixtures at their authenticated
issuance time, so the tests remain useful after the certificates expire.
It covers P-256 ECDSA timestamps and P-256 identity chains, wrong
nonces/imprints, signatures, trust roots, TLS usage, identity, keys, expiry,
rollback, and truncated responses. Fixture private keys are disposable test keys.
The verifier runs with simulated wall clocks in 1970 and 2100 to catch accidental
dependence on the boot clock, while still rejecting certificates outside their
validity period at the authenticated verification time.

`public_time_test` verifies a captured Sigstore timestamp with its pinned P-384
root and SHA-384 certificate chain. Signed disposable fixtures cover P-384
signers, optional ESSCertIDv2 issuerSerial, mismatched issuer/serial, extra issuer
names, and unsupported curves. It also rejects wrong nonces, untrusted roots,
rollback, and signature tampering under simulated wall clocks in 1970 and 2100.
See `public-time-fixtures/README.md` for provenance and regeneration.

`renewal_test` runs the production connection flow with in-memory NVS and HTTP
stubs. It checks fallback after failed renewal, retries on the next connection,
expiry during renewal, rejection of expired or invalid stored identities, failed
initial enrollment, and connections that do not yet need renewal. It also checks
explicit USB trust selection and rejects partial or unauthorized bundles.
The BLE stream accept path uses the stored identity without issuance or network
time requests. Tests reject missing, expired, invalid and reset identities before
calling the TLS backend.
`ble_tls_lifecycle_test` compiles the production BLE session owner with a stubbed
PKI accept boundary. It injects reset and enrollment changes before, during and
after acceptance, including configuration-cache invalidation between sessions.
It checks that the boot authentication policy prevents anonymous fallback,
changed identities block I/O, teardown closes the accepted connection once, and
the next session starts without a stale connection. These lifecycle assertions
remain enabled in Release builds.
`conf_test` uses the real nanopb decoder and configuration writer with an in-memory
flash partition to check persistence, snapshot ownership across writes, and size
limits. The verifier rejects malformed bundles and leaf certificates as roots.

To regenerate with a local pki-core checkout, build the native verifier first,
then run:

```sh
python3 components/wendy_pki/tests/regenerate.py \
  /path/to/pki-core /path/to/build-pki/verify_test
```

The generator runs inside a temporary directory under pki-core because it imports
its internal packages. Its in-memory signing adapter replaces key storage only;
the timestamp issuance code and certificate encoder are the actual PKI code.
`request.der` is produced by the firmware encoder and consumed by pki-core for
the successful timestamp fixture. Never use these roots in a deployed image.

`tls_test_driver.go` creates disposable P-256 chains and connects Go TLS to the
production firmware TLS adapter. Inbound cases cover TLS 1.3, wrong tenant/role/EKU,
expired/untrusted/missing client certificates, TLS 1.2 refusal, truncated shutdown,
unexpected application data during handoff, valid intermediate chains, and
rejection of non-CA intermediates, missing keyCertSign usage, path-length
violations, expired intermediates, and SHA-1 leaf signatures. Relay cases send the
WLG3 layout through authenticated TLS, reject a validly signed WLG2 record, reject another key for the
same operator URI, and enforce independent presentation and session deadlines.
They cover both certificate expiry caps, legacy/truncated/expired grants and
presentation windows over 60 seconds. The valid handoff case exchanges
close_notify and then transfers raw bytes on the preserved TCP socket.
LAN cases also accept same-tenant device clients and assert the verified peer
role. They reject wrong tenants, malformed or ambiguous identities, missing
clientAuth, CA leaves, invalid dates, untrusted issuers, and signature tampering.
The operator-only accept path rejects device clients, including relay clients.
Callback stream cases exercise the PKI stream API used by BLE through fragmented reads and
writes with forced retry responses. A valid operator exchanges application data;
wrong tenants, device roles, missing or invalid certificates, TLS 1.2 and failed
waits are rejected. The tests check buffered plaintext readiness, revocation
during reset, refusal to detach a stream as a socket, and transport ownership
after both accepted and rejected handshakes.
The same cases run with ML-DSA-65 roots and P-256 device/operator keys.
A separate case authenticates a P-256 device and an ML-DSA-65 operator through
the complete enrollment chain: an ML-DSA-87 root and customer CA followed by
ML-DSA-65 tenant and identity CAs. The operator chain crosses the 16 KiB TLS
record boundary. Tampered signatures from either ML-DSA-87 CA are rejected.
The server must advertise ML-DSA-65 CertificateVerify and must not advertise
ML-DSA-44 or ML-DSA-87. Operator leaves using either unsupported parameter set
fail authentication.

`operator_auth_test_driver.go` creates temporary signed certificates for the
legacy LAN/BLE authentication helper. Unit checks cover device tenant extraction,
strict operator identities, explicit clientAuth usage, CA rejection, and
preservation of every pre-existing mbedTLS verification flag. Real TLS 1.2 and
TLS 1.3 handshakes exercise the LAN/BLE verification callback and the identity
check after a required client-certificate handshake. Valid same-organization operators
and intermediate chains can exchange application data. Missing, untrusted,
expired, future, and tampered certificates cannot. Other rejection cases cover
wrong organizations, roles, authorities, missing or duplicate URI identities,
invalid subject segments, URI query/fragment/percent/NUL suffixes, missing or
incorrect EKUs, and CA leaves. Safe operator names and nested subjects remain
valid, matching the pki-core issuer grammar. The same signed fixtures also
exercise the PKI operator verifier.
The LAN policy additionally accepts same-tenant device certificates and records
their restricted role. Tests exercise both policies against the same fixtures,
reject role changes during later verification, and check the TLS adapters' peer
classifiers.
These tests use the same mbedTLS backend as PKI, LAN, and BLE.
The host adapter also checks anonymous TLS 1.2 and TLS 1.3 access in its
unprovisioned configuration, with a self-signed server certificate containing no
tenant identity. Provisioned configurations continue to reject missing client
certificates. These cases check the TLS policy, not the firmware provisioning
state machine.

`wendycom_link_permissions` sends serialized protocol frames through the
production link, agent, and command code. It permits SensorLink manifest,
subscribe, and unsubscribe requests from device links while rejecting every
management command and console input before calling delegates. It covers extra
channels, stale client IDs, channel and link reuse, invalid permissions, reset
revocation, and preserved operator/local access.

`wendycom_tx_stall_*` compiles the production transport and SensorLink sender
with a clock and a transport that can stop accepting bytes. It checks that
`select()` wakes at the 15-second transmit deadline without a readiness event,
including partial writes, no initial progress, and TLS-style WANT_READ retries.
Timeout teardown returns the borrowed frame once, notifies disconnect once,
and permits a new stream after the link slot is reused. Appending queued traffic
does not extend the deadline. Successful writes do extend it, so a transfer
lasting longer than the timeout and an idle connection remain connected.

An outbound case exercises `pki_tls_connect` against Go's verifying TLS server.
The device chain includes three intermediates and exceeds 16 KiB with ML-DSA-65
issuers. A host-only send adapter limits writes to 512 bytes and alternates them
with `EAGAIN`; the test requires both partial writes and retries during the
handshake. It also verifies a P-384 server CA and exchanges application data in
both directions after the server authenticates the complete device chain.
The same chain is sent by the firmware's stream-server path, whose callbacks
limit writes to 61 bytes and reads to 73 bytes and inject both retry directions.
These cases exercise the tracked outgoing Certificate fragmentation patch in
both TLS roles, including transcript integrity and record counters across retries.
A negative case ends the connection after the first complete encrypted
Certificate record; the Go peer must reject the incomplete handshake message.

A second Mbed TLS client negotiates 512-byte TLS records and sends a valid
ML-DSA-65-signed P-256 operator chain to the production stream server. This
exercises incoming handshake reassembly across records, separately from the
transport callbacks' short reads. Incoming Certificate handshakes remain bounded
to 32 KiB while TLS records remain bounded to 16 KiB. A valid chain exceeding the
handshake limit is rejected.
Firmware disables IDF dynamic buffers because their allocation can follow the
current record's size while the bundled library bounds reassembly against the
configured input size. The fixed-buffer host tests cover the chosen allocation
model; they do not validate the disabled dynamic-buffer wrappers on hardware.

The outbound server uses Go's default session-ticket settings. Firmware performs
a fresh certificate handshake. The outbound regression checks application data
after the handshake and partial client-flight writes. Host socket tests do not
establish ESP32 handshake latency or reproduce a sustained lwIP send-window stall.

`mldsa_test` covers signed timestamps and mixed ML-DSA/P-256 identity chains at
authenticated time under incorrect device clocks, including certificate date,
CA, key usage, path length, identity, and signature failures. See
`mldsa-fixtures/README.md` for provenance and regeneration commands.

`mesh_mldsa_router_test` feeds Linux router `bundle` and `manifest` control
messages, produced by the WendyOS router's own manifest signer, through the
leaf's JSON parser, chain verifier and directory. An ML-DSA-65 router leaf under
ML-DSA-87/65 CAs and its pure ML-DSA-65 manifest are accepted, as is a P-256
router through the same signer. Signatures over the SHA-256 digest, with a
non-empty context, without the principal, or by another key are rejected, along
with damaged signatures, bodies and agent metadata, cross-algorithm signatures,
wrong tenants, expiry and an unrelated root. See
`../../wendy_mesh/tests/mldsa-router-fixtures/README.md`.

The enrollment capability tests compile the production WendyCom capability
helper with Cloud, Wi-Fi, and PKI individually disabled. They ensure unsupported
profiles report an explicit false enrollment capability while retaining local
identity recovery wherever PKI is available. They also check that ML-DSA support
is advertised only when both PKI and ML-DSA-65 verification are enabled and that false values
survive protobuf encoding.

`pki_time_nonce_normal` covers seven ordinary 256-bit nonce shapes: low/high
leading bit, all-ones, leading zeroes before low/high bits, one, and zero.
It compares firmware request bytes with independently marshalled Go ASN.1 and
verifies a correctly signed disposable P-384 timestamp for each value. The
imprint always hashes all 32 original bytes; only the INTEGER representation
strips zeroes or adds a sign octet. Run this positive interoperability check with
`ctest --test-dir <build> -R '^pki_time_nonce_normal$' --output-on-failure`.

The C6 sustained BLE trial on 2026-10-28 exposed the former fixed-width encoder:
control-channel renewals used arbitrary random bytes, unlike bootstrap callers
which masked the high bit. A high-bit nonce was encoded as negative and rejected
by the timestamp response verifier. Renewal retries sometimes succeeded by
chance. Canonical positive encoding fixes the source rather than constraining
the random input, and matching canonical INTEGER values also handles leading
zeroes in otherwise valid random nonces.
