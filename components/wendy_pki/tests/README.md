# PKI interoperability tests

The host tests build the pinned esp-pqc mbedTLS 4 and liboqs libraries with
ML-DSA-65 identity signatures and ML-DSA-65/87 CA verification. Initialize nested dependencies with
`git submodule update --init --recursive components/esp-pqc`, set `IDF_PATH` to
ESP-IDF 6.0.3, and install Go 1.27 or newer before configuring:

```sh
cmake -S components/wendy_pki/tests -B build-pki
cmake --build build-pki -j4
GOTOOLCHAIN=go1.27.3 GOMAXPROCS=2 GOFLAGS=-p=1 ctest --test-dir build-pki --output-on-failure -j2
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
`relay_control_test` runs the production broker control loop with deterministic
TLS reads, writes and socket waits. Healthy heartbeats reach the four-minute
refresh deadline and return the planned-renewal result. Early heartbeat timeout,
EOF, invalid or partial headers, stalled writes, reset and socket errors retain
the failure result even at that deadline. Successful handoff preserves the
detached fd and its trust data for the caller.
`relay_stream_wait_test` additionally checks the scoped DER/TLS read wrapper.
Stream errors remain failures even when their callback reaches the deadline;
successful retry hints preserve read versus write direction, partial frames and
reset, including a readiness hint immediately before the loop crosses its deadline.
A spurious hint cannot hide a subsequent EOF. The initiating TLS allocation
scope is restored before the caller waits on its transport.
