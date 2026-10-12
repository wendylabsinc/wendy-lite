# PKI interoperability tests

The default host test build uses mbedTLS. Run the same tests with the optional
wolfSSL backend by initializing `components/wendy_wolfssl/wolfssl` and configuring
a separate build directory with `-DWENDY_PKI_WOLFSSL=ON`. Go 1.27 is required for
the ML-DSA certificate fixtures.

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
production firmware TLS adapter. Twenty-four cases cover TLS 1.3, wrong tenant/role/EKU,
expired/untrusted/missing client certificates, TLS 1.2 refusal, truncated shutdown,
unexpected application data during handoff, valid intermediate chains, and
rejection of non-CA intermediates, missing keyCertSign usage, path-length
violations, expired intermediates, and SHA-1 leaf signatures. Relay cases send the
current Cloud WLG2 layout through authenticated TLS, reject another key for the
same operator URI, and enforce independent presentation and session deadlines.
They cover both certificate expiry caps, legacy/truncated/expired grants and
presentation windows over 60 seconds. The valid handoff case exchanges
close_notify and then transfers raw bytes on the preserved TCP socket.
The wolfSSL profile runs the same cases with ML-DSA-44, ML-DSA-65, and ML-DSA-87
roots and P-256 device/operator keys. Set `IDF_PATH` to ESP-IDF 5.5.4 and install
Go 1.27 or newer before configuring host tests.

`mldsa_test` covers signed timestamps and mixed ML-DSA/P-256 identity chains at
authenticated time under incorrect device clocks, including certificate date,
CA, key usage, path length, identity, and signature failures. See
`mldsa-fixtures/README.md` for provenance and regeneration commands.

The enrollment capability tests compile the production WendyCom capability
helper with Cloud, Wi-Fi, and PKI individually disabled. They ensure unsupported
profiles report an explicit false enrollment capability while retaining local
identity recovery wherever PKI is available. They also check that ML-DSA support
is advertised only when both PKI and wolfSSL are enabled and that false values
survive protobuf encoding.
