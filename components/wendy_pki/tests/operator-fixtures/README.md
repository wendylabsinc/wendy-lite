These are public, self-signed ECDSA test certificates generated with OpenSSL.
Private keys were discarded. They test only the post-TLS operator identity
check; they are not trust anchors or enrollment credentials.

The cases cover a valid operator URI, a device URI, duplicate URI SANs,
serverAuth without clientAuth, and a CA certificate. The native test also
checks a different tenant and truncated DER. Certificate time and chain
verification are performed separately by the TLS handshake.


# Positive Go-produced operator artifacts

These are public certificate/proof fixtures, never lab/operator credentials. No private key is exported or needed. The producer is WendyOS `go/internal/agent/localmesh/operator_fixture_export_test.go`, `TestOperatorPositiveCOracle`; set `WENDY_OPERATOR_FIXTURE_DIR` to a separate output directory when deliberately regenerating. Go signs the exact production artifact/body and validates it with the production directory before writing public files. Normal tests do not write artifacts.

Both suites use named primary roots and operator leaf/proof keys: all P-256 in the P256 suite, and pure ML-DSA-65 throughout the MLDSA65 suite. The opaque principal is `operator/auth0%7Calice`. These fixtures establish both proof algorithms and the all-ML-DSA-65 primary path. Certificate and signed lease dates are fixed by each `metadata.json`. The C test sets its test clock from `facts.bin`, so future wall-clock expiry does not invalidate the fixture.

`first.cbor`, `renewed.cbor`, `withdrawn.cbor`, `other-instance.cbor`, and `optional.cbor` are complete binary `{proof,certificates}` artifacts. The optional artifact contains a normal unknown nested body field under the original signature. `0.der`/`1.der` are the leaf-first primary presentation; `root.der` is locally selected fixture trust. Hashes and signatures stay native bytes, with no base64 or PEM conversion. `facts.bin` contains BE64 now_ms, BE64 path expiry in seconds,16-byte address, BE64 chain count. `sha256.json` records exact file sizes and hashes. The explicit Go `TestOperatorFrozenCControlOracle` also emits `go-artifact.hash` and binary `go-have.cbor`/`go-request.cbor`/`go-chunk.cbor` from these frozen signed bytes, for independent class3 hash/control interoperability.

Run `cmake --build <pki-host-build> --target operator_success_test`, then `ctest --test-dir <pki-host-build> -R '^operator_success$' --output-on-failure`. The ordinary positive test covers independent primary-chain and proof verification, real operator address derivation, exact unknown-field signature preservation, idempotent fixed live-owner storage, bounded second-instance admission, renewal, withdrawal, expiry and full OFF cleanup. It does not explore adversarial inputs.
