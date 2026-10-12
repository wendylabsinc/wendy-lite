# Disposable ML-DSA verification fixtures

These fixtures are generated locally with Go's standard `crypto/mldsa` and
`crypto/x509` packages. They are test data, not Wendy production certificates or
trust roots. The checked-in EC private keys are disposable test keys; never use
these keys or CA certificates in a deployed device.

Regenerate from `components/wendy_pki/tests` with Go 1.27 or newer:

```sh
go run mldsa_fixtures.go mldsa-fixtures
```

The generator uses fresh random keys. Regeneration changes the certificate and
signature bytes while retaining the cases and authenticated time:
2026-10-12 08:00:00 UTC. No network service or private production key is needed.

For each of ML-DSA-44, ML-DSA-65, and ML-DSA-87, the fixtures contain an ML-DSA
root, a P-256 intermediate, P-256 device identities, and ML-DSA timestamp signers.
The RFC 3161 responses carry SHA-256 message imprints, nonce bindings, and
ESSCertIDv2 issuer/serial bindings. This exercises both classical and ML-DSA
certificate signatures in one chain.

`mldsa_test` runs under simulated wall clocks in 1970 and 2100. It accepts valid
chains at their authenticated time and rejects expired or future roots and
intermediates, non-CA intermediates, missing keyCertSign usage, path-length
violations, expired leaves, wrong or noncritical timestamp EKUs, invalid device
EKUs and URIs, duplicate URIs, mismatched private keys, nonce mismatches,
rollback, damaged signatures, and truncated responses. Peer hashes are checked
against SHA-256 of the sole expected URI, including rejection of duplicate URIs.

Build host tests with `-DWENDY_PKI_WOLFSSL=ON` to enable these cases. The separate
Go TLS interoperability driver generates its own temporary ML-DSA operator and
device chains for all three parameter sets.
