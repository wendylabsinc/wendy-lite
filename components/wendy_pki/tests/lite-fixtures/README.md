# Disposable Lite relay grant fixtures

`grant.bin` and `vector.json` contain the current shared service-protos Lite
relay conformance vector, also used by the Swift Cloud `LiteSessionGrantTests`.
The record follows `LiteSessionGrant.sign`: `309 + key_id_length` bytes, including
operator SPKI, principal payload, and attestation hashes. Its presentation window
is Unix seconds 1700000000 through 1700000060 (exclusive); its session ceiling
is 1700001800. `cloud-key.bin` is the uncompressed P-256 verification key.

The vector comes from service-protos commit
`d9bc039f16f0368237b4dba0d964b44a16deca19`, `conformance/lite-relay`.
`legacy-grant.bin` is
this firmware repository's former `213 + key_id_length` vector and must fail.

All keys are public, disposable test material, never deployment credentials.
`operator.der` and `operator-wrong-key.der` contain the same URI with distinct
keys. `operator-spki.der` is the canonical key bound by the valid grant.
The remaining signed records exercise invalid presentation windows, integer
limits, and the maximum accepted key-ID length.

Regenerate from `components/wendy_pki/tests` with the Go standard library:

```sh
go run lite_grant_fixture.go lite-fixtures
```

The generator preserves the canonical shared grant's existing signature when
its unsigned body is unchanged. Other randomized signatures and the alternate
operator key can change. Tests validate semantics rather than random bytes.
The legacy vector is retained as an explicit compatibility rejection fixture.
