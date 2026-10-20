# Disposable Lite relay grant fixtures

`grant.bin`, `cloud-key.bin` and `vector.json` are byte-for-byte the shared
service-protos WLG3 Lite relay conformance vector (`conformance/lite-relay` at
f74e61ec, PR #138,
WDY-3919); `lite_grant_test` checks the grant's SHA-256 against it. The record
is `293 + key_id_length` bytes: no asset UUID, and the device is bound only by
the SHA-256 of its SPIFFE URI `.../device/00000000-0000-4000-8000-000000000004`,
whose UUID is the device's one id. Its presentation window is Unix seconds
1700000000 through 1700000060 (exclusive); its session ceiling is 1700001800.
`cloud-key.bin` is the uncompressed P-256 verification key.

`wlg2-grant.bin` is the retired WLG2 layout (`309 + key_id_length`, with an
asset UUID), validly signed for the same device, and must fail: firmware accepts
WLG3 only. `legacy-grant.bin` is this firmware repository's former
`213 + key_id_length` vector and must fail.

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
