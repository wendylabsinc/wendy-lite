# Public timestamp fixtures

`sigstore.der` is an RFC 3161 response captured from
`https://timestamp.sigstore.dev/api/v1/timestamp` on 2026-10-12 at 07:49:29 UTC.
The request uses SHA-256 of the 32-byte nonce `01 02 ... 20`, also encoded as the
RFC 3161 nonce, and requests the signer certificates. The firmware test encoder
produces this request with `verify_test --request request.der`.

The CMS signature uses ECDSA with SHA-256 and a P-384 signer. The certificates
use ECDSA with SHA-384. Its ESSCertIDv2 includes the optional issuerSerial field.
`sigstore-root.pem` is the Sigstore TSA root from the
[official root-signing trust metadata](https://github.com/sigstore/root-signing/blob/main/targets/trusted_root.json),
selected from the timestamp authority with URI
`https://timestamp.sigstore.dev/api/v1/timestamp` and checked byte for byte against
the root returned by `https://timestamp.sigstore.dev/api/v1/timestamp/certchain`.
Its SHA-256 fingerprint is
`2ACA8FEA5D3CE48B01CC77076293C280E6C23FFE44034757EE7833CA9F45D633`.
The tests verify certificate validity at the authenticated issuance time so
the fixture remains useful after the certificate expires.

The remaining files are disposable P-384 test certificates and correctly signed
timestamp responses. Their ESSCertIDv2 values distinguish a missing optional
issuerSerial, a matching issuerSerial, a wrong issuer, a wrong serial, and extra
issuer names. `unsupported-curve.der` has a P-521 signer and must be rejected.
These fixtures use the same nonce as the live capture. Regenerate them from the
repository root with:

```sh
go run components/wendy_pki/tests/public_time_fixtures.go \
  components/wendy_pki/tests/public-time-fixtures
```

The generator does not replace the captured Sigstore response or its trust root.
Never use `test-root.pem` as a deployed trust anchor.
