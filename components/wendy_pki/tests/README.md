# PKI interoperability tests

`verify_test` verifies the committed pki-core fixtures at their authenticated
issuance time, so the tests remain useful after the certificates expire.
It covers ML-DSA and ECDSA timestamps, mixed P-256/ML-DSA identity chains, wrong
nonces/imprints, signatures, trust roots, TLS usage, identity, keys, expiry,
rollback, and truncated responses. Fixture private keys are disposable test keys.

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
