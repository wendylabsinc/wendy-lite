# Authenticated Cloud relay

WDY-3512 uses the versioned contract in
[service-protos PR #110](https://github.com/wendylabsinc/service-protos/pull/110).
Cloud PR #753 and CLI PR #2223 must roll out with this firmware.

The device opens a hostname-verified outer TLS 1.3 connection using its enrolled
identity and provisioned HTTPS trust roots. All outer records start with
`57 52 02 <opcode>` (WR02). Ping (1) and pong (2) have no payload. Key set (4)
provisions one or two ML-DSA-65 public keys. Upgrade (3) carries a 16-byte session
ID and SHA-256 of the exact signed grant. Keys are accepted only from the
authenticated outer connection; neither CLI nor inner TLS can provision them.

On upgrade, wolfSSL exchanges close notifications and releases the outer TLS
session while preserving the descriptor. The same TCP socket then accepts a new
TLS server session from the CLI. The CLI must authenticate the intended device.
The device requires a valid chain, explicit client-auth EKU and exactly one
same-tenant operator SPIFFE URI. Device and service identities are refused.

Before WendyCom, the CLI must send the WLG1 compact grant as its first inner TLS
application record. Firmware checks the ML-DSA-65 signature, trusted key ID,
upgrade session and grant hash, its own device identity, authenticated operator
identity, issuance time and expiry. Lifetime must be positive and at most 1800
seconds. Success sends WLA1; failure closes the socket. The operator's signing
and TLS keys may differ, but their principal URI must match.

The cloud task opens a replacement control connection after handing off the
operator stream. PostgreSQL-backed broker caps permit one active session per
device and four per user, including replacement connections. The broker closes
sessions at expiry and after 60 seconds idle. Firmware also refuses reads and
writes after the grant expires. Inner TLS establishment plus grant admission
share a 10-second deadline; outer control reads have a 30-second deadline.

Build with ESP-IDF 5.5.4 and enable `CONFIG_WENDY_CLOUD=y` as described in
[enrollment](cloud-enrollment.md). All images include PKI support. The relay uses
wolfSSL support for mixed ECDSA/ML-DSA chains.
Old WR01 firmware and unsigned relay opens are incompatible.

## Verification

```sh
cmake -S components/wendy_pki/tests -B build-pki
cmake --build build-pki
ctest --test-dir build-pki --output-on-failure
```

The shared Go-generated ML-DSA grant fixture also runs in Swift. Firmware tests
cover valid grants, every truncated length, altered signatures, expiry, key and
identity mismatches. Seven host tests pass both normally and under ASan/UBSan.
An ESP32-C6 build passes. A physical-board trial must still verify enrollment,
outer shutdown/inner handshake, key rotation, resource use and crypto latency.
