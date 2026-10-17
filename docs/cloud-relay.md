# Authenticated Cloud relay

WDY-3512 follows the
[Lite relay contract](https://github.com/wendylabsinc/service-protos/blob/main/docs/lite-relay-v1.md).
Cloud PR #753, CLI PR #2223 and PKI's Lite authority delivery support must roll out
with this firmware.

The device opens a hostname-verified outer TLS 1.3 connection using its enrolled
identity and provisioned HTTPS trust roots. All outer records start with
`57 52 03 <opcode>` (WR03). Ping (1) and pong (2) have no payload. Key set (4)
provisions one or two P-256 public keys. Upgrade (3) carries a 16-byte session
ID and SHA-256 of the exact signed grant. Keys are accepted only from the
authenticated outer connection; neither CLI nor inner TLS can provision them.

On upgrade, the TLS backend exchanges close notifications and releases the outer TLS
session while preserving the descriptor. The same TCP socket then accepts a new
TLS server session from the CLI. The CLI must authenticate the intended device.
The device requires a P-256 Lite operator leaf signed by its separately pinned
Lite Operator Authority, with exactly one same-tenant operator SPIFFE URI.
Its critical keyUsage must be `digitalSignature` only, and its EKU must be exactly
`clientAuth` plus `id-kp-wendyLiteOperator` (`1.3.6.1.4.1.65441.1.9`). Device,
service and unmarked operator certificates are refused. The CLI sends only that
Lite leaf; its primary operator chain does not establish relay operator trust.

The pin comes only from `X-Wendy-Lite-Operator-Authority` on an authenticated PKI
enrollment or renewal response: standard base64 DER for a self-signed P-256 CA
with `pathLen=0`. Initial enrollment requires it. A valid renewal header replaces
the pin after device identity verification; omission keeps the existing pin, and
malformed data cannot replace it. Existing identities without a pin renew on the
next control connection and refuse relay access until one is installed. This pin
is separate from device, HTTPS and TSA roots and cannot be set through the CLI,
BLE or configuration. See [enrollment](cloud-enrollment.md).

Before WendyCom, the CLI must send the WLG2 compact grant as its first inner TLS
application record. Firmware checks the P-256 signature, trusted key ID,
upgrade session and grant hash, its own device identity, authenticated operator
identity, and SHA-256 of the authenticated operator certificate's SubjectPublicKeyInfo
DER. The operator's signing and TLS certificates may differ, but their principal
URI and public key must match. A matching URI with a different key is refused.
Success sends WLA2; failure closes the socket.

The current Cloud WLG2 record is `309 + key_id_length` bytes (at most 437).
After the key ID it contains two 8-byte timestamps; four 16-byte identifiers
(session, grant, correlation, asset); five 32-byte hashes (device URI, operator
URI, operator SPKI, principal payload, attestation); and a 64-byte raw P-256
signature. Earlier `213 + key_id_length` records are rejected.

The signed expiry is a presentation deadline: firmware requires
`issued_at <= now < present_by` and `0 < present_by - issued_at <= 60` seconds.
Once admitted, the session deadline is `issued_at + 1800` seconds, capped by
both authenticated certificate expiries. The presentation deadline does not
terminate an established session. The upgrade hash and session bind admission
to the single-use outer connection.

The cloud task opens a replacement control connection after handing off the
operator stream. PostgreSQL-backed broker caps permit one active session per
device and four per user, including replacement connections. The broker closes
sessions at expiry and after 60 seconds idle. Firmware also refuses reads and
writes after the session deadline. Inner TLS establishment plus grant admission
share a 10-second deadline; outer control reads have a 30-second deadline.

Build with ESP-IDF 5.5.4 and enable `CONFIG_WENDY_CLOUD=y` as described in
[enrollment](cloud-enrollment.md). All images include PKI support. The relay uses
wolfSSL by default for ML-DSA device or infrastructure certificate chains.
Set `CONFIG_WENDY_PKI_WOLFSSL=n` to use ESP-IDF mbedTLS. Both profiles require
compatible device, HTTPS and TSA trust, and use the separate P-256 Lite authority
for relay operators and P-256 keys for session grant verification.
Old WR01/WR02 firmware and unsigned relay opens are incompatible.

## Verification

```sh
cmake -S components/wendy_pki/tests -B build-pki -DWENDY_PKI_WOLFSSL=ON
cmake --build build-pki
ctest --test-dir build-pki --output-on-failure
```

The shared Go-generated P-256 grant fixture also runs in Swift. Firmware tests
cover the current Cloud record, rejected legacy records, every truncated length,
maximum and oversized records, altered signatures, presentation deadlines,
session expiry, key rotation, and matching operator URIs with different keys.
They also cover authenticated authority delivery, enrollment and renewal pin
lifecycle, and rejection of certificates outside the Lite operator profile.
See [fixture provenance and regeneration](../components/wendy_pki/tests/lite-fixtures/README.md).
A physical-board trial must still verify the complete cloud relay, including
outer shutdown/inner handshake, key rotation, resource use and crypto latency.

## Default image size

WASM and its host API exports are opt-in through `boards/wasm.defaults`.
Historical measurements on ESP32-C6 with ESP-IDF 5.5.4 and Cloud enabled:

| Build | Firmware bytes |
| --- | ---: |
| Previous wolfSSL + WASM | 1,838,784 |
| Previous wolfSSL, WASM disabled | 1,638,064 |
| mbedTLS only, WASM disabled | 1,386,000 |
| mbedTLS only, WASM enabled | 1,586,688 |
| mbedTLS only, WASM and Bluetooth disabled | 1,012,544 |

In these builds, removing wolfSSL saved 252,064 bytes against the no-WASM baseline.
These are controlled local builds before the wolfSSL profile was restored,
not measurements of deployed hardware or the current default firmware, which
includes wolfSSL and ML-DSA support.
Existing sdkconfig files retain their settings, so use a fresh configuration
when adopting these defaults. Partition layouts are unchanged.

These measurements explicitly enable TLS 1.3. Earlier numbers of 1,340,432 bytes
without WASM and 1,541,552 bytes with WASM came from reused sdkconfig files with
TLS 1.3 disabled and do not describe the intended Cloud firmware. Confirm
`CONFIG_MBEDTLS_SSL_PROTO_TLS1_3=y` in the generated sdkconfig. Use a fresh
configuration when adopting changed defaults.

Append `boards/no-ble.defaults` last to omit Bluetooth while retaining USB,
Wi-Fi and Cloud. In the historical mbedTLS-only C6 builds above, disabling
Bluetooth saved 373,456 bytes and left 920,768 bytes in the factory partition.
Linker archive and symbol inspection confirmed the BLE stack was absent.
Both Bluetooth modes built; hardware behavior still needs validation.
See [Bluetooth configuration](../README.md#optional-bluetooth-support).
