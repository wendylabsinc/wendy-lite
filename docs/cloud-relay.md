# Authenticated Cloud relay

WDY-3512 uses the versioned contract in
[service-protos PR #110](https://github.com/wendylabsinc/service-protos/pull/110).
Cloud PR #753 and CLI PR #2223 must roll out with this firmware.

The device opens a hostname-verified outer TLS 1.3 connection using its enrolled
identity and provisioned HTTPS trust roots. All outer records start with
`57 52 03 <opcode>` (WR03). Ping (1) and pong (2) have no payload. Key set (4)
provisions one or two P-256 public keys. Upgrade (3) carries a 16-byte session
ID and SHA-256 of the exact signed grant. Keys are accepted only from the
authenticated outer connection; neither CLI nor inner TLS can provision them.

On upgrade, mbedTLS exchanges close notifications and releases the outer TLS
session while preserving the descriptor. The same TCP socket then accepts a new
TLS server session from the CLI. The CLI must authenticate the intended device.
The device requires a valid chain, explicit client-auth EKU and exactly one
same-tenant operator SPIFFE URI. Device and service identities are refused.

Before WendyCom, the CLI must send the WLG2 compact grant as its first inner TLS
application record. Firmware checks the P-256 signature, trusted key ID,
upgrade session and grant hash, its own device identity, authenticated operator
identity, issuance time and expiry. Lifetime must be positive and at most 1800
seconds. Success sends WLA2; failure closes the socket. The operator's signing
and TLS keys may differ, but their principal URI must match.

The cloud task opens a replacement control connection after handing off the
operator stream. PostgreSQL-backed broker caps permit one active session per
device and four per user, including replacement connections. The broker closes
sessions at expiry and after 60 seconds idle. Firmware also refuses reads and
writes after the grant expires. Inner TLS establishment plus grant admission
share a 10-second deadline; outer control reads have a 30-second deadline.

Build with ESP-IDF 5.5.4 and enable `CONFIG_WENDY_CLOUD=y` as described in
[enrollment](cloud-enrollment.md). All images include PKI support. The relay uses
ESP-IDF mbedTLS with compatible complete certificate chains.
Old WR01/WR02 firmware and unsigned relay opens are incompatible.

## Verification

```sh
cmake -S components/wendy_pki/tests -B build-pki
cmake --build build-pki
ctest --test-dir build-pki --output-on-failure
```

The shared Go-generated P-256 grant fixture also runs in Swift. Firmware tests
cover valid grants, every truncated length, altered signatures, expiry, key and
identity mismatches. Seven host tests pass both normally and under ASan/UBSan.
An ESP32-C6 build passes. A physical-board trial must still verify enrollment,
outer shutdown/inner handshake, key rotation, resource use and crypto latency.

## Default image size

WASM and its host API exports are opt-in through `boards/wasm.defaults`.
On ESP32-C6 with ESP-IDF 5.5.4 and Cloud enabled:

| Build | Firmware bytes |
| --- | ---: |
| Previous wolfSSL + WASM | 1,838,784 |
| Previous wolfSSL, WASM disabled | 1,638,064 |
| mbedTLS only, WASM disabled | 1,386,000 |
| mbedTLS only, WASM enabled | 1,586,688 |
| mbedTLS only, WASM and Bluetooth disabled | 1,012,544 |

Removing wolfSSL saves 252,064 bytes against the no-WASM baseline. Combined with
making WASM opt-in, the default saves 452,784 bytes, about 24.6%, and leaves
547,312 bytes in the unchanged 1,933,312-byte factory partition. Both current
configurations build; the default map has no wolfSSL, ML-DSA or WASM runtime.
These are controlled local builds, not measurements of deployed hardware.
Existing sdkconfig files retain their settings, so use a fresh configuration
when adopting these defaults. Partition layouts are unchanged.

These measurements explicitly enable TLS 1.3. Earlier numbers of 1,340,432 bytes
without WASM and 1,541,552 bytes with WASM came from reused sdkconfig files with
TLS 1.3 disabled and do not describe the intended Cloud firmware. Confirm
`CONFIG_MBEDTLS_SSL_PROTO_TLS1_3=y` in the generated sdkconfig. Use a fresh
configuration when adopting changed defaults.

Append `boards/no-ble.defaults` last to omit Bluetooth while retaining USB,
Wi-Fi and Cloud. On this same C6 configuration it saves another 373,456 bytes
compared with the Bluetooth-enabled default and leaves 920,768 bytes in the
factory partition. Linker archive and symbol inspection confirms the BLE stack
is absent. Both Bluetooth modes build; hardware behavior still needs validation.
See [Bluetooth configuration](../README.md#optional-bluetooth-support).
