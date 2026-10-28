# Nearby BLE setup

`CONFIG_WENDY_BLE_SETUP` enables first enrollment over BLE on builds with PKI,
Cloud, and Wi-Fi. It defaults to enabled on those builds. An unenrolled board
advertises service `7565e9eb-4c20-4b67-9272-d708b397b632` and accepts an LE
connection-oriented channel on PSM **131**. Its scan response contains the
hardware ID and device name. GATT info reads report PSM 131.

PSM 128 is management, PSM 129 is mesh, and PSM 130 is the Wendy Net timestamp
transport. Earlier development setup listeners used 129 or 130. Update
the phone and firmware together; setup clients now use 131. Setup uses a fresh
static random BLE address for each boot, distinct from the public address that
mesh clients may have cached. It keeps that address across scan and connection
retries during the same boot.

When a setup session ends, including a handshake timeout, the firmware closes
the underlying GAP connection so advertising resumes. Teardown runs on the
NimBLE host queue and excludes new L2CAP sessions until cleanup completes.
An already disconnected peer's handle is invalidated before teardown so a
reused handle cannot cause an unrelated connection to be terminated.

The macOS hardware regression uses an unenrolled board without writing its
configuration. It rejects a mesh PSM connection, leaves setup idle, then checks
that advertising resumes while the test client still owns its connection object:

```sh
cd go/console
WENDY_SETUP_LIVE_NAME=esp-setup-test go test -run TestLiveSetupRecovery -v -count=1
```

Enrolled boards retain the existing Lite identity advertisement and WendyCom
management channel, protected by same-tenant operator mTLS. Setup never marks a
BLE link as a local USB link and never passes unauthenticated commands into the
WendyCom protocol. It only schedules its restricted handlers on the WendyCom task
so USB reset, challenge, and configuration writes cannot race those handlers.

Setup does not advertise if enrollment is configured, a certificate remains
without its configuration, identity storage cannot be read, or reset is pending.
Every command checks enrollment again. A first-enrollment-only configuration write
also checks under the configuration lock. Pending or failed enrollment writes
cannot reopen setup. Reset and replacement of an enrolled identity require USB.

## Trust

The setup handshake protects credentials against passive BLE listeners. It does
not authenticate the phone or the board against an active nearby attacker.
Physical proximity grants first-setup trust, like headless BLE Just Works.
A phone must obtain Cloud authority and CA roots through its authenticated Cloud
session and verified HTTPS endpoints. It must not derive trusted endpoints from
the BLE advertisement or status response.

Set `CONFIG_WENDY_BLE_SETUP=n` and `CONFIG_WENDY_BLE_REQUIRE_MTLS=y` for devices
whose enrollment must require USB. `REQUIRE_MTLS` alone protects management and
allows this separate setup service when `SETUP` is enabled.

## Wire format

Every frame is a two-byte big-endian length followed by protobuf data. The
length excludes the two-byte prefix. A frame contains exactly one message field.
Duplicate or concatenated outer fields are rejected. The wire numbers match the
WendyOS nearby setup protocol. The bounded nanopb definitions for Lite are in
[`wendy_ble_setup.proto`](../components/wendy_ble/proto/wendy_ble_setup.proto).

1. Send command field **20**, a `Hello` with a 32-byte X25519 public key in field 1.
2. Receive response field **21**, a `Hello` with the board's ephemeral public key.
3. Compute X25519 shared secret. Use HKDF-SHA256 with salt
   `client_public_key || server_public_key`, info `wendy-ble-setup-v1`, and 64 output
   bytes. Bytes 0..31 are the client write key; bytes 32..63 are the server write key.
4. Subsequent commands use outer field **21** containing `Sealed.data` in field 1.
   Decrypt responses from outer field **22** in the same way.
5. `data` is AES-256-GCM `nonce || ciphertext || tag`, with no associated data.
   The 12-byte nonce is four zero bytes followed by an unsigned 64-bit big-endian
   request counter starting at 1. Each response echoes that request's counter
   using the other key. Only one request can be outstanding. Replays, skipped
   counters, authentication failures, and plaintext after the hello close the session.

The initial frame is capped at 64 bytes and has a 15-second handshake deadline.
Later frames are capped at 60,128 bytes, with a 120-second whole-frame deadline.
Responses have a 15-second write deadline. All I/O handles partial reads/writes.
Ephemeral keys and plaintext buffers are cleared when the session ends.

## Commands

The decrypted payload is a BluetoothCommand-compatible envelope. Error responses
use field **10**, containing `Error.message` in field 1. No management, arbitrary
configuration, imported private keys, application, reset, or shell commands exist
on this service.

| Command field | Body | Response field | Behavior |
| --- | --- | --- | --- |
| 1 | Empty | 1, `WifiList` | Scan up to 24 APs, including SSID, security and signal |
| 2 | `WifiConnect` | 2, `WifiConnected` | Connect and persist Wi-Fi credentials on success |
| 3 | Empty | 3, `WifiStatus` | Report connection and SSID |
| 18 | `StatusCommand` | 19, `Status` | Read capabilities; optionally obtain a fresh enrollment nonce |
| 19 | `Enroll` | 20, `Enrolled` | Validate and persist first enrollment, then reboot |

`Status.device_class` is `C`; `lite_supported` is true only when setup is allowed.
`acme_supported` is always false. Older clients that only support WendyOS class-B
ACME enrollment must decline setup, rather than minting the wrong credential.
`enrolled` means an identity exists or enrollment is already configured, including
pending enrollment. It is not proof of certificate installation or Cloud presence.
`max_config_size` is 60,000 bytes, including the entire serialized WendyConf.

A normal status read does not rotate the nonce. Set `StatusCommand.request_nonce`
to true only when preparing enrollment. The returned `nonce` is a 32-byte
hex-encoded, device-generated challenge. A later challenge replaces it.

## Phone enrollment flow

1. Open the setup service and read status. Require `device_class == "C"` and
   `lite_supported`, and refuse enrollment if `enrolled` is true.
2. Optionally scan/connect Wi-Fi. If requested, confirm the expected SSID is
   connected. A Wi-Fi connection is not a prerequisite for accepting enrollment
   configuration.
3. Obtain a fresh nonce. Discover compatible device, TSA, and HTTPS CA roots using
   verified HTTPS, then obtain a nonce-bound RFC 3161 timestamp. The existing
   Wendy CLI's `liteenroll` implementation defines the class-C Cloud flow.
4. Reserve the device UUID and mint a **class-C enrollment token** using the
   selected organization's signed Cloud request. Cache the result for a safe
   retry; do not mint another token after an uncertain response.
5. Serialize WendyConf with only `device_name` and `enrollment`. Use a lowercase
   DNS-style name of 1..63 bytes starting with a letter. Enrollment includes the
   canonical tenant/device UUIDs, one-use token, CSR/time HTTPS URLs, broker,
   signed time, and CA roots. Set `provision_trust` if providing roots. Send these
   bytes in `Enroll.lite_config` field **6**. WendyOS fields 1..5 are rejected.
6. The board checks the configuration, CA bundles, persisted challenge and signed
   time, then persists it. The response contains the requested SPIFFE principal
   and **`pending = true`**. This acknowledges configuration only.
7. Expect BLE to disconnect. The board reboots, generates its own key and CSR,
   refreshes verified time, redeems the token, validates the returned identity,
   and connects to Cloud using the existing PKI path.
8. Confirm an authenticated Cloud presence or authenticated device session for
   the exact UUID before showing success. A Cloud inventory row alone only proves
   reservation. After a timeout or lost acknowledgment, check that UUID before
   suggesting another enrollment. Recovery of a pending enrollment uses USB.

The board reboots after a successful write even if sending the acknowledgment
fails. Enrollment tokens and Wi-Fi passwords never appear in setup error replies.
The Lite operator authority remains installable only by the authenticated PKI
response, not by the uploaded configuration.

Accepting configuration offline does not bootstrap a mesh identity. Current
firmware must reach the timestamp and enrollment HTTPS endpoints to obtain its
first certificate. Mesh authentication requires that certificate already be
installed, and the mesh Cloud uplink cannot issue it. A phone/gateway bootstrap
relay is still needed for first-time mesh-only enrollment. Do not describe a
pending configuration as successful mesh enrollment; its token may expire while
offline and recovery currently requires USB. The test board's generic build
does not enable mesh.

This firmware patch supplies the Lite service and protocol. A companion client
must implement the class-C branch above; an existing class-B-only app cannot
complete Lite enrollment just by updating the firmware.

## Verification

Host advertising/dispatch tests:

```sh
cmake -S components/wendy_ble/tests -B /tmp/lite-ble-tests
cmake --build /tmp/lite-ble-tests
ctest --test-dir /tmp/lite-ble-tests --output-on-failure
```

Crypto, framing, and persistence tests use the existing PKI test build. Set
`IDF_PATH` to ESP-IDF 6.0.3 or pass its components directory with `IDF_COMPONENTS`.

```sh
cmake -S components/wendy_pki/tests -B /tmp/lite-pki-tests
cmake --build /tmp/lite-pki-tests --target ble_setup_crypto_test ble_setup_session_test conf_test renewal_test
ctest --test-dir /tmp/lite-pki-tests -R 'ble_setup|pki_configuration_persistence|pki_renewal_fallback' --output-on-failure
```

The crypto test shares a deterministic public fixture with the Swift companion
and Go agent. Framing tests cover fragmentation, plaintext rejection, timeouts,
and reboot after a lost acknowledgment. Dispatch/persistence tests cover existing
identities, reset, duplicate commands/configs, invalid timestamps and trust roots,
failed writes, and preserving stored Wi-Fi. These tests do not replace a physical
BLE and Cloud enrollment test with an updated companion client.
