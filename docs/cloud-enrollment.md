# Enrollment for Wendy Lite

Wendy Lite has one enrollment flow. Enrollment creates the device identity used
for Cloud, LAN, and BLE. There is no separate provisioned state or credential
import flow.

`wendy cloud enroll-device` enrolls a USB-connected board with the PKI deployment
selected by the operator's Wendy CLI session. A development login selects
`identity.dev.pki.wendy.sh`; the CLI derives the sibling CSR and EST CA-discovery
endpoints. Self-hosted deployments can override these URLs and the broker address.

The device generates its P-256 private key, creates a CSR, and redeems a single-use
Tier C token directly at pki-core over HTTPS. Cloud authorizes that token using the
operator's signed request and reserves the asset/device binding in PostgreSQL.
No device private key passes through the CLI or the configuration protobuf.

## Build the firmware

Use ESP-IDF 6.0.3, or ESP-IDF 6.1 for the
[ESP32-S31 preview target](../README.md#esp32-s31-notes). Firmware uses the pinned
esp-pqc mbedTLS 4 backend for PKI trust and TLS, with ML-DSA-65 certificate
verification.

PKI and the cloud connection task are enabled by default. The task starts after
Wi-Fi connects and enrollment is configured. Build without deployment-specific roots:

```sh
echo 'CONFIG_WENDY_CLOUD=y' > cloud.defaults
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;cloud.defaults' set-target esp32c6
idf.py build
```

The base defaults enable `CONFIG_MBEDTLS_USE_BUNDLED_PQC=y` and
`CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65=y`. Device keys remain P-256.
ML-DSA-65 operator keys and ML-DSA-65/87 CA chains are supported. ML-DSA-87
support is verification-only for CAs; it does not enable ML-DSA-87 operator
keys or TLS CertificateVerify signatures. ML-DSA-44 remains unsupported.
Inbound TLS handshake messages, including Certificate, are limited to 32 KiB.
The build applies a [tracked mbedTLS fix](../patches/README.md) that fragments
larger outgoing certificate chains into separate TLS records.
Keep `CONFIG_MBEDTLS_DYNAMIC_BUFFER=n` and
`CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN=16384`. ESP-IDF's dynamic receive allocator
does not match the bundled backend's handshake reassembly bounds.
Select `CONFIG_MBEDTLS_DEFAULT_MEM_ALLOC=y` so PSRAM-equipped boards can
allocate the larger TLS buffers without exhausting internal RAM.

For an existing native app, apply these options to its active `sdkconfig` and
keep them in the app's defaults. A change to `sdkconfig.defaults` alone does not
override a value already in `sdkconfig`. Use a fresh build directory when moving
from ESP-IDF 5 to ESP-IDF 6.

Install compatible device, TSA and HTTPS CA bundles through the authorized USB
connection using `--device-roots`, `--tsa-roots` and `--https-roots`. Obtain them
from the PKI administrator. Each complete chain must use supported algorithms;
a P-256 leaf beneath an ML-DSA issuer requires an ML-DSA-65 or ML-DSA-87 CA. The firmware
also verifies ECDSA timestamps, including Sigstore's P-384 signing certificates.
The HTTPS bundle must also trust the configured broker hostname.

Pass the deployment's actual RFC 3161 HTTPS endpoint with `--time-url`. Roughtime
is not supported by this firmware. Optional build-time bundles remain supported;
the CLI checks the board's advertised trust readiness. Without all required trust,
the device refuses to connect. Never use fixture roots for deployment.

Every partition table ends with a 176 KiB `wendy_pki` NVS partition and a 72 KiB
configuration partition. These layouts are not an OTA-compatible upgrade from
images that predate them: flash over USB, and preserve any needed application data
before installing. The identity partition is never erased by automatic NVS recovery.

Private keys currently use software NVS custody. Hardware key protection, flash
encryption, and secure boot setup are not implemented by this enrollment
flow. Do not describe the resulting image as hardware-protected.

## Enroll

Install the companion Wendy CLI branch, log in to the development Cloud, and
configure the board's Wi-Fi over USB. The broker needs the companion Cloud change
and its real PKI/fabric configuration from
[cloud#638](https://github.com/wendylabsinc/cloud/pull/638).

```sh
wendy cloud login --email YOU@YOUR_ORGANIZATION
wendy cloud enroll-device \
  --device wendy-lite:/dev/cu.usbmodemXXXX \
  --name lite-desk \
  --time-url https://YOUR_TSA_ENDPOINT/v1/time \
  --device-roots device-ca-bundle.pem \
  --tsa-roots tsa-ca-bundle.pem \
  --https-roots server-ca-bundle.pem
wendy cloud discover
```

The Lite broker defaults to `tunnel.wendy.dev:5055` for production Cloud and
`tunnel.dev.wendy.dev:5055` for development Cloud, based on the selected session.
No broker flags are needed for hosted Cloud. Self-hosted deployments can override
the listener with `--broker-host` and `--broker-port`. Set
`--csr-url https://csr.example/v1/TENANT_UUID` for custom CSR routing and
`--time-url https://codesign.example/v1/time` to use RFC 3161.

The CLI validates discovered or supplied roots and checks USB trust support
before reserving an asset. Firmware advertises `mldsa_verification_supported` only
when PKI and ML-DSA-65 verification are enabled. This capability covers ML-DSA-65;
it does not imply support for ML-DSA-44 or ML-DSA-87 operator keys. The CLI requires it before
accepting ML-DSA trust bundles, and the device validates every installed bundle.
The firmware accepts at most eight CA certificates
and 16 KiB per bundle; signed time plus all bundles must fit within 64 KiB.

The bundles persist with the enrollment configuration in the `wendy_conf` flash
partition and survive reboot. Trust installed over USB takes precedence over embedded
roots. Missing, partial, or malformed installed trust fails closed, with no
fallback to a different trust source. Network peers cannot write this configuration.
Wi-Fi-only configuration updates preserve it; replacing or erasing the entire
configuration removes it. Existing enrolled boards require operator recovery to
change enrollment through the CLI. Those root bundles do not rotate remotely.
The separate Lite operator anchor described below can rotate through authenticated
renewal; changes to device, TSA and HTTPS roots require USB enrollment recovery.

If an enrolled board reports `Invalid or missing device CA bundle` after a
firmware update and both LAN TLS and Cloud stop working, first check the firmware
build's [dependency patches](../patches/README.md). Builds that silently skipped
the ML-DSA CA patch reject otherwise valid stored roots before contacting Cloud.
Rebuild with the patch-application fix and preserve the enrollment configuration
and identity partitions. Replacing the trust bundle or erasing enrollment is not
required to correct that build defect.

The command obtains a device-generated nonce and a matching RFC 3161 timestamp
before minting the credential. The board verifies its signature, TSA chain,
critical timestamp EKU, nonce, message imprint and persisted rollback floor.
It receives configuration through USB, reboots, refreshes verified time, and
obtains its certificate. The CLI waits up to two minutes for installation.
Tier C enrollment must also return `X-Wendy-Lite-Operator-Authority`, containing
standard base64 DER for the tenant's self-signed P-256 CA with `pathLen=0`.
Firmware validates and pins it separately in the identity partition as the sole
Cloud relay operator anchor. Only authenticated PKI enrollment and renewal
responses can install it; USB configuration, BLE, the CLI and device CA bundles cannot.
The firmware retains the pending certificate and authority header separately from
its usable identity so verification can retry without spending the one-use token
again. Missing or malformed initial authority data cannot activate an identity.

An installed certificate is distinct from broker presence. The broker establishes
presence after mTLS authentication, asset lookup, revocation checks, and the
WendyCom exchange. Failed enrollment may leave a reserved asset; the CLI reports
that asset ID rather than claiming success. An expired identity requires operator
recovery. A fresh token is not silently substituted for an expired certificate.

## Connection and renewal

Lite opens an outbound TLS 1.3 connection authenticated with its issued identity.
It refreshes signed time and reconnects every four minutes. A currently valid
certificate with less than one day remaining is renewed over mTLS. An existing
identity without a Lite operator anchor also renews on the next connection,
regardless of its remaining lifetime. A valid authority header in that response
replaces the pin after the issued device identity verifies; an omitted header
preserves the current pin, and a malformed header cannot overwrite it. The device
retains renewal responses before verification so it can recover without spending
the predecessor again. Before accepting a new certificate, it refreshes signed
time again because the certificate's validity starts at issuance.
It continues using its stored certificate if renewal fails and that certificate
still passes validation after the request. It retries renewal on the next
connection. An expired or invalid certificate cannot be used as a fallback.
If renewal omits the header and no pin exists yet, the control connection can
continue, but relay sessions remain unavailable and the next connection retries
renewal.
The device persists the signed-time floor and rejects rollback, invalid
certificates, and unverified timestamps. A delayed fresh-time exchange over
30 seconds fails.

Enrollment challenges and configuration replacement are restricted to the physical
UART/USB link. Network management connections may submit UPDATE uploads containing
only the Wi-Fi field. The firmware validates the complete payload before writing
flash and preserves the existing enrollment and trust settings.
The enrolled identity is used for Cloud, LAN, and BLE connections. Once
enrollment is configured, the LAN server uses the verified stored identity and
requires a clientAuth certificate with exactly one operator or device SPIFFE URI
in the same tenant. Operators can manage the device; authenticated devices can
only request the SensorLink manifest, subscribe, and unsubscribe. Device clients
cannot send console input or invoke management commands, including through extra
WendyCom channels. Missing, invalid, or expired enrollment credentials fail closed;
neither LAN nor BLE falls back to anonymous TLS. Enrolled boards
advertise the BLE identity service with mTLS required and accept same-tenant
operators over TLS 1.3 on L2CAP. BLE keeps advertising when Wi-Fi is unavailable;
connections require a valid stored PKI identity. BLE retains its startup
authentication policy and rejects sessions after an enrollment change until reboot.
Unenrolled devices accept anonymous TLS connections over LAN
and Bluetooth by default. `CONFIG_WENDY_BLE_REQUIRE_MTLS=y` disables anonymous
Bluetooth access. Enrollment and other configuration changes still require USB/UART.

BLE and Cloud relay access remain operator-only. Client certificates must have
exactly one `spiffe://wendy.sh/tenant/<tenant UUID>/operator/<subject>` URI.
The tenant must match the device certificate's sole `/device/` URI. Service,
ambiguous, and missing identities are rejected. Discovery advertises whether
mTLS is required. Missing or invalid enrollment credentials never enable anonymous
access.

Older firmware could import a device key and certificate into configuration
field 3, named `provisioning`. That field is reserved and no longer accepted.
Boards with only those credentials refuse network access and require a local
enrollment reset over USB/UART, followed by `wendy cloud enroll-device`. Boards
that also have a valid enrollment continue to use their enrolled identity.
The firmware does not interpret imported credentials as an enrolled identity or
use anonymous access as a fallback. The configuration utility only edits the
device name and Wi-Fi; it cannot import or export device credentials.

LAN discovery advertises the tenant and device principal to select an appropriate
identity and locate paired sensors. BLE publishes the same principal string in the
info service's read-only characteristic `4E57454E-4459-0002-0006-000000000000`
(UTF-8, empty when unenrolled), and USB `GetDeviceIdentity` returns its UUID as
`enrolled_device_id`. That UUID, minted by the CLI at enrollment, is the device's
one id and its cloud asset id. The hardware id (TXT `id=`, BLE manufacturer data and
device-ID characteristic, `GetDeviceIdentity.id`) is only the asset serial number.
This is only a selection hint: TLS still verifies the certificate chain and the
CLI checks the device principal. LAN clients supply a certificate chain compatible
with the device's configured roots and TLS backend, including intermediates.
BLE clients also authenticate with a certificate from the enrolled tenant.

For Cloud relay, the CLI obtains a separate marked P-256 Lite operator leaf through
the selected operator login. Its issuer is the separately pinned Lite Operator
Authority, outside the primary operator's CA tree. An explicit override uses
`WENDY_LITE_OPERATOR_CERT` for that PEM leaf and `WENDY_LITE_OPERATOR_KEY` for its
matching private key; both must represent the selected operator. The same Lite
key signs `create_lite_tunnel` requests and authenticates inner TLS. The CLI sends
only the Lite leaf and verifies the device with the selected session's device CA
trust. Cloud administration and enrollment authorization retain the primary identity.

CLI access through Cloud requires an authorized tunnel, an end-to-end
CLI/device mTLS handshake and a verified Cloud session grant. See
[the relay protocol](cloud-relay.md). The console's existing `cloud://` target is the
separate tinycloud development transport and must not be used as that secure path.

## Verification

```sh
cmake -S components/wendy_pki/tests -B build-pki
cmake --build build-pki
ctest --test-dir build-pki --output-on-failure
```

The committed fixtures were generated with pki-core's `ca.Engine.IssueTimestamp`
and P-256 certificate builder. They contain public test credentials only.
See [the test instructions](../components/wendy_pki/tests/README.md) to regenerate
them. CI runs host verification, including Go-to-mbedTLS TLS 1.3
interoperability tests, and builds the PKI-enabled C6 image. Hardware enrollment,
latency and memory behavior still require a connected board and compatible
deployment trust bundles.

## Firmware size

The firmware uses esp-pqc's mbedTLS for PKI TLS, certificate validation and signed
time, including ML-DSA-65 certificate verification. Device keys and session grants
remain P-256. WASM is opt-in through
`boards/wasm.defaults`. See [relay size measurements](cloud-relay.md#default-image-size).


## Reset a local enrollment

Updated firmware advertises `enrollment_reset_supported` in its USB enrollment
challenge. With an updated CLI, `wendy device unenroll --device
wendy-lite:/dev/cu.usbmodemXXXX` first removes the Cloud enrollment, then clears
the connected board's enrollment and reboots it. Cloud-only removal still leaves
the board's identity in place. A board whose Cloud asset was already removed can
repeat the USB command to finish local recovery.

The `enrollment_reset` WendyCom command accepts the hardware ID and the current
challenge nonce. Firmware accepts it only through the physical serial link;
LAN, Bluetooth, and Cloud sessions cannot reset enrollment. A stale nonce or a
different hardware ID is rejected before any write. The command acknowledges
success before the CLI reboots. Existing network sessions stop accepting reads,
writes, and commands as soon as reset begins, including when the response is lost.

Reset first commits a pending marker and a recovery copy of the unrelated
configuration. It removes enrollment and any obsolete imported credentials before
erasing the key, certificate, active and pending Lite operator anchor, pending
issuance, and identity binding. Device name,
Wi-Fi, unknown configuration fields, and the app partitions are preserved. The
signed time floor also remains. Interrupted configuration writes can resume from
the retained recovery copy; the copy is cleared only after a verified write.
An incomplete reset blocks Cloud issuance after restart and reports an enrolled
state until a fresh USB challenge and reset finish the cleanup. Repeating the
command with a new nonce is safe after a lost reply or a partial failure.

Ordinary configuration uploads still use the existing erase/write storage format;
this recovery journal only protects the enrollment-reset operation. Corrupt
recovery data or failed NVS writes return an error and retain remaining identity
material. Older firmware does not advertise reset support and requires an update
before the CLI can complete local recovery.

## Firmware enrollment capability

Standard builds enable `CONFIG_WENDY_CLOUD` so a Wi-Fi connection can start the
PKI enrollment task when enrollment configuration is present. Firmware without
stored enrollment does not start the task. Custom profiles can still disable
Cloud support explicitly.

Network services start when Wi-Fi obtains an IP address, including when DHCP
finishes after the initial connection wait times out. The service worker retries
mDNS and cloud-task startup failures while connected, without starting duplicate
services after repeated IP events.

The optional `cloud_enrollment_supported` field in the USB challenge is true
only when PKI, Cloud, and Wi-Fi are compiled in. Updated CLIs reject an explicit
false value before reserving an asset or minting a credential. Older firmware
omits the field and remains compatible. Firmware with Cloud or Wi-Fi disabled
still advertises local enrollment reset when PKI is enabled.

The default CLI timestamp service is Sigstore. Its RFC 3161 responses use a
P-384 signer and SHA-384 certificate chains, and may include the optional
ESSCertIDv2 issuer/serial binding. Firmware verifies those fields against the
actual signer certificate and retains its curve restrictions, nonce, imprint,
trust-root, signature, validity, and rollback checks. The public timestamp host
tests exercise captured Sigstore data and signed negative fixtures.
