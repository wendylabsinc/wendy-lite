# Real PKI enrollment for Wendy Lite

`wendy cloud enroll-device` enrolls a USB-connected board with the PKI deployment
selected by the operator's Wendy CLI session. A development login selects
`identity.dev.pki.wendy.sh`; the CLI derives the sibling CSR and EST CA-discovery
endpoints. Self-hosted deployments can override these URLs and the broker address.

The device generates its P-256 private key, creates a CSR, and redeems a single-use
Tier C token directly at pki-core over HTTPS. Cloud authorizes that token using the
operator's signed request and reserves the asset/device binding in PostgreSQL.
No device private key passes through the CLI or the configuration protobuf.

## Build the firmware

Use ESP-IDF 5.5.4. Firmware uses its bundled mbedTLS by default.

PKI and the cloud connection task are enabled by default. The task starts after
Wi-Fi connects and enrollment is configured. Build without deployment-specific roots:

```sh
echo 'CONFIG_WENDY_CLOUD=y' > cloud.defaults
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;cloud.defaults' set-target esp32c6
idf.py build
```

For a PKI deployment with ML-DSA CA or operator certificates, enable the optional
wolfSSL backend. `CONFIG_WENDY_PKI_WOLFSSL` defaults to `n`; standard images keep
mbedTLS and do not compile wolfSSL. Initialize the pinned wolfSSL submodule before
building the optional profile:

```sh
git submodule update --init components/wendy_wolfssl/wolfssl
echo 'CONFIG_WENDY_PKI_WOLFSSL=y' > wolfssl.defaults
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;wolfssl.defaults' set-target esp32c6
idf.py build
```

For an existing native app, enable **Wendy PKI / wolfSSL** in `idf.py menuconfig`
or set `CONFIG_WENDY_PKI_WOLFSSL=y` in its active `sdkconfig`. A change to
`sdkconfig.defaults` alone does not override a value already in `sdkconfig`.
Keep the setting in the app's defaults as well if future clean builds need it.
The optional backend verifies ML-DSA-44, ML-DSA-65 and ML-DSA-87 certificates and
keeps P-256 device keys. It increases firmware size and memory use.

Provision compatible device, TSA and HTTPS CA bundles through the authorized USB
connection using `--device-roots`, `--tsa-roots` and `--https-roots`. Obtain them
from the PKI administrator. Each complete chain must use algorithms supported by
the selected backend; issuing a P-256 leaf beneath an ML-DSA issuer still requires
the wolfSSL profile. Both profiles verify ECDSA timestamps, including Sigstore's
P-384 signing certificates.
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
encryption, and secure boot provisioning are not implemented by this enrollment
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
  --broker-port 5055 \
  --time-url https://YOUR_TSA_ENDPOINT/v1/time \
  --device-roots device-ca-bundle.pem \
  --tsa-roots tsa-ca-bundle.pem \
  --https-roots server-ca-bundle.pem
wendy cloud discover
```

The broker hostname defaults to the devices hostname used by wendy-agent for the
selected Cloud session. Override it with `--broker-host`. Set
`--csr-url https://csr.example/v1/TENANT_UUID` for custom CSR routing and
`--time-url https://codesign.example/v1/time` to use RFC 3161.

The CLI validates discovered or supplied roots and checks USB trust support
before reserving an asset. Firmware advertises `mldsa_verification_supported` only
when PKI uses wolfSSL. The CLI requires this capability before accepting ML-DSA
trust bundles. An absent capability uses the mbedTLS compatibility check.
The firmware accepts at most eight CA certificates
and 16 KiB per bundle; signed time plus all bundles must fit within 64 KiB.

The bundles persist with the enrollment configuration in the `wendy_conf` flash
partition and survive reboot. USB-provisioned trust takes precedence over embedded
roots. Missing, partial, or malformed provisioned trust fails closed, with no
fallback to a different trust source. Network peers cannot write this configuration.
Wi-Fi-only configuration updates preserve it; replacing or erasing the entire
configuration removes it. Existing enrolled boards require operator recovery to
change enrollment through the CLI. This does not add remote trust rotation.

The command obtains a device-generated nonce and a matching RFC 3161 timestamp
before minting the credential. The board verifies its signature, TSA chain,
critical timestamp EKU, nonce, message imprint and persisted rollback floor.
It receives configuration through USB, reboots, refreshes verified time, and
obtains its certificate. The CLI waits up to two minutes for installation.
The firmware retains an unverified issuance response separately from its usable
identity so verification can retry without spending the one-use token again.

An installed certificate is distinct from broker presence. The broker establishes
presence after mTLS authentication, asset lookup, revocation checks, and the
WendyCom exchange. Failed enrollment may leave a reserved asset; the CLI reports
that asset ID rather than claiming success. An expired identity requires operator
recovery. A fresh token is not silently substituted for an expired certificate.

## Connection and renewal

Lite opens an outbound TLS 1.3 connection authenticated with its issued identity.
It refreshes signed time and reconnects every four minutes. A currently valid
certificate with less than one day remaining is renewed over mTLS. The device
continues using its stored certificate if renewal fails and that certificate
still passes validation after the request. It retries renewal on the next
connection. An expired or invalid certificate cannot be used as a fallback.
The device persists the signed-time floor and rejects rollback, invalid
certificates, and unverified timestamps. A delayed fresh-time exchange over
30 seconds fails.

Configuration upload and enrollment challenges are restricted to the physical
UART/USB link. The new PKI identity is used for Cloud and LAN connections. Once
enrollment is configured, the LAN server uses the verified stored identity and
requires a clientAuth certificate with exactly one operator or device SPIFFE URI
in the same tenant. Operators can manage the device; authenticated devices can
only request the SensorLink manifest, subscribe, and unsubscribe. Device clients
cannot send console input or invoke management commands, including through extra
WendyCom channels. Missing, invalid, or expired enrollment credentials fail closed;
the LAN server does not fall back to legacy or anonymous TLS. BLE requires
legacy provisioning credentials and a trusted operator certificate for the same
organization. BLE is disabled whenever PKI enrollment is configured, including
devices that also retain legacy credentials, because BLE cannot use the stored
PKI identity yet. Unprovisioned devices accept anonymous TLS connections over LAN
and Bluetooth by default. `CONFIG_WENDY_BLE_REQUIRE_MTLS=y` disables anonymous
Bluetooth access. Configuration upload and enrollment still require USB/UART.

Legacy LAN and BLE provisioning also require certificate chain validation and
an explicit `clientAuth` leaf with exactly one
`spiffe://wendy.sh/tenant/<tenant UUID>/operator/<subject>` URI. Legacy LAN also
accepts `/device/<subject>` with the same SensorLink-only restrictions. BLE and
Cloud relay access remain operator-only. The tenant must match the device
certificate's sole `/device/` URI. Service, ambiguous, and missing identities are
rejected. Legacy credentials without this
device identity must be replaced over USB/UART. Missing or invalid credentials on
a PKI-enrolled device never enable anonymous access. Discovery advertises whether
mTLS is required.

LAN discovery advertises the tenant and device principal to select an appropriate
identity and locate paired sensors.
This is only a selection hint: TLS still verifies the certificate chain and the
CLI checks the device principal. The CLI sends its operator certificate chain,
including intermediates. With the default mbedTLS firmware and an ML-DSA administration identity,
provision a P-256 certificate for the same operator and set `WENDY_LITE_OPERATOR_CERT`
to its PEM leaf plus full compatible CA chain and `WENDY_LITE_OPERATOR_KEY` to its
private key. The CLI uses this identity for Lite request signing and device TLS.
Cloud administration and enrollment authorization keep their existing identity.

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
them. CI runs host verification, including a Go-to-mbedTLS TLS 1.3 interoperability
test, and builds the PKI-enabled C6 image. Hardware enrollment, latency and memory
behavior still require a connected board and compatible deployment trust bundles.

## Firmware size

The default firmware uses ESP-IDF's mbedTLS for TLS, P-256 certificate validation,
signed time and session grants. The optional wolfSSL profile adds ML-DSA certificate
verification. WASM is opt-in through
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
configuration. It removes enrollment and legacy provisioning configuration before
erasing the key, certificate, pending issuance, and identity binding. Device name,
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
