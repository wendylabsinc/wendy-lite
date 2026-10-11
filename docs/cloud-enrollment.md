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

Use ESP-IDF 5.5.4 and its bundled mbedTLS. wolfSSL is no longer required.

PKI enrollment is built into every image. The cloud connection is opt-in; enable it
and build without deployment-specific roots:

```sh
echo 'CONFIG_WENDY_CLOUD=y' > cloud.defaults
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;cloud.defaults' set-target esp32c6
idf.py build
```

Provision compatible device, TSA and HTTPS CA bundles through the authorized USB
connection using `--device-roots`, `--tsa-roots` and `--https-roots`. Obtain them
from the PKI administrator. Each complete chain must use algorithms supported by
mbedTLS; issuing a P-256 leaf beneath an ML-DSA issuer is insufficient. The device
and operator profiles use P-256, and the TSA uses ECDSA P-256 with SHA-256.
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
before reserving an asset. The firmware accepts at most eight CA certificates
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
requires a clientAuth certificate with exactly one operator SPIFFE URI in the
same tenant. Missing, invalid, or expired enrollment credentials fail closed;
the LAN server does not fall back to legacy or anonymous TLS. BLE still uses the
legacy provisioning credentials.

LAN discovery advertises the tenant to select an appropriate CLI identity.
This is only a selection hint: TLS still verifies the certificate chain and the
CLI checks the device principal. The CLI sends its operator certificate chain,
including intermediates. For a CLI session with an ML-DSA administration identity,
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

The firmware uses ESP-IDF's mbedTLS for TLS, P-256 certificate validation, signed
time and session grants. It has no wolfSSL dependency. WASM is opt-in through
`boards/wasm.defaults`. See [relay size measurements](cloud-relay.md#default-image-size).
