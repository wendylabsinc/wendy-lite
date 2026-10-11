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

Use ESP-IDF 5.5.4 and initialize the pinned wolfSSL dependency:

```sh
git submodule update --init components/wendy_wolfssl/wolfssl
```

PKI enrollment is built into every image. The cloud connection is opt-in; enable it
and build without deployment-specific roots:

```sh
echo 'CONFIG_WENDY_CLOUD=y' > cloud.defaults
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;cloud.defaults' set-target esp32c6
idf.py build
```

The companion CLI discovers device CA roots over HTTPS verified by the enrolling
computer and provisions them over USB, together with verified HTTPS trust anchors.
Use `--ca-certs-url` for a custom CA-discovery endpoint. No deployment-specific
roots need embedding in the firmware. Private HTTPS CAs must already be trusted
by the computer, or supplied explicitly with `--device-roots` and `--https-roots`.
The HTTPS bundle must cover the broker too if it uses a different CA.

Roughtime is the default time source and requires two agreeing pinned servers.
RFC 3161 remains available with `--time-url` and explicit `--tsa-roots` as well as
the device and HTTPS bundles. Optional build-time bundles remain supported by the
firmware, but the CLI provisions trust at enrollment by default. Without trust,
the device refuses to connect. Never use disposable fixture roots for deployment.

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
  --broker-port 5055
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

The command obtains a device-generated nonce and relays signed Roughtime replies
before minting the credential. The board verifies their signatures and consensus.
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
including intermediates, and supports the deployment's ML-DSA certificate chain.

CLI access through Cloud still requires an authorized tunnel and a separate
end-to-end CLI/device mTLS handshake. This change supplies device enrollment and
broker presence, not that tunnel. The console's existing `cloud://` target is the
separate tinycloud development transport and must not be used as that secure path.

## Verification

```sh
cmake -S components/wendy_pki/tests -B build-pki
cmake --build build-pki
ctest --test-dir build-pki --output-on-failure
```

The committed fixtures were generated with pki-core's `ca.Engine.IssueTimestamp`
and mixed-family certificate builder. They contain public test credentials only.
See [the test instructions](../components/wendy_pki/tests/README.md) to regenerate
them. CI compiles the PKI-enabled C6 image both without embedded roots and with
disposable test roots. Neither image is published by the PKI workflow. Hardware enrollment and memory behavior still need a connected
board and the development trust bundles.
