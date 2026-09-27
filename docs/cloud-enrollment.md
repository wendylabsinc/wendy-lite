# Real PKI enrollment for Wendy Lite

`wendy cloud enroll-lite` enrolls a USB-connected board with the PKI deployment
selected by the operator's Wendy CLI session. A development login selects
`identity.dev.pki.wendy.sh`; the CLI derives the sibling CSR and signed-time
endpoints. Self-hosted deployments can override both URLs and the broker address.

The device generates its P-256 private key, creates a CSR, and redeems a single-use
Tier C token directly at pki-core over HTTPS. Cloud authorizes that token using the
operator's signed request and reserves the asset/device binding in PostgreSQL.
No device private key passes through the CLI or the configuration protobuf.

## Build the firmware

Use ESP-IDF 5.5.4 and initialize the pinned wolfSSL dependency:

```sh
git submodule update --init components/wendy_wolfssl/wolfssl
```

Obtain the deployment's trust bundles through your existing authenticated PKI
administration process. The firmware pins these before enrollment. A certificate
returned by the enrollment endpoint does not become a trust anchor.

Create an untracked `pki-trust.defaults` file with absolute PEM paths:

```ini
CONFIG_WENDY_PKI_DEVICE_ROOTS="/absolute/path/to/development-device-roots.pem"
CONFIG_WENDY_PKI_TSA_ROOTS="/absolute/path/to/development-tsa-bundle.pem"
CONFIG_WENDY_PKI_HTTPS_ROOTS="/absolute/path/to/development-server-roots.pem"
```

The device bundle anchors pki-core identities. The TSA bundle must include the
pinned TSA issuer chain needed to validate its signer, since pki-core's timestamp
response currently embeds only the signer. The HTTPS bundle must trust the CSR,
signed-time, and broker server certificates. Server hostname checks are mandatory.
Do not use `components/wendy_pki/tests/fixtures/root.pem` for a development deployment.

For the ESP32-C6 4 MB trial layout:

```sh
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;boards/esp32c6_cloud.defaults;pki-trust.defaults' set-target esp32c6
idf.py build
```

This layout adds a 192 KiB `wendy_pki` NVS partition and an 80 KiB configuration
partition. It changes the WASM/configuration layout and is not an OTA-compatible
upgrade from the normal C6 image. Preserve any needed application data before
installing it. The identity partition is never erased by automatic NVS recovery.
Other boards need an equivalent partition layout and enough application space.

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
wendy cloud enroll-lite \
  --serial /dev/cu.usbmodemXXXX \
  --name lite-desk \
  --broker-host YOUR_WENDYCOM_BROKER_HOST \
  --broker-port 5055
wendy cloud discover
```

The broker hostname is explicit because the Cloud API endpoint does not identify
a WendyCom listener. Set `--csr-url https://csr.example/v1/TENANT_UUID` and
`--time-url https://codesign.example/v1/time` for custom PKI routing.

The command obtains a device-generated nonce and a signed time response before
minting the credential. It sends configuration through physical USB, reboots the
board, and waits up to two minutes for certificate installation. The board checks
the seed against its pinned TSA bundle, retrieves fresh nonce-bound signed time,
and only then redeems its token. Issued certificates must match the device's key
and exact tenant/device SPIFFE URI and allow both TLS client and server use.

An installed certificate is distinct from broker presence. The broker establishes
presence after mTLS authentication, asset lookup, revocation checks, and the
WendyCom exchange. Failed enrollment may leave a reserved asset; the CLI reports
that asset ID rather than claiming success. An expired identity requires operator
recovery. A fresh token is not silently substituted for an expired certificate.

## Connection and renewal

Lite opens an outbound TLS 1.3 connection authenticated with its issued identity.
It refreshes signed time and reconnects every four minutes. A currently valid
certificate with less than one day remaining is renewed over mTLS. The device
persists the signed-time floor and rejects rollback, invalid certificates, and
unverified timestamps. A delayed fresh-time exchange over 30 seconds fails.

Configuration upload and enrollment challenges are restricted to the physical
UART/USB link. The new PKI identity is used for the Cloud connection; existing LAN
and BLE TLS servers are not migrated by this change.

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
them. CI also compiles the PKI-enabled C6 image using test roots and does not
publish that image. Hardware enrollment and memory behavior still need a connected
board and the development trust bundles.
