# Wendy Lite Console

A small client for connecting to Wendy Lite and testing the WendyCom protocol implementation.

This is a development tool and is not intended for production use.

`conf-update <configuration.pb>` pushes a protobuf-encoded `WendyConf` using
UPDATE mode. Omitted root fields stay unchanged. Run `reset` afterwards to apply
the configuration. Use it for device name and Wi-Fi settings. Firmware rejects
configuration uploads from network connections.

Enroll through the companion Wendy CLI's `wendy cloud enroll-device` command over
USB/UART. Enrollment uses an operator-authorized Tier C credential from pki-core
and a private key generated and retained by the device. A compatible nearby setup
client can also enroll an unenrolled board over the restricted BLE setup service.
Both paths provision the identity used by Cloud, LAN, and BLE. Firmware rejects the old
credential import field. See [the enrollment guide](../../docs/cloud-enrollment.md)
for trust bundles, builds, and recovery of boards with imported credentials.

## Connecting

```
console <target>
```

| Target | Transport |
|---|---|
| `192.168.1.42:5054` | TCP + TLS on the local network |
| `/dev/cu.usbmodemXXXX` | USB serial |
| `ble://` | BLE, scan and connect to the only wendy-lite device in range |
| `ble://<name>` | BLE, match the advertised name |
| `ble://<address>` | BLE, a CoreBluetooth peripheral UUID |
| `ble://<target>?psm=129` | BLE, override the L2CAP PSM instead of reading it over GATT |
| `setup://<name-or-address>` | Read-only probe of the restricted BLE setup service on PSM 131 |
| `cloud://host:port[/asset-uuid]` | Through a cloud tunnel broker (tinycloud or the cloud's dev tunnel); the asset defaults to tinycloud's `00000000-0000-0000-0000-000000000023` |

The `setup://` probe performs the encrypted setup handshake, reads enrollment and
Wi-Fi status, scans networks, prints a JSON result, and exits. It never requests an
enrollment nonce or changes configuration. It requires exactly one matching setup
advertisement. See [the BLE setup protocol](../../docs/ble-setup.md).

The `ble://` transport carries the same session as the other transports, WendyCom over TLS, with the
device as peripheral. It is the only one that works on a board with no Wi-Fi
credentials and no cable. It is macOS-only: the client is CoreBluetooth through cgo,
and an address is therefore a per-host CoreBluetooth peripheral UUID rather than a
hardware MAC, which the OS never exposes. Because nothing here is built behind a
platform tag, `go build` for this module only works on macOS.

The BLE client itself lives in `go/internal/shared/ble`, a verbatim macOS-only subset
of the WendyOS package of the same name. The Linux and Windows backends are left
behind, everything copied stays byte-identical, and `tools/sync_with_wendy_os.sh`
checks that it still is.

This development console connects without verifying the device's certificate.
An unenrolled board serves a self-signed certificate that authenticates nothing.
Enrolled boards require mTLS; use the Wendy CLI with the enrolled tenant's
operator identity to connect to them. A board whose only credentials are invalid
or obsolete refuses network access until it is recovered over USB/UART.
