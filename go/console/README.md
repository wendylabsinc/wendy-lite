# Wendy Lite Console

A small client for connecting to Wendy Lite and testing the WendyCom protocol implementation.

This is a development tool and is not intended for production use.

`conf-update <configuration.pb>` pushes a protobuf-encoded `WendyConf` using
UPDATE mode. Omitted root fields stay unchanged. Run `reset` afterwards to apply
the configuration. This is a configuration editor, not a PKI enrollment command.

Real cloud enrollment must use an operator-authorized Tier C credential from
pki-core and a private key generated and retained by the device. Importing a
laptop-generated key and certificate through `conf-update` does not implement
that flow. Use the companion Wendy CLI's `wendy cloud enroll-lite` command with
PKI-enabled firmware. See [the enrollment guide](../../docs/cloud-enrollment.md)
for trust bundles, builds, and the remaining Cloud tunnel work. Enrollment upload
is restricted to physical USB/UART; network configuration pushes are rejected.

## Connecting

```
console <target>
```

| Target | Transport |
|---|---|
| `192.168.1.42:5054` | TCP + TLS on the local network |
| `/dev/cu.usbmodemXXXX` | USB serial |
| `ble://` | BLE — scan and connect to the only wendy-lite device in range |
| `ble://<name>` | BLE — match the advertised name |
| `ble://<address>` | BLE — a CoreBluetooth peripheral UUID |
| `ble://<target>?psm=129` | BLE — override the L2CAP PSM instead of reading it over GATT |
| `cloud://host:port[/asset-id]` | Through a tinycloud tunnel broker |

BLE carries the same session as the other transports — WendyCom over mTLS, with the
device as peripheral. It is the only one that works on a board with no Wi-Fi
credentials and no cable. It is macOS-only: the client is CoreBluetooth through cgo,
and an address is therefore a per-host CoreBluetooth peripheral UUID rather than a
hardware MAC, which the OS never exposes. Because nothing here is built behind a
platform tag, `go build` for this module only works on macOS.

The BLE client itself lives in `go/internal/shared/ble`, a verbatim macOS-only subset
of the WendyOS package of the same name — the Linux and Windows backends are left
behind, everything copied stays byte-identical, and `tools/sync_with_wendy_os.sh`
checks that it still is.

Every transport currently connects without verifying the device's certificate, which
is what an unprovisioned board needs: it serves a self-signed certificate that
authenticates nothing.
