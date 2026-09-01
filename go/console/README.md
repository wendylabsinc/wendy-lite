# Wendy Lite Console

A small client for connecting to Wendy Lite and testing the WendyCom protocol implementation.

This is a development tool and is not intended for production use.

## Connecting

```
console <target>
```

| Target | Transport |
|---|---|
| `192.168.1.42:5054` | TCP + TLS on the local network |
| `/dev/cu.usbmodemXXXX` | USB serial |
| `ble://` | BLE — scan and connect to the only wendy-lite device in range |
| `ble://<name-or-id>` | BLE — match the advertised name or device id |
| `ble://<address>` | BLE — a CoreBluetooth UUID on macOS, `AA:BB:CC:DD:EE:FF` on Linux |
| `ble://<target>?psm=129` | BLE — override the L2CAP PSM instead of reading it over GATT |
| `cloud://host:port[/asset-id]` | Through a tinycloud tunnel broker |

BLE carries the same session as the other transports — WendyCom over mTLS, with the
device as peripheral. It is the only one that works on a board with no Wi-Fi
credentials and no cable. macOS is the tested platform; the Linux path is ported but
unverified, and needs an explicit Bluetooth address because scanning there would
require BlueZ over D-Bus. Windows is not supported.

Every transport currently connects without verifying the device's certificate, which
is what an unprovisioned board needs: it serves a self-signed certificate that
authenticates nothing.
