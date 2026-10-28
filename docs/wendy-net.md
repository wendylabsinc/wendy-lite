# Wendy Net on Wendy Lite

Wendy Net lets an enrolled Lite device join other devices in the same tenant,
provide management and application services across the mesh, and discover
services without being on the same physical LAN. Devices with PSRAM can also
forward traffic between peers. The smaller ESP32-C6 profile connects through
one neighbour and does not forward traffic for other devices.

Wendy Net is optional and **off by default**. Use matching WendyOS and Lite
firmware: the current binary protocol replaces the old special-purpose leaf
protocol and does not support it.

## Choose a firmware profile

The release catalog includes these profiles with Wendy Net and WASM support:

| Profile | Required hardware | Guest linear-memory ceiling | Mesh memory ceiling | Mesh connections |
| --- | --- | --- | --- | --- |
| `esp32c5_net_psram` | ESP32-C5, 8 MiB flash and 8 MiB quad PSRAM | 5 MiB | 2 MiB total, PSRAM preferred | Up to 3 BLE and 3 Wi-Fi |
| `esp32c6_net` | ESP32-C6, 8 MiB flash | 64 KiB | 160 KiB internal RAM | One BLE **or** one Wi-Fi |

Memory ceilings bound allocations; they are not reserved when mesh is off or
preallocated in full when it starts. Radio and internal-memory availability can
limit the number of connections below the configured maximum. C5 stores mesh
state in PSRAM, but task stacks and radio allocations still need internal RAM.
Guest runtime metadata and networking also need RAM beyond the linear-memory
ceiling. Both profiles
support bytecode and target AOT/XIP guests. Generic native-only catalog profiles
do not gain WASM support by enabling mesh at runtime.

For a source build, use the matching board argument file and a fresh
configuration. For example, build the C5 profile with:

```sh
idf.py -B build/c5-net -D SDKCONFIG=build/c5-net/sdkconfig \
  @boards/esp32c5_net_psram.cfg set-target esp32c5
idf.py -B build/c5-net -D SDKCONFIG=build/c5-net/sdkconfig build
```

For C6, use `boards/esp32c6_net.cfg`, target `esp32c6`, and a separate build
and sdkconfig path. The argument files select the mesh, WASM and 8 MiB partition
defaults together. Flash and PSRAM settings must match the physical module.

## Enable and configure

[Enroll the device over USB](cloud-enrollment.md) and, for a Wi-Fi carrier,
configure its Wi-Fi connection first. Select it through its existing management
connection; USB is useful while changing wireless settings. Replace `PORT` below
with the serial device shown by `wendy discover`.

For a C5 with both transports enabled:

```sh
wendy --device wendy-lite:PORT device wendy-net configure \
  --participate=true --ble=true --infrastructure-wifi=true --nan=false \
  --ble-links=3 --wifi-links=3 --max-links=6
wendy --device wendy-lite:PORT device wendy-net status
```

For a C6 using Wi-Fi:

```sh
wendy --device wendy-lite:PORT device wendy-net configure \
  --participate=true --ble=false --infrastructure-wifi=true --nan=false \
  --wifi-links=1 --max-links=1
```

To select BLE instead, set `--ble=true --infrastructure-wifi=false`. C6 enforces
this choice at runtime; it does not need a different firmware image. A change
between BLE and Wi-Fi saves the settings and restarts the device. The CLI reports
that settings were applied and the device is restarting. Reconnect afterwards.
Enabling both returns a one-carrier-only error. An unavailable BLE, Wi-Fi or NAN
carrier returns an explicit unsupported-carrier error rather than silently
ignoring the request. NAN is not available in these profiles.

Omitted settings retain their previous values. Status reports the requested and
applied settings, connection state, active links and mesh memory use. Peers are
discovered automatically over mDNS and BLE and authenticated before use; there
is no per-neighbour leaf configuration.

Disable participation with:

```sh
wendy --device wendy-lite:PORT device wendy-net configure --participate=false
```

Disabling stops mesh tasks and releases their allocations. Ordinary management
remains available through the device's other configured transports. The C6
profile disables Cloud connectivity; use USB or an available local or mesh
management connection. Internet sharing and borrowing are not implemented for
Lite, and the CLI rejects those settings.

## Services and device capabilities

The signed device manifest contains the device's management endpoint,
capabilities and all active application services. Services share the manifest's
expiry. A change is published immediately when possible, with further changes
batched to at most one publication per second. Unchanged devices refresh the
manifest every five minutes with a fifteen-minute lease. Browsing shows services
only while their owner has a usable mesh route and a current verified manifest.

WendyCom management and SensorLink use an encrypted connection to the destination
device. WendyCom does not add another TLS connection inside that connection.
`caps=sensors` indicates SensorLink support; available channels still come from
the device's SensorLink manifest and depend on its firmware and sensor providers.
Publishing a guest service does not automatically create a SensorLink channel.

Wi-Fi mesh connections use TCP with TLS; BLE uses TLS over L2CAP. WendyOS peers
also support Lite's TCP transport alongside their normal QUIC connections.
Authentication and destination encryption apply across intermediate routers.

## Guest applications and small-device limits

Guests can publish TCP/UDP listeners and browse remote services using the
[guest networking API](../components/wendy_net/README.md). Service declarations
are part of the device manifest, rather than separately signed records.
The C replay helper and Swift `Services` API keep desired declarations in guest
memory and replay them when mesh becomes available again. No host service
registry survives mesh off/on. Replaying a declaration does not preserve an
old socket: applications must also handle closed connections and listeners.
Small synchronous guests can use the socket imports without async Swift.

C5 retains bounded full manifests, certificate data and service details in RAM.
C6 instead keeps small verified endpoint summaries, up to 64 allocated on demand,
and a limited key cache. It scans and connects out to an authenticated neighbour,
which supplies its next hop. Large manifests, busy handshakes or cache pressure
can make remote browsing and outgoing service connections temporarily unavailable.
Incoming mesh management and SensorLink share one client slot, alongside one guest
flow in each direction. Applications should close idle connections and retry
resource-unavailable results.

Learned peer records, keys, services and packet queues stay in RAM. Flash holds
the device's own enrollment material, explicit management settings and
once-per-boot publication/time metadata, rather than other peers' changing data.
