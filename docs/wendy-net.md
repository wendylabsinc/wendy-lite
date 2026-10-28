# Native Wendy Net

Lite peers use the WendyOS binary carrier protocol, enrolled device identity,
nonce-bound signed time, complete v4 router manifests with embedded services,
and sparse Babel routing. Wi-Fi carriers use TCP + TLS rather than QUIC and
advertise the distinct TCP service. BLE uses the normal router TLS ALPN over
L2CAP. Discovery hints never substitute for peer authentication. There is no
special leaf protocol, startup quarantine, or separately signed service gossip.

## Build and runtime configuration

Append `boards/wendy_net.defaults` after a board profile and, for guest apps,
`boards/wasm.defaults`. ESP32-C5 with verified 8 MiB quad PSRAM additionally uses
`boards/esp32c5_net_psram.defaults`; ESP32-C6 uses `boards/esp32c6_net.defaults`.
Use a fresh sdkconfig when selecting defaults. The release catalog includes
`esp32c5_net_psram` (8 MiB flash and 8 MiB quad PSRAM) and `esp32c6_net`
(8 MiB flash). Their `.cfg` files select the actual mesh, WASM, target and
`partitions.net.8mb.csv` defaults together. The C5 guest linear-memory ceiling
is 5 MiB; the C6 ceiling is 64 KiB. Both support bytecode and target AOT/XIP
modules. Existing generic 4 MiB native catalog variants retain their physical
management-only build policy; use a mesh variant for runtime Wendy Net settings.
Flash/PSRAM capacity and the partition layout must match the physical module.

Mesh starts off until enabled using WendyCom configuration. The management
interface reports compiled carrier capabilities, desired and applied policy,
state, link count and managed allocation counters. On C6, enabling BLE and Wi-Fi
mesh together returns the one-carrier-only result. Changing its selected radio
saves policy and returns an applied/restarting result before reboot. USB remains
available when the selected radio has no peer. NAN is unavailable in this wave.

## Resource profiles

PSRAM routers have a 2 MiB managed mesh ceiling and capacity settings for up to
three BLE and three Wi-Fi carriers. Full router manifests and certificate data
use bounded RAM FIFOs, with active transfers pinned until completion. Limits are
admission ceilings, not a promise that every radio topology is equally stable.
The earlier C5 hardware qualification covered three Wi-Fi and one BLE carrier;
the delivery smoke report records the final snapshot's tested combinations.

The C6 profile has a 160 KiB managed ceiling, one selected outgoing carrier,
64 lazily allocated verified endpoint summaries, and small public-key/cache
budgets. Its authenticated neighbour supplies the default next hop. It publishes
its own ordinary signed manifest and uses end-to-end TLS for incoming native
management, SensorLink and guest services. Remote service browsing and outgoing
VIP setup may defer or fail under bounded cache/handshake pressure; this does not
require special handling by the next-hop peer. A single native agent client is
supported alongside one guest flow in each direction. Cloud overlap is outside
the constrained profile's headroom qualification.

The actor owns mesh state and established TLS; one lower-priority worker owns
lent heavy cryptographic contexts. Disabling drains owned tasks and allocations.
Ephemeral peer records, keys, services and packet queues are RAM-only. Flash holds
explicit management settings, enrolled own identity/certificate material and
once-per-boot publication/time-floor metadata, never learned peer records.

## Guest publications

Service declarations belong to the running guest. The C replay helper and Swift
`Services` API retain desired intent in guest memory and replay it after mesh
returns. Nothing is retained in a host service registry while mesh is off.
The existing raw socket imports supply TCP/UDP data paths and support small
synchronous guests; async Swift is not required.
