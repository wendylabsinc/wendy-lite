# Experimental signed mesh leaf

Wendy Lite can join a Wendy local mesh as an IPv6 endpoint through one explicitly
configured peer over Wi-Fi TCP, BLE L2CAP, or ESP-NOW. The build is opt-in and limited to native ESP32-S3
profiles with PSRAM. The Seeed XIAO ESP32S3 profile compiles with ESP-IDF 6.0.3.
The BLE image boots on an ESP32-S3 DevKit with 8 MB PSRAM and starts its L2CAP
listener. An authenticated mesh connection has not yet been verified on hardware. Other targets, boards
without PSRAM, WASM profiles and IPv6 forwarding are excluded by Kconfig.

The leaf uses its existing Cloud enrollment, P-256 device key, device certificate,
tenant trust roots and signed-time authority. Both device and tenant IDs must be
canonical UUIDs. Updated firmware reports `uuid_enrollment_supported` over USB;
the matching CLI assigns a new UUID during enrollment. Older `lite-<hardware-id>`
identities require explicit unenrollment and re-enrollment before joining this
mesh. Flashing firmware preserves the existing enrollment. The mesh never enrolls
a device or changes its membership. A matching
Linux agent with the opt-in `leafListen` adapter is required. Its implementation
is tracked in [WendyOS PR 2376](https://github.com/wendylabsinc/WendyOS/pull/2376).

## Endpoint behavior

The leaf's address is `fd45:b891:567f::/48` followed by the final 80 bits of its
device UUID. A point-to-point lwIP interface carries TCP, UDP and ICMPv6 to
authorized mesh addresses. The leaf advertises only its own exact `/128` and
does not forward packets for other devices. It has no Internet donor role.
IPv6 extension headers, IPv6 fragments, raw IPv4 and IP-in-IP are unsupported.
The MTU is 1320 bytes; the carrier can split one packet into two bounded frames.

The existing WendyCom/SensorLink listener becomes dual-stack when this profile
is enabled, so its existing authenticated service on port 5054 can accept the
mesh IPv6 address. Native applications can also bind IPv6 sockets. Service
authorization stays in the existing application protocol. This is raw IP
endpoint support; it does not implement Linux mesh application QUIC, the Linux
application catalog, or the topology gRPC service on Lite. A router can report
the leaf's signed announcements to the mesh visualizer. A direct topology
snapshot from Lite remains unsupported.

## Authentication and route leases

Each endpoint pins its peer's full same-tenant SPIFFE device principal.
IP, Bluetooth and station MAC addresses are dial addresses, not identities.
TCP and BLE leaves are TLS clients. One ESP-NOW endpoint is a TLS server.
TLS 1.3 verifies both certificate chains with ALPN `wendy-local-mesh-leaf/3`.
Session tickets, resumption, PSK and 0-RTT are disabled. The separate carrier
does not alter or fall back to the existing `WMT1` TCP/QUIC carrier.

Each announcement uses the production version 3 manifest format. A P-256
signature covers SHA-256 of `wendy-local-mesh/manifest/3`, a zero byte, a
four-byte big-endian length of the canonical full SPIFFE principal, that
principal, and the exact JSON body. Version 1/2 proofs and version 2 carrier
handshakes are rejected. The body binds the device UUID, exact prefix, router ID, Babel
sequence number, revision, issue time and expiry. `Issued` and `Expires` are
Unix milliseconds. Revisions and router IDs use exact decimal uint64 values;
they never pass through a floating-point representation.

The leaf renews a 60-second lease every 20 seconds. Remote leases may last at
most 120 seconds and may be issued at most five seconds into the verified
future. A certificate's effective expiry includes every issuer and the trust
anchor. No lease can extend past that expiry. The leaf independently verifies
each remote device's certificate and signature, even when the router relays it.
Duplicate proofs do not extend a lease. Older or expired proofs are ignored;
invalid signatures and conflicting bodies with the same revision close the
carrier. Two live device claims for the same derived address authorize neither
owner. A remote claim colliding with the leaf's own address is rejected.

Local revision ranges are committed to NVS before the first signature. A range
contains 1024 revisions. Reservation happens after successful pinned TLS, so
failed or unauthenticated router dials do not consume revision writes.

## Startup delay and bounded receipts

There is a **125-second IP quarantine** after the first fresh signed-time reply
on each boot, and after a tenant, device or trust-root change. Announcements can
be exchanged during this interval, but incoming and outgoing IP are blocked.
The delay covers the maximum accepted lease plus future clock skew. It prevents
a router from replaying a pre-boot, superseded proof after the RAM-only receive
history has been lost. This is a deliberate availability cost of this profile.

Ordinary reconnects retain revision history and the quarantine deadline.
Fresh signed-time replies cannot move the proof clock backwards. Forward
corrections can shorten active leases but never extend them. The leaf requires
a fresh nonce-bound signed-time reply for every connection and reconnects after
at most five minutes. The persisted wall-clock floor is insufficient to enable
mesh. If the signed-time service is unavailable, the mesh remains unavailable.

The remote directory retains at most 32 distinct device identities per trust
epoch, including expired or withdrawn identities. It never evicts replay
receipts to admit a new identity. Additional valid identities and their proofs
are ignored without disconnecting existing peers; they remain unreachable from
this leaf. A reboot or a changed enrollment/trust epoch clears the directory
and starts the full quarantine again. This is an experimental fleet-size limit.

## Configuration and build

On the Linux router, add `"leafListen": "0.0.0.0:43024"` to its existing
`local-mesh.json`. Preserve its other configured carriers and peers. The Linux
adapter is explicit and does not discover or configure leaves automatically.
The TCP port must be reachable from the leaf's Wi-Fi network.

Create a local `mesh.defaults` with the actual router address and enrolled UUID:

```ini
CONFIG_LWIP_HOOK_IP6_ROUTE_CUSTOM=y
CONFIG_LWIP_IPV6_FORWARD=n
CONFIG_WENDY_MESH_LEAF=y
CONFIG_WENDY_MESH_TCP=y
CONFIG_WENDY_MESH_ROUTER_HOST="192.0.2.1"
CONFIG_WENDY_MESH_ROUTER_DEVICE="12345678-9abc-4def-8123-000000000001"
CONFIG_WENDY_MESH_ROUTER_PORT=43024
```

The example address is a documentation address. The custom IPv6 route hook is
a prerequisite, selected under the lwIP hooks menu before enabling the mesh
option. Use a fresh sdkconfig so previous choices cannot mask these defaults.
After initializing the repository's nested submodules, build without flashing:

```sh
idf.py -B build-mesh-s3 -D SDKCONFIG=sdkconfig.mesh-s3 \
  -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;boards/seeed_xiao_esp32s3_native.defaults;mesh.defaults' \
  -D IDF_TARGET=esp32s3 build size
```

The equivalent container is `espressif/idf:v6.0.3`. Keep `mesh.defaults` local;
this change does not add mesh to the firmware catalog or existing OTA profiles.
The default build leaves the feature disabled.

## Memory and outstanding hardware validation

The shared protocol state remains below 128 KiB.
That includes a 64 KiB control buffer, 32 KiB certificate decode workspace,
32 origin receipts, one packet assembler and a four-packet output queue. A
compile-time assertion caps the state below 128 KiB. The worker has a separate
32 KiB task stack. ESP-NOW adds a 64 KiB PSRAM receive window and a
bounded 16-datagram callback queue. The window lets both endpoints send their
certificate bundles before reading without deadlocking. Startup requires enough free PSRAM for the state plus
512 KiB of remaining headroom for TLS, X.509 and other work. That admission
check is not a measurement of peak TLS memory use.

The validated XIAO image occupies about 1.31 MB of its 3.81 MiB application
slot. Peak heap use, stack high-water marks, concurrent SensorLink load, packet
loss, Wi-Fi reconnection, and lwIP callback lifetime across reset still require
hardware tests. No throughput or support claim is made for other boards.

Mesh connection setup currently holds the existing PKI identity mutex while
obtaining signed time and opening the router connection. An unreachable router
or time authority can therefore delay other identity operations. TCP/TLS setup
has a 15-second deadline after DNS. Radio TLS has a 30-second deadline.
HTTP and DNS have their own limits, so there is no single end-to-end bound. Established carrier reads and writes
have 30-second deadlines and check reset state. This latency needs hardware
validation before unattended deployment.

## Wire framing and tests

The untrusted preface is `WML3`, 16 raw tenant UUID bytes, and 16 raw device UUID
bytes. TLS follows. The bootstrap hello is a four-byte big-endian JSON length
and the existing version 3 hello, with MTU 1320 and datagram limit 1100. Later
frames use a one-byte kind and a four-byte big-endian payload length. Kind 1
contains a control message including its inner four-byte JSON length. Kind 2
contains an existing Babel datagram or IP fragment. Control JSON is bounded to
64 KiB, 160 tokens and depth eight; certificate bundles contain at most eight
certificates and 32 KiB of DER. One fragmented packet may be pending for at
most two seconds.

The native host suite uses the production parser, certificate verifier, TLS
client and server over fragmented stream callbacks, signature helpers and identity persistence code. It requires Go 1.27
or newer and the dependencies described in
[the PKI test instructions](../components/wendy_pki/tests/README.md):

```sh
cmake -S components/wendy_pki/tests -B build-pki
cmake --build build-pki -j 8
ctest --test-dir build-pki --output-on-failure
```

The `mesh_*` tests cover exact uint64 encoding, framing, replay, equivocation,
expiry, collisions, trust changes, the quarantine, backward/forward clock
corrections, revision persistence failures and real Go-to-C TLS. TLS tests
reject wrong router, tenant, ALPN, expired certificates and TLS 1.2. A real
certificate fixture reuses the same key and UUID under another tenant; the
relabeled old proof fails while a new proof signed for that tenant succeeds.
Another fixture verifies an early-expiring intermediate without treating an
unrelated retired root as part of the verified path. The Linux
adapter's `TestLeafCManifestInteroperability` accepts the C fixture tool through
`WENDY_LITE_FIXTURE_TOOL` and checks C-generated signatures with the production
Go verifier, including tampering and restart replay. Its separate Linux
namespace test covers TLS, Babel and TUN routing with a synthetic leaf. Neither
test substitutes for running the C lwIP interface on a physical board.

## BLE without access-point association

Choose `CONFIG_WENDY_MESH_BLE=y` instead of TCP, enable
`CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM=2` and
`CONFIG_BT_NIMBLE_MSYS_1_BLOCK_SIZE=256`, and set
`CONFIG_WENDY_MESH_BLE_PSM=129`. Keep `CONFIG_WENDY_BLE=y` and
`CONFIG_WENDY_WIFI_ENABLED=y`. The latter initializes lwIP; BLE mesh starts
even when there are no Wi-Fi credentials and no access-point connection.
The mesh PSM must differ from the management PSM, which defaults to 128.
The mesh owns a separate channel, receive ring and buffer pool.
Its 240-byte SDU limit keeps NimBLE's receive grant at one packet per armed
buffer, so a full receive ring can stop incoming traffic without overrunning
the channel. Larger TLS records and IPv6 packets span multiple SDUs.

Set `CONFIG_WENDY_MESH_ROUTER_DEVICE` to the Linux router's enrolled UUID.
The host and TCP port settings are unused for BLE. Add this to the router's
existing `local-mesh.json`, using the actual ESP32 identity and Bluetooth address:

```json
{
  "leafBLEPeers": [{
    "device": "12345678-9abc-4def-8123-000000000002",
    "address": "80:45:6b:00:00:01",
    "addressType": "public",
    "psm": 129
  }],
  "leafTimeURL": "https://your-enrolled-timestamp-authority.example/timestamp"
}
```

Replace the example URL with the timestamp URL in the leaf's enrollment.
The router must trust its HTTPS certificate through the system trust store.
The Linux agent needs this branch's BLE leaf provider, Bluetooth hardware and
permission to open LE L2CAP sockets. It dials up to eight explicitly configured
leaves, with one retry worker per leaf. Rotating Bluetooth addresses and
automatic discovery are not implemented. A running carrier worker does not
mean its peer has authenticated; inspect the live mesh links.

BLE here is an encrypted point-to-point carrier into Wendy's signed mesh.
It does not implement the Bluetooth SIG Mesh provisioning or flooding protocol.

## ESP-NOW between ESP32s

On both enrolled ESP32-S3 boards, select `CONFIG_WENDY_MESH_ESPNOW=y`, set
`CONFIG_WENDY_MESH_ESPNOW_PEER` to the other board's station MAC, and pin
its UUID with `CONFIG_WENDY_MESH_ROUTER_DEVICE`. Set the same
`CONFIG_WENDY_MESH_ESPNOW_CHANNEL` on both. Enable
`CONFIG_WENDY_MESH_ESPNOW_SERVER=y` on exactly one board.

The responder needs Internet access for signed time. Its AP must use the
configured ESP-NOW channel. The other board can run without AP credentials.
The implementation refuses to retune an associated Wi-Fi link. Stored Wi-Fi
credentials are preserved; an ongoing or failed AP connection attempt is not
overridden by the radio carrier. Clear unwanted credentials through the normal
configuration workflow before testing a radio-only endpoint.

The transport uses unicast datagrams of at most 250 bytes for ESP-NOW v1
compatibility. A 25-byte header leaves 225 bytes for stream data. Each direction
has one unacknowledged datagram, a random 64-bit connection epoch and a 32-bit
sequence number. Retries occur after 150 ms; a missing ACK closes the stream
after five seconds. Duplicate data is acknowledged without being delivered
twice. A full receive window withholds ACKs. Frames from a different connection
epoch cannot acknowledge or append to the current stream. TLS protects the
contents and identity; ESP-NOW link-layer encryption is not required.

This is a direct two-endpoint link. Lite does not forward packets for a third
ESP32. Each build selects one mesh carrier and one pinned peer; simultaneous
links, automatic carrier failover and ESP-NOW route discovery are not implemented.
Wi-Fi TCP remains the default mesh carrier.

## Signed time over radio

Before TLS, the radio client sends `WMT3`, a four-byte big-endian request length,
and a nonce-bound RFC 3161 timestamp request of at most 128 bytes. The peer
forwards it only to its configured timestamp authority, without forwarding
credentials or accepting a URL from the client. It returns a four-byte length
and at most 64 KiB of response. The client accepts a reply only within 30
seconds. Stream reads and writes have deadlines; DNS and HTTP on an ESP32
responder retain their existing timeout limits.
The client verifies the authority's signature, its nonce and its persistent
clock floor before using the response. A router-provided wall clock is never
trusted. The normal `WML3` preface and mutually authenticated TLS follow.

An ESP32 responder also obtains its own fresh signed time before TLS. Therefore
two entirely offline boards cannot start this profile. Existing enrollment and
certificates are required; radio mesh does not provide enrollment or renewal.

The host tests exercise stream TLS client/server authentication, relayed time
bounds and rejection, and ESP-NOW loss, reordering, duplicates, backpressure,
stale epochs and stalled ACKs. Wi-Fi, BLE and ESP-NOW firmware variants compile
for the 8 MB PSRAM ESP32-S3 DevKit with ESP-IDF 6.0.3. Actual radio throughput,
coexistence, heap peaks and reconnection still need a two-device hardware test.

For the tested DevKit memory configuration, copy and edit one carrier example
under [mesh-examples](mesh-examples/). Use the actual peer UUID, dial address
and, for ESP-NOW, radio channel. Start with a fresh sdkconfig for each carrier:

```sh
idf.py -B build-mesh-ble -D SDKCONFIG=sdkconfig.mesh-ble \
  -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;docs/mesh-examples/devkit-8mb.defaults;mesh-ble.defaults' \
  -D IDF_TARGET=esp32s3 build
```

Here `mesh-ble.defaults` is your edited copy of `mesh-examples/ble.defaults`.
The example memory profile is unsuitable for boards with a different PSRAM
interface or flash capacity.
