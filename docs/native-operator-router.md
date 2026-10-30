# Native operator router attachments

PSRAM full routers accept primary operators on the same LAN TLS listener and
BLE L2CAP PSM as enrolled-device carriers. TLS negotiates
`wendy-net-operator-router/1` for operators; enrolled devices keep
`wendy-local-mesh-ble/2`. This is a separately authenticated carrier role, not a
fallback to the direct WendyCom management service.

An operator must present a current, same-tenant primary client-auth certificate
chain anchored in the enrollment's independently configured trust. The device
rechecks the exact chain against its generation-bound signed-time snapshot.
A Lite authority twin or discovery advertisement grants no operator authority.
The post-TLS CBOR hello supplies a nonzero 16-byte installation ID; the principal
and installation remain typed operator identity, never a fabricated device UUID.

The framing matches the WendyOS operator broker: kind1 hello/ready, kind4 mesh
datagrams and kind5 length-prefixed mesh control. Lite does not expose WendyOS's
optional gRPC agent multiplexing on this carrier. Native management is reached
at its signed WendyCom endpoint through the ordinary routed IPv6 connection.

The attachment joins the existing Babel/gossip node and forwards device and
operator traffic. TLS and hello do not authorize an IP prefix: the existing
primary-signed operator manifest, independent origin proof, expiry, withdrawal
and reverse-path checks remain mandatory. Separate installations belonging to
one operator have separate addresses and topology rows. Carrier retirement
removes its link and releases its borrowed authenticated identity.

The PSRAM profile allows eight total authenticated or pending mesh connections,
shared by all roles, directions and transports. LAN may use that same total;
BLE retains its physical channel ceiling. The existing two-MiB allocation
ledger and serialized handshake admission still apply. Allocations are sparse;
eight is a resource ceiling rather than a reservation. Existing saved settings
are preserved; set `max-links` and `wifi-links` to eight to use the expanded
ceiling on an already configured board.

Constrained endpoints, endpoint gateways and boards without actual PSRAM do not
accept operator router attachments. In particular, C6 remains a leaf. PSRAM
routers advertise `operator_router=1` in LAN discovery; this is only a connection
hint. Clients must support the operator handshake and bootstrap from signed
routing state rather than requiring a first-hop WendyOS gRPC agent.
