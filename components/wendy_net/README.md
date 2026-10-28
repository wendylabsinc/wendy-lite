# Guest networking and native mesh services

The guest socket API can connect to a verified mesh service using its canonical
`device-<uuid>.mesh.wendy.internal` hostname and port. The native mesh actor owns
its TCP/UDP VIP TLS context; the guest receives ordinary socket data. The remote
endpoint independently checks that the requested port belongs to a live guest
listener. Native WendyCom uses its signed agent endpoint and its own end-to-end
TLS session, with no additional WendyCom TLS wrapper.

## Browsing and publishing

`wendy.services_browse_endpoints` uses the same arguments and required-size
convention as `wendy.services_browse`: service-type bytes and length, output
buffer and capacity. It returns the required JSON byte count excluding NUL.
A result greater than or equal to capacity is incomplete; negative results
indicate invalid input or temporary unavailability. The host retains no guest
pointers.

An endpoint summary includes the device UUID, canonical hostname, app/service
IDs, service type and port, manifest generation and expiry, and a
`detailsAvailable` flag. Summaries originate in an independently verified router
manifest. Browsing requires a current manifest and usable authenticated route.
Endpoint projection retention does not retain a signed body for forwarding.
Full details can be evicted without automatically fetching that body again.
All active services share their router manifest's signature and expiry; there
is no separately signed service gossip stream.

The full browse operation includes instance/TXT fields when those details are
resident. Endpoint browsing does not invent missing details or decompress a
body. A guest can match a service type and attempt its ordinary encrypted
connection using a retained summary. Large-result pagination and interest
subscriptions remain future work.

`services_publish` and `services_withdraw` are one-shot operations on the current
actor-owned catalogue. Only the running guest's listeners can be published.
Identical normalized declarations for the same listener incarnation are a
no-op: they do not advance the manifest generation or cause a new signature.

`wendy.services_epoch() -> i32` returns zero while the catalogue adapter is off,
otherwise a nonzero 32-bit incarnation (interpret its bits as unsigned). The
getter allocates nothing. An enabled token does not promise that a route is
ready; registration can still return temporary unavailability. All host mesh
registration descriptions are released on OFF. A guest wishing to preserve
publication intent must retain it in guest memory and replay it when the epoch
changes. SDK replay helpers and management activation belong to the following
cutover layer.

## Raw sockets

The legacy numeric-address BSD socket imports support IPv4 and IPv6, explicit
nonblocking mode, bounded receive/send timeouts, local-port queries and errno.
The guest owns their descriptors; guest reset closes them. Blocking guest calls
wait in short slices so normal guest termination can unwind. These calls run in
the guest task and do not block the mesh actor. Mesh hostname translation is
provided by DNS resolution and the async guest connection API.

The generic legacy `tls_connect` import has no TLS implementation and returns
an error. Native mesh carrier/VIP TLS uses the implemented actor-owned paths.
