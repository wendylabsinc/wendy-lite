# Reading Wendy Net topology

An enrolled Lite device can report its mesh connections, selected routes and
verified device announcements through its existing management connection.
Reading topology does not enable mesh or change its configuration.

## CLI and Wendy Client

Use a matching CLI and select the device through USB, BLE, LAN, Cloud or an
available mesh connection:

```sh
wendy --device wendy-lite:PORT device wendy-net topology
wendy --device wendy-lite:PORT --json device wendy-net topology
```

Replace `wendy-lite:PORT` with the selector shown by discovery. Cloud access
requires a profile with Cloud connectivity; the constrained C6 profile disables
it. A management connection must have full operator permissions. A device-role
SensorLink connection cannot read topology.

In Wendy Client, open **Networks**. The desktop combines available local, Cloud
and mesh reports; the browser uses authenticated Cloud devices. Both also show
devices learned through neighbours. A visible node therefore does not guarantee
that the client can connect to it directly. Reading a Lite report requires a
client version with WendyCom topology support.

C5 can report its routing state. C6 uses a single neighbour as its next hop and
keeps a smaller directory, so its report is explicitly **partial**. Missing remote
route details do not imply that the rest of the mesh is disconnected. An off or
unready mesh reports its state without inventing connections or routes.

A busy C6 can reject an additional management connection while its one native
client slot is in use, for example by SensorLink. Close the other client or retry
later. Networks can still show that device through its neighbours. Slow BLE
connections can take longer to read; the view retains previous observations as
stale when a refresh fails, rather than treating them as a healthy empty mesh.

## WendyCom API reference

`net_topology` is command 24, response 9. Replies use binary protobuf and contain
at most one metadata record plus a generation and opaque next cursor. Begin with
cursor and generation zero, then echo the returned generation and next cursor
until the next cursor is zero. A terminal reply has no record. A structural change
returns `BUSY`; discard collected rows and retry at most once. Ordinary counters
and timer updates do not invalidate a collection. Clients bound collection to
1,024 rows, 512 KiB and 60 seconds and preserve the `partial` indication.

`owner_role` distinguishes an enrolled device (1) from an operator router (2);
zero retains the original device encoding. `device` is an enrolled device UUID.
An operator instead has a case-sensitive `owner_principal` and sixteen-byte
`owner_instance`, its routing installation UUID. Its address uses the operator
allocation, `fd45:b891:5680::/48`. An operator identity is distinct from an
enrolled device identity. Next-hop device metadata names an actual neighbour.
A route without retained owner proof can report its address and routing metadata
without claiming verified ownership.

Public JSON adapters convert UUIDs and addresses to canonical text and represent
64-bit link, router and revision values as decimal strings. They do not expose
protobuf byte fields as base64. Certificates, signatures, keys and signed bodies
are not included in topology replies. `--observation` on the CLI adds a typed
result envelope for clients that need to distinguish partial or failed reads.

## Firmware ownership

The management task submits a bounded request to the mesh task; it never reads
mutable routing state directly. The mesh task captures one immutable row for
encoding. Timeout, shutdown and encoding failure release that row, and a pending
response keeps its memory owner alive until release. Reads while mesh is off do
not start its tasks or allocate a topology request.

Operator projection uses `wnrs_topology_operator_row` with a borrowed
`wnt_record_view`. Category 2 fills the verified operator owner for a selected
route; category 3 returns the indexed live operator announcement. It returns 1
for found, 0 for absent and -1 for unavailable and allocates nothing. Structural
generation hashing uses semantic fields, not pointers, padding or timer counters.
Principal strings use nanopb callbacks; only the selected operator row is copied,
with a 1,024-byte cap. Device proof expiry is bounded by both certificate and
manifest validity. These rules apply equally to full and partial reports.
