# Wire protocol compatibility

Wendy Lite protocols evolve independently. Add optional fields and message types
within an existing protocol version when an older peer can safely ignore them.
Change the specific protocol's version, magic, service identity or negotiated
ALPN when interpretation of existing bytes or required semantics changes. A
change to one family does not require a mesh-wide version bump.

## Rules for protocol changes

- Keep existing field numbers, names, enum meanings and binary offsets stable.
  Never reuse a removed protobuf field number or an assigned message type.
- Read known JSON/CBOR map members by name and ignore unknown optional members.
  Retain validation of required members, identities, signatures and bounds.
  For the mesh CBOR profile, extension values use definite maps/arrays, text,
  byte strings, integers, booleans or null; tags and floating-point values are
  not part of that profile. Extension values stay inside encoding/resource limits;
  an unknown field is not permission to exceed message, depth or memory bounds.
- Drain a length-delimited unknown frame before reading the next frame. Ignore
  unknown optional messages and operations without changing state or satisfying
  a pending operation. A request for an unknown command may receive a bounded
  unsupported-command result. Required initial handshakes remain required.
- Treat an unfamiliar enum or capability as unsupported, rather than mapping it
  to a known action. Advisory capability bits may be ignored. Required extension
  declarations must be understood before using the object.
- Reject an unsupported version at that protocol's boundary. Do not interpret
  new-version bytes using the old layout or treat an unsupported version as an
  empty successful response. Supporting several versions requires explicit
  selection or fallback; the presence of a version marker alone is not fallback.
- Preserve signed bytes exactly. Ignoring optional members during interpretation
  must not change the bytes covered by a signature or make an unknown required
  extension optional. Retain the original complete artifact envelope for gossip
  hashes, caches and retransmission; re-encoding only known members would lose
  unknown optional envelope metadata and change the artifact identity.

Compatibility tests should send a future optional field or message followed by a
known message, verify that the known message still works, and verify that the
ignored message did not change state. Keep rejection tests for missing required
fields and incompatible versions alongside those tests.

## Protocol boundaries

| Family | Version or narrow wrapping scope | Evolution boundary |
| --- | --- | --- |
| Serial mode selection and DLE escaping | Two-byte DLE command namespace; `m` selects WendyCom | Unknown commands are ignored. Console and echo are opaque byte streams. New structured management stays inside the selected WendyCom handshake. |
| WendyCom link framing | Magic `A5`, frame version `2`, category/channel and 16-bit body length | Known version establishes header layout. Future categories can be drained by their stated length; an unsupported header version is rejected. |
| WendyCom commands, responses, events and channel services | Required major/minor handshake; current major `2`; TLS management uses `wendy-com/2` | Protobuf field numbers and oneof tags provide additive extension points. Unknown fields and optional variants do not become another known command. Major changes require a new handshake major. |
| Configuration, app transfer, console, topology and radio settings | WendyCom 2 command/event scope | These protobuf payloads share management negotiation. Console/app bytes are opaque; command-specific required fields/presence still apply. Restricted Wi-Fi-only configuration rejects unknown root fields instead of applying an unrecognized configuration action; nested optional fields remain extensible. Topology readers omit unsupported future record kinds and owner roles before interpreting current row fields and mark the resulting view partial. |
| SensorLink catalogue, subscriptions, data and ping | WendyCom 2 envelope; each generic sensor descriptor names its own schema such as `wendy.temperature.celsius.f32le.v1` | Protobuf additions are optional. A new sample layout needs a new schema identity; receivers must not decode an unknown schema as a known sample. |
| Development Cloud gRPC relay | `WendyComRelayService.WendyComRelay` RPC identity; payload carries a separate WendyCom 2 handshake | Required initial Open selects the channel. Unknown later protobuf variants are ignored. Incompatible relay control needs a separately named RPC/service; it is not implied by the enclosed WendyCom version. |
| Native carrier stream | `wendy-local-mesh-ble/2` ALPN; router hello version `1`; operator uses its own router ALPN | Five-byte kind/length framing scopes router control and IP fragments. Unknown bounded frame kinds can be drained. A changed frame header needs a new carrier protocol selection. |
| Operator-router admission | `wendy-net-operator-router/1` ALPN and typed hello/ready messages | Required hello/instance and ready stay mandatory. Optional map fields can be ignored; a new mandatory exchange needs a new selected operator protocol. |
| Router control messages | Current carrier/operator protocol plus `kind` discriminator | Unknown kinds are optional and ignored. Hello remains mandatory; its version, authenticated identity, MTU and datagram limits must be understood. |
| Gossip HAVE/WANT/DATA/UNAVAILABLE/GONE | Per-message `v=1`, object type and operation under router control; no independent version-range negotiation | Unknown operations and unassigned artifact types under v1 are ignored before variant payload decoding. WendyOS rejects unsupported versions of known formats; Lite discards them. Registered Service type 2 remains a known wrong-session error on WendyOS manifest-only links. Current senders use v1; known transfers retain digest, offset, total and bounds checks. |
| Signed device/operator manifests and embedded services | Manifest body `version=4`, signature envelope and required-extension declaration | Optional map members/capabilities can be ignored. An unsupported optional endpoint transport or service kind is omitted from local projection; known sibling entries, route proof and the original artifact remain usable. Unsupported body versions and required extensions do not establish routes or services. Signature verification always uses original bytes. |
| Manifest/identity requests, directory results and certificate chain/chunk transfer | Named router-control kind under the selected carrier/operator protocol | Unknown optional operations and fields do not complete a pending fetch. Known replies retain principal/hash/offset/length validation. Certificate payload is standard DER. |
| Legacy time relay codecs | Nested time-control `v=1` (absent/zero means legacy 1); obsolete one-shot framing uses `WNT1` magic | Production mesh drivers neither request nor serve peer timestamp relays and do not register the BLE time PSM or app time service. The retained codecs are compatibility helpers, not an available relay transport. Public RFC 3161 requests use ordinary direct HTTPS. |
| Babel routing | Babel packet version 2 and length-delimited TLVs/sub-TLVs | Unknown optional TLVs are skipped; mandatory sub-TLV semantics and required route proof remain enforced. No arbitrary packet tail is interpreted as an old TLV. |
| Mesh IP packet fragments | Fragment subtype `1`, carried inside a selected carrier's packet frame | Fixed fragment offsets are scoped to subtype 1 under the carrier protocol. Unknown subtypes are discarded without changing current assembly. Subtype 2 carries Babel; IPv6 retains its own standard version. |
| Native TCP application admission | `wendy-app-mesh-tls/1` plus `WAS1` request magic | Fixed port request and acknowledgement are narrow admission metadata. A different admission layout needs new magic/protocol selection. After admission the TCP stream belongs to the application. |
| Native UDP application admission and records | `wendy-app-mesh-tls/1` plus `WAU3`/`WUA3` magic and negotiated datagram maximum | Admission is fixed and versioned; each subsequent datagram has a length. Datagram bytes are application-owned, not new mesh control messages. |
| BLE mesh discovery | ServiceData AD field version 1, scoped by tenant/service UUID and network hint | Unknown AD types, independent unknown-version ServiceData and advisory capability bits are ignored. Version 1 accepts a stable known prefix plus bounded trailing optional bytes. TLS provides the full identity afterward. |
| NAN presence | `WNAN`, version 1 and tenant/network scope; optional WFA service envelope | Unknown versions are ignored. Version 1 accepts its stable prefix plus bounded optional bytes and ignores advisory flag bits; required mesh support stays mandatory. Hints do not authorize identity or routes. |
| GATT management discovery | Named GATT service/characteristic UUIDs; BLE/GATT handles and lengths | Unknown characteristics are ignored. A changed characteristic layout can use a new characteristic UUID; the selected management channel still performs WendyCom negotiation. |
| mDNS management, carrier and projected application endpoints | DNS-SD: mesh `_wendy-net._tcp` TXT `version=1`/`protocol=tls-v1`; management `_wendy-lite._tcp` negotiates WendyCom; projected apps name their service type | Unknown TXT keys and unrelated records are ignored. Discovery advertises endpoint hints; connection and signed-manifest validation determine capability and identity. Application TXT belongs to its advertised service. |
| Cloud control, relay grants and acknowledgement | ASCII `WR` + version byte `0x03` + opcode, `WLG3` signed grant, `WLA2` acknowledgement | Version-3 Cloud opcodes have opcode-specific sizes without a general unknown-body length. Unknown opcodes close the control connection for normal reconnect; they cannot be safely skipped. New incompatible grammar needs a new selected record version. Signed-grant fields remain exact. |
| Enrollment and identity renewal | Configured, validated `/v1/` enrollment API; HTTP content types and headers | JSON readers use named response members and ignore unrelated fields/headers. A changed required API contract needs a new endpoint version. X.509/DER certificates and PKCS requests retain their standard formats. |
| Native TLS, issuer-cache hints, timestamping and HTTPS | Native PKI TLS 1.3; exact application ALPN; issuer-cache `WCI` v1 hints and named `wendy-net-cached` offers; RFC 3161 and HTTP | TLS/HTTP/DER framing is library-owned; the issuer-cache ALPN suffix is scoped by `WCI` version 1 or the separate `wendy-net-cached` marker name. Unknown or unusable hints fall back to the ordinary certificate exchange; no hint grants identity. Application protocol versioning remains separate. The development gRPC relay uses its own TLS configuration, which permits TLS 1.2 or later. |
| DNS bootstrap and direct timestamp HTTPS | Standard DNS query/response fields and RR `RDLENGTH`; ordinary HTTPS/TLS to the configured timestamp authority | Unknown DNS RR types are skipped by their lengths while known answer fields remain checked. Direct timestamp traffic retains TLS, HTTP and RFC 3161 framing; no peer timestamp tunnel is started. |
| Korvo benchmark serial JSON | Per-record `version=1`; absent version means legacy version 1 | Unknown record versions, test names and optional targets are ignored. Required known qualification results still must be present and successful. Extra object members are ignored. |

## Manifest lifetime policy

The signed device/operator body remains version 4, with the same signature
preimage and exact-envelope artifact digest. A receiver validates the signer
under its local certificate policy. Signed `Issued` must be at or after the
signing leaf's `NotBefore`; signed `Expires` must not exceed the earliest
`NotAfter` on the accepted path. Issuer validity is independently checked at
the receiver's certificate-policy base time. The positive signed
`Expires - Issued` duration, at most 15 minutes, sets a local monotonic lifetime
from first acceptance. Announcement UTC dates are metadata, not proof of the
receiver's current time.

Same-revision/body duplicates, including certificate re-signing, never restart a
lifetime. Lower revisions are ignored; a different body at the same revision
is rejected. A higher revision starts a new lifetime. Expiry actively removes
full payload, gossip/export and foreign service projection state and revokes
route authorization during idle maintenance. Local desired app declarations
remain for republishing, while the expired signed publication is no longer
browseable. A compact highest-revision/hash receipt remains for ten times that
revision's signed duration from first acceptance, without extension by repeated
copies. Receipts grow on demand in RAM and expire separately from payloads;
allocation failure must not erase an existing receipt to admit new state.

The TTL does not extend certificate trust. A trusted public-time update or known
certificate/issuer-window invalidity revokes active claims, gossip copies and
derived service state early, preserving their original receipt deadlines.
Missing cached keys and temporary repair failures do not by themselves prove
that an identity is invalid.

Receipts survive carrier changes within the mesh epoch. They are not persisted
on Lite and are cleared on mesh OFF, enrollment/trust reset or reboot. After a
receipt expires, a first-seen old record may live for one new local lifetime
if its signer still passes current certificate checks. This deliberately permits
stale discovery/routing metadata while
retaining independent live-link, endpoint TLS and operation-permission checks.

This policy introduces no new wire message or origin-confirmation exchange.
Legacy readers retain UTC freshness checks and can reject clock-uncertain
bootstrap records. Clock-independent bootstrap requires updated receivers; an
unchanged body version does not imply legacy receivers adopt the new lifetime
policy. Mesh certificate boot trust is distinct from fresh public timestamp
confidence and does not relax Cloud or direct LAN management time checks.

## Opaque data and local APIs

Raw TCP/UDP, UART, SPI, I2C, USB CDC, BLE GATT values, console bytes and published
application TXT/data belong to the guest or external device protocol. The host
carries them without assigning a Wendy Net message type or inserting a version
byte. Applications choose their own versioned service/schema/characteristic.
The Swift and Rust SDKs expose the same byte APIs; they add no network codec.

WASM imports, callback queues, guest service declaration JSON, persisted settings,
AOT/OTA images and flash partition headers are local ABI/storage formats, not
additional mesh wire envelopes. Their existing validation and lifecycle rules
still apply. A guest service declaration becomes a versioned signed manifest
before distribution; strict diagnostics in the local declaration API do not
make the remote manifest map closed to extension.

The OpenTelemetry host exports keep metrics/spans in memory and emit log text;
there is currently no OTLP network exporter in this stack. Mosaico diagnostics
and example chat/UDP programs emit application/debug text, not a Wendy Net
control protocol. Standard USB, BLE, DNS, Wi-Fi, IPv6, TCP, UDP, HTTP and TLS
headers remain the responsibility of their respective SDK implementations.

Implementation entry points: [management schema](../components/wendy_com/proto/wendy_com_msg.proto),
[SensorLink schema](../components/wendy_com/proto/sensorlink.proto),
[relay schema](../go/proto/wendy_com_relay_service.proto),
[mesh codecs](../components/wendy_net_peer/src),
[Babel codec](../components/wendy_babel/src/wire.c),
[PKI and TLS](../components/wendy_pki/src), and
[benchmark reader](../tools/korvo_benchmark.py).
