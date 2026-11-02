# Wendy Net peer state and signed sessions

This component implements the Lite mesh state machine, carrier framing,
Babel routing, certificate exchange and verified device/operator manifests.
Its outer driver supplies radio and socket readiness, timers and crypto job
completions. The state machine owns established TLS and service connections;
heavy cryptographic work runs on the separate serialized worker.

For configuration, firmware profiles and device limits, see
[Wendy Net on Wendy Lite](../../docs/wendy-net.md). For protocol state and cache
ownership, see [signed routing sessions](SIGNED_SESSIONS.md).

A complete device manifest carries services with one inherited lease. The
service helpers validate and project those fields; they do not create separate
signed service records, service gossip or an independent service cache. Keys on
the mesh are single characters; certificates, signatures, hashes and payloads
remain raw binary. JSON adapters serve only the existing local guest metadata
ABI and never carry binary certificate or mesh payloads.

Endpoint and verified-key projections grow on demand and remain bounded. The
endpoint cache retains up to 64 entries, replaces updates in place, reaps expired
entries on admission, and reuses the oldest allocation when full. The key cache
can lower its limit while preserving pinned next-hop keys. Certificate FIFO
admission skips active immutable loans, which remain valid and charged through
cache close until their owners release them. Empty stores reserve no payload
memory. Every peer object is RAM-only. Portable directory snapshot helpers are
for caller-owned RAM state in the same identity/trust epoch; firmware installs
no flash persistence path here.

Service schema validation matches WendyOS: lowercase dotted service/mesh labels,
compact TCP/UDP types, bounded TXT, and unique `(mesh, app, service)` identities.
A borrowed-span identity index grows only during validation, up to 3 KiB for
256 services, and is freed before return. It does not retain full service names
or allocate a maximum-sized table while idle.

The current Lite PKI verifies P-256 and ML-DSA-65 peer keys. It generates a
P-256 key for its own identity. ML-DSA-87 device-key authentication is unsupported
by that PKI ABI, independently of the CA signature algorithms accepted when
verifying a certificate chain. The format reader classifies a larger origin
signature as `WND_UNSUPPORTED`; a session must ignore that artifact rather than
close an otherwise valid carrier. WendyOS's broader verifier is unchanged.
Operators use their primary operator identity and a separate per-installation
routing identity. PSRAM routers verify and retain operator origins through the
same signed routing protocol; they are not synthetic enrolled devices. Constrained
C6 uses its authenticated gateway without an operator transit registry. There is
no special delegated leaf protocol or ALPN.

## Component tests

The standalone host suite reuses the real pinned PKI source and build-local
vendor patches. Configuration fetches esp-pqc at the revision in the PKI
component manifest. Resolve the managed cJSON component first:

```sh
cmake -S components/wendy_net_peer/tests -B build/peer-formats \
  -DIDF_COMPONENTS=/path/to/esp-idf/components \
  -DCJSON_ROOT=/path/to/espressif__cjson/cJSON
cmake --build build/peer-formats --target \
  format_device_dns format_directory format_key_fifo format_endpoint_cache \
  format_certificate_fetch format_certificate_store format_service_schema \
  format_certificate_fetch_budget format_service_schema_budget \
  format_manifest_interop
GOTOOLCHAIN=go1.27.3 ctest --test-dir build/peer-formats -R '^format_' \
  --output-on-failure
```

To use an existing esp-pqc checkout instead of fetching it, add
`-DFETCHCONTENT_SOURCE_DIR_ESP_PQC=/path/to/esp-pqc` when configuring.

The independent Go oracle signs P-256 and ML-DSA-65 native manifests and compares
C/Go encoded complete bodies exactly. ML-DSA-87 is checked only for unsupported
classification. The host suite checks formats and state-machine behavior. It
does not measure radio capacity or establish a supported hardware topology.
