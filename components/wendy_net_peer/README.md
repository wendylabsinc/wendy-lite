# Native peer formats and signed sessions

This layer provides current-format CBOR, verified manifest/directory projections,
packet framing and bounded RAM certificate fetch/store/wire primitives. It
starts no radio or actor. [Signed sessions](SIGNED_SESSIONS.md) add bounded
routing, worker-backed certificate effects and complete-manifest projections.

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

The current Lite PKI verifies P-256 and ML-DSA-65 device keys. It generates a
P-256 key for its own identity. ML-DSA-87 device-key authentication is unsupported
by that PKI ABI, independently of the CA signature algorithms accepted when
verifying a certificate chain. The format reader classifies a larger origin
signature as `WND_UNSUPPORTED`; a session must ignore that artifact rather than
close an otherwise valid carrier. WendyOS's broader verifier is unchanged.
There is no delegated endpoint/leaf ALPN or operator-origin wire variant here.

The standalone host suite reuses the real pinned PKI source and build-local
vendor patches. Resolve the managed cJSON component and initialize esp-pqc first:

```sh
cmake -S components/wendy_net_peer/tests -B build/peer-formats \
  -DESP_PQC_ROOT=/path/to/esp-pqc \
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

The independent Go oracle signs P-256 and ML-DSA-65 native manifests and compares
C/Go encoded complete bodies exactly. ML-DSA-87 is checked only for unsupported
classification. These are component tests, not hardware or radio qualification.
