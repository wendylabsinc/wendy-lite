# DER configuration snapshots

Configuration supplies `wendy_conf_copy_enrollment_der`, device-only and
time-only DER trust snapshots, configuration generation checks, bundle import,
and `pki_parse_certificate_bundle`. Native PKI and TLS consumers use DER directly.
The encoded `wendy_conf_copy_enrollment` API remains available for callers that
need the exact provisioned bytes. It does not require TLS to convert DER to PEM.

Every snapshot owns one allocation, freed by the caller with `free(storage)`.
Empty snapshots need no allocation. Selected trust bundles contain at most eight
concatenated complete DER certificate extents; PEM is decoded directly from the
mapped configuration at the import boundary. The signed-time seed is copied as
opaque bytes. Metadata callback fields are cleared. Partial snapshots import only
their selected domains, so time refresh does not decode device roots and service
TLS does not retain time/HTTPS material. Source SHA-256 hashes refer to the exact
provisioned device-root bytes, and are populated only when DER snapshots include
nonempty device roots. The legacy encoded API leaves new metadata fields zero.

DER generations identify the configuration cached during the copy in this boot. Any cache
invalidation, including an intervening configuration write, makes earlier
snapshots stale; their owned bytes remain valid. `wendy_conf_snapshot_current`
is a point-in-time check, not a lease against later writes. Callers coordinate
publication with configuration changes. All copy
outputs must be non-NULL and a prior snapshot must be freed before reusing its
output structure. Failed copies return empty data.

The bundle helpers validate framing and extents, not X.509 semantics or trust.
The direct parse helper appends to a caller-initialized Mbed TLS chain. Borrowed
DER must remain immutable and alive until that chain is freed. Copied DER and
PEM parsing retain their own certificate bytes; a PEM borrow request still copies
because its temporary DER import buffer is freed before return. The caller frees
the chain even after a partial parse failure and performs trust/usage checks.
Snapshot storage retains its `malloc`/`free` ownership contract. Parsed TLS and
crypto objects use the installed scoped allocator hooks; these are separate
allocation lifetimes.

PKI performs identity conversion, issuance and own-certificate DER caching.
Signed sessions use the once-per-boot publication allocator. Learned peer
material remains in bounded RAM; snapshots do not persist it.

Host integration lives in `tests/CMakeLists.txt`: `pki_configuration_persistence`
checks legacy/DER snapshots and `pki_der_bundle_import` checks direct parse and
copy/borrow ownership using existing certificate fixtures. Pinned SDK builds
compile the bundle helper in `wendy_conf` with a private Mbed TLS dependency and
the direct parser in the enabled PKI backend.
