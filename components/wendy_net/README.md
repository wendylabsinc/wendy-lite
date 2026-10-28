# WASM service endpoint browsing

The native `wendy.services_browse_endpoints` import takes the same arguments and
required-size convention as `wendy.services_browse`: service-type bytes and length,
output buffer and capacity, returning required JSON bytes excluding NUL. A result
greater than or equal to capacity means the output is incomplete. Negative
results indicate invalid input or temporary unavailability. An empty list is
`[]`. The host retains no guest pointers.

This operation returns verified endpoint projections without parsing or
decompressing full service records:

```json
[{"device":"00000000-0000-4000-8000-000000000004","host":"device-00000000-0000-4000-8000-000000000004.mesh.wendy.internal","appId":"com.example.sensor","serviceId":"temperature","type":"_sensorlink._tcp","port":28080,"generation":42,"expires":1790000060000,"detailsAvailable":false}]
```

These fields are retained from an independently verified publication. Results
still require a current lease, no withdrawal/unavailability and an origin made
ready by the existing nonce-bound inventory and routing checks. An inventory
advancing the generation invalidates the old endpoint projection until the new
body is verified. Reboot restores high-water receipts without live projections.

An app can match a type and attempt its normal connection using the returned
host/port even after that exact full blob was retired from the cache. This does
not bypass the ordinary encrypted app transport, live route or remote listener
checks. The projection cannot serve as a relayed origin signature.

`detailsAvailable` says whether the full body remains locally resident. The
existing full-record browse operation supplies signed-body fields including TXT
and instance strings when available; endpoint browsing does not invent those
fields or refill an evicted blob. Rich filters need selectively retained fields
or a newer publication. The current API returns a type-filtered snapshot;
pagination/interest subscriptions remain work for larger result sets so callers
do not need to allocate a complete large catalogue response.

## Publication intent across mesh OFF/ON

`wendy.services_epoch() -> i32` returns zero while the catalogue adapter is off,
otherwise a nonzero32-bit incarnation (interpret its bits as unsigned). A new
adapter after enable or configuration restart receives a new incarnation. A
nonzero token is not a promise of a live route: registration may still return
`-2` while the node is becoming ready. The token getter allocates nothing; only
a4-byte static counter remains outside the stopped runtime. All host mesh
registration/specification storage is released on OFF.

The Swift `Services` API retains desired declarations **inside guest memory**,
up to64entries/32KiB of declaration+ID bytes, plus bounded entry metadata.
`System.yield`, `System.waitForEvent` and `System.sleepMs` pump one declaration
at a time. Native checks/retries are limited to once per second per entry;
normal successful registrations are not resubmitted in the same incarnation.

```swift
Services.publish(serviceID: "temperature", type: "_sensor._tcp",
                 instance: "Kitchen temperature", port: 28080,
                 txt: ["unit=C"])
// The TCP listener must belong to this guest.
// Later, including while mesh is off:
Services.withdraw(serviceID: "temperature")
```

`publish` returning true means the guest retained desired intent. It does not
promise a signed publication or peer delivery. `lastResult(serviceID:)` exposes
the most recent native replay result; zero acknowledges the observed current
incarnation, `-2` means pending/OFF. Other native admission values are preserved.
After successful withdrawal it returns nil. Withdrawal immediately releases the
full declaration; its bounded service ID remains across OFF until a new ON
catalogue signs a fresh withdrawal. This also retires an unexpired publication
that another peer still holds, even when the new local catalogue has no row.
Stopping/replacing the guest releases its entire memory and closes its listeners.

C guests can include `wendy_services.h`, retain their own specification bytes,
and poll `wendy_service_replay_step` from their existing loop. Its state is
16bytes per desired publication; it allocates no host or guest payload storage.
Call `wendy_service_replay_changed` after changing a specification or before
withdrawing (pass the service ID and `withdrawing=1`). A successful native call
is acknowledged only when the incarnation is unchanged across the handoff.
An ordinary restart during the call leaves the intent pending for replay.

Identical normalized declarations for the same listener incarnation are a
host-side no-op. They do not dirty the record, advance its generation, postpone
its normal five-minute refresh, or trigger a new signature. A changed listener
or specification still creates the required new publication.

The raw `services_publish` ABI remains a one-shot registration in the current
host catalogue. Old raw callers must adopt the replay helper or explicitly
re-register after a new incarnation; firmware does not retain their forgotten
intent. There is no hidden OFF host registry, flash persistence, periodic blind
re-signing, or cross-thread entry into the guest.
