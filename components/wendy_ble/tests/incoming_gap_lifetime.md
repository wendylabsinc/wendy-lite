# Incoming GAP selection leases

An incoming advertising connection can outlive a refused mesh CoC. In the C6
GAP3/transit trial one authenticated mesh carrier plus two channel-less incoming
connections occupied all controller slots. Physical info/status/SensorLink3 had
passed, but a later physical NET_SET2 could no longer connect. This was separate
from the prior TLS fragmentation/ACL retry findings and had ample free heap.

The physical advertising host now records incoming peripheral-role connections
in a fixed `CONFIG_BT_NIMBLE_MAX_CONNECTIONS` table. Read-only GATT metadata
activity renews a30s idle selection lease. The existing full-peer advertisement
host event expires a lease only when both physical and mesh channel ownership
probes confirm no claim. Physical lock contention and mesh unknown lifetime or
lock contention retain the connection. Every accepted/pending/closing mesh pipe,
including signed-time channels, claims its handle before authentication. A mesh
publication lifetime loan protects the probe against OFF freeing its mutex.

Termination remains pending until the host observes disconnect; that event
clears the slot before handle reuse. Host reset clears the registry. No Linux
Device1 global disconnect, channel rejection, extra task/timer or heap buffer is
introduced. This housekeeping has the same scope as the existing full-peer /
explicit-transit advertisement timer: mesh OFF, constrained scan-only operation,
stale identity and reset do not newly perform baseline idle cleanup. Active
physical management and shared channels retain their ACL irrespective of age.

Measured RV32 registry BSS is48B for the three-slot C6 profile (16B/slot). The
four-slot C5 compile fixture uses64B. No per-idle-node heap allocation exists;
this fixed physical-BLE bookkeeping persists while mesh is off.

`incoming_gap_lifetime_success_test.c` compiles actual physical host code and
covers ordinary refused/expired GAP reclamation, advertising recovery after
slot release, GATT-to-CoC selection, active/shared claims, OFF/current/reset and
handle reuse. `mesh_connection_claim_success_test.py` compiles the actual mesh
probe with normal pending/closing/time channel states, contention and publication
lifetime turnover. The BLE host suite and ASan/UBSan pass; actual C5/C6 physical,
L2CAP and mesh transport translation units compile with pinned SDK headers.
Hardware confirmation is a separate campaign step.
