# Recover full-peer management advertising after controller pressure

A normal C6 transit boot accepted an incoming mesh GAP while an outgoing setup
was retiring. Restarting the shared connectable advertisement returned controller
0x207 (memory capacity). The outgoing connection then closed via its different
callback, leaving the healthy one-carrier node permanently unadvertised. This
blocked physical management before TLS; it was not a certificate/heap failure.

Full-peer mesh advertisement rotation already has a500ms timer posting to the
NimBLE host queue. When advertising is inactive, that event now retries the
existing start path, preserving boot identity/current/reset guards. A blocked
attempt changes this same periodic timer to5s; successful recovery restores500ms
payload rotation. There is no new task, timer, allocation or persistent state.
Known host/controller capacity errors are quiet for these retry calls; the
original failure remains logged. SDK HCI diagnostics are bounded to one attempt
per5s while full. No private SDK count/HCI query is introduced, because a public
connection count does not capture pending GAP/controller activity reservations.

The cost is up to5s recovery latency after capacity becomes available. This is
advertising recovery only, not a timed eligibility gate for peer candidates.
Normal active advertising receives no extra start calls. OFF deletes the mesh
rotation/retry timer; late/current-identity/reset checks prevent resurrection.

The fixture compiles the actual BLE transport, injects ordinary transient
controller capacity, releases it on the alternate-owner path, then checks the
same timer recovers advertising and restores its period. It also checks no
active-advertising retries and ordinary OFF/current/reset behavior. Normal and
ASan/UBSan advertising/dispatch regressions remain enabled. This increment
covers full-peer/transit modes with this existing timer; it does not claim a
new recovery path for constrained modes without mesh advertisement rotation.
