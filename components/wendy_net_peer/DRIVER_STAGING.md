# Native actor and outer driver

One preemptible actor owns carrier, Babel, gossip and established TLS state.
The separate serialized crypto worker owns each lent heavy operation until
completion. All I/O readiness, timer waits and work completions belong to the
outer driver; the portable actor core performs no sockets/timers/tasks.
No delegated endpoint implementation, operator proof or diagnostic task is
part of this layer. VIP adapters and persisted settings are explicitly inactive
until their separate delivery layers. Runtime remains OFF by default.

The existing baseline server must register work_enable after it is ready and
poll CPU and I/O work for its lifetime; no extra I/O task is required. The new
driver must quiesce submissions, drain crypto, and wait actual task reaping
before closing/reopening the ledger. Schema definitions are introduced here as
typed driver contracts; every existing nanopb/Go binding must regenerate in
this same branch before acceptance. Supported management delegates join last.
