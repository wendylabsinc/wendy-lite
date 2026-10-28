# Native actor and outer driver

One preemptible actor owns carrier, Babel, gossip and established TLS state.
The separate serialized crypto worker owns each lent heavy operation until
completion. All I/O readiness, timer waits and work completions belong to the
outer driver; the portable actor core performs no sockets/timers/tasks.
No delegated endpoint implementation or diagnostic task is part of this
runtime. Native/guest VIP adapters and persisted WendyCom settings use the same
bounded actor. Runtime remains OFF by default; no managed mesh task or heap is
retained while disabled.

The existing baseline server must register work_enable after it is ready and
poll CPU and I/O work for its lifetime; no extra I/O task is required. The new
driver must quiesce submissions, drain crypto, and wait actual task reaping
before closing/reopening the ledger. Typed management definitions have matching
nanopb/Go bindings. The public
management delegate activates the runtime only after its response crosses the
transport fence described in NATIVE_VIP.md.
