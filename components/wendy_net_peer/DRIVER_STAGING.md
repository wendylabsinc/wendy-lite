# Mesh task and I/O driver

One preemptible task owns carrier connections, Babel, manifest exchange and
established TLS state. A separate, lower-priority crypto task processes one
heavy operation at a time. While a context is lent to that task, the mesh task
must not touch it; established connections using other contexts can continue.

The portable state machine performs no socket, timer or task operations.
Its outer driver supplies I/O readiness, timer deadlines and crypto completions.
Native and guest service adapters and WendyCom settings use the same bounded
runtime. It is off by default; disabling it releases its tasks and managed heap.

The existing management server registers `wendy_pki_work_enable()` when ready
and polls CPU and I/O work for its lifetime. Shutdown first quiesces submissions,
drains crypto and waits for actual task reaping before reopening the memory
owner. Settings that stop or restart the transport take effect after the
management response is sent, as described in [NATIVE_VIP.md](NATIVE_VIP.md).

For user configuration and resource limits, see
[Wendy Net on Wendy Lite](../../docs/wendy-net.md).
