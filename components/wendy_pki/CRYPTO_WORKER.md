# Serialized crypto and retained context admission

This layer replaces the synchronous baseline facade with one optional
preemptible crypto worker and a one-item handoff. Baseline calls stay inline
until the mesh starts the worker. One callback owns a lent context at a time;
established I/O on unrelated contexts is not locked behind a handshake.
Retained handshake admission is separate from the CPU queue.

The later actor starts/stops this worker and binds itself as nonblocking; the
existing outer server adapter supplies I/O-worker polling when native consumers
are installed. This layer adds no active task while the native runtime is OFF.
Task reservations use the reviewed common task lifecycle helper.

The outer driver contract is:

1. The existing certificate-capable server calls `wendy_pki_work_enable()`
   when it can service both `wendy_pki_work_poll()` and
   `wendy_pki_io_work_poll()` outside its other handshakes. This registers a
   firmware-lifetime polling provider; it creates no task or request buffer.
2. The mesh actor calls `wendy_pki_work_start(wake)` and
   `wendy_pki_work_bind_actor()`. During dedicated operation only the crypto
   task polls CPU jobs. The server still polls I/O jobs, whose heavy TLS steps
   use `wendy_pki_work_run()`. Starting crypto alone never enables I/O requests
   without a real provider. Start may be retried after existing inline/fallback
   work completes. Repeating start is allowed only with the same wake function.
3. Before OFF the actor quiesces producers and stops lending new contexts,
   retaining every accepted context until completion. It polls
   `wendy_pki_work_stop()` until true while the server continues draining I/O.
   No new queue submission is accepted during this drain. Baseline synchronous
   waiters finish on the worker or their inline fallback after its retirement.
4. True means execution and the old completion wake are quiescent. Task memory
   is still charged until FreeRTOS idle reaps it. The outer driver waits for the
   common runtime ledger to drain before closing/reopening that owner. The
   registered server remains available for baseline polling after mesh OFF;
   without a registered server, the async APIs remain disabled.

The actor and crypto task cannot poll the potentially blocking I/O queue. A
callback may call nested CPU helpers directly from the crypto task; it must not
wait for a second queued callback. Context admission remains a separate lease:
one SRAM slot, or two mesh PSRAM slots plus one reserved for baseline callers.
Claim/transfer/release require exclusive ownership of that context and do not
make simultaneous access to a TLS object valid.

Static dispatcher state is small and does not grow with mesh size. Starting
the worker uses the accounted common task helper (default 10 KiB stack); no
worker or per-job allocation survives OFF. Existing baseline PKI uses the same
small synchronization state even while the mesh is disabled. Device heap and
radio qualification belongs to the final integration smoke test.
