# Physical BLE native handshake dispatch

An enrolled physical BLE session must start on `wendy_pki_io_work_submit`, the
existing certificate-capable native server stack. Its TLS crypto steps still use
the CPU worker. It must not itself occupy the CPU queue while awaiting retained
workspace admission or network input. No new task or TLS/auth policy is added.

The previous dispatcher used `wendy_pki_work_submit`; the later native preparation
helper intentionally rejects callers currently executing that CPU queue. This
made every enrolled physical BLE session immediately fail at native workspace
admission. A normal C6 no-radio GAP2 capture reproduced this with108,680 bytes
free/92,160 largest: this failure was not caused by insufficient heap. The guard
remains in place; the dispatcher is corrected instead.

The positive host dispatcher fixture compiles the actual BLE coordinator and
production CPU/I/O queues, verifies native admission from the I/O callback while
an independent CPU job remains queued, verifies completion notification/cleanup,
and creates no task. Existing advertising fixtures remain enabled. Separate
positive actual P256/ML-DSA TLS fixtures run the full owned stream handshake via
the I/O slot with the real native preparation lease and fragmented stream BIO.
