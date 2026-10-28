/* Serialized work on the existing certificate-capable server stack. No task,
 * per-request allocation or retained caller pointer after completion. */
#pragma once
#include <stdbool.h>

/* The server enables this only after its listener is ready. Before then,
 * callers retain their existing standalone worker path (including no Wi-Fi). */
void wendy_pki_work_enable(void);
bool wendy_pki_work_available(void);
/* One pending/running callback. Context belongs to the caller until callback
 * completion; false means nothing was retained. Callback must not await a
 * second callback on this same worker. The initiating allocation scope follows
 * the job; the worker restores its previous scope after callback completion. */
bool wendy_pki_work_submit(void (*callback)(void *),void *context);
/* Call only from the server/TLS worker, outside other handshakes. */
bool wendy_pki_work_poll(void);

/* Dedicated preemptible mesh crypto worker, priority3 (actor4). Existing server
 * polling is disabled once started. Completion wakes the actor's outer I/O. */
bool wendy_pki_work_start(void (*wake)(void));
/* Cooperative shutdown: pending work finishes before the task deletes itself.
 * False means still draining. Non-mesh PKI callers resume their inline path. */
bool wendy_pki_work_stop(void);

bool wendy_pki_work_idle(void);
/* True only on the task/thread currently executing this queue's callback. */
bool wendy_pki_work_is_current(void);

#include <stdint.h>
struct wendy_pki_work_metrics {uint64_t jobs,total_us,max_us;unsigned stack_free;bool running;};
void wendy_pki_work_metrics(struct wendy_pki_work_metrics *);
/* Existing platform PKI I/O worker. These callbacks may wait for network I/O;
 * their CPU-heavy TLS steps use work_run, never occupy the crypto queue while
 * waiting for bytes. No additional task is created for this provider. */
bool wendy_pki_io_work_submit(void (*)(void *),void *);
bool wendy_pki_io_work_poll(void);
bool wendy_pki_io_work_idle(void);
/* Synchronous facade for existing non-actor callers. Actor use is rejected;
 * on the crypto task itself this invokes directly, so nested CPU helpers are
 * safe. Caller retains its arguments until completion. */
int wendy_pki_work_run(void (*)(void *),void *);
void wendy_pki_work_bind_actor(void);
/* Retained heavyweight context lifetime, separate from one CPU callback.
 * SRAM has one shared slot; PSRAM has two mesh slots plus a reserved baseline
 * slot. Mesh allocation scopes cannot use that reserve. Baseline callers try
 * it first, then idle shared slots. TLS holds admission across I/O waits;
 * SRAM-only math jobs also hold it until temporary allocations are released.
 * Established TLS I/O on other contexts keeps running. */
bool wendy_pki_handshake_claim(void *);
bool wendy_pki_handshake_owned(void *);
void wendy_pki_handshake_release(void *);
/* Availability for the current allocation scope; a hint, never admission. */
bool wendy_pki_handshake_available(void);
unsigned wendy_pki_handshake_mesh_limit(void);
/* Retain one uninterrupted workspace lease while preparation moves into its
 * real TLS context. A stale cookie/context cannot release a different owner. */
bool wendy_pki_handshake_transfer(void *from,void *to);
bool wendy_pki_handshake_busy(void);
