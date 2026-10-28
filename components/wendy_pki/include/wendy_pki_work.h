/* Single-item crypto handoff and separate existing-server I/O handoff.
 * No per-request heap allocation. State/handles are mutex-protected across tasks. */
#pragma once
#include <stdbool.h>

/* Register the firmware-lifetime existing server as a polling provider, only
 * once it can keep calling both poll functions outside other handshakes. This
 * creates no task. It enables I/O submission and fallback CPU polling. Before
 * registration I/O submissions fail without retaining their context.
 * A dedicated crypto start alone does not register an I/O provider. */
void wendy_pki_work_enable(void);
bool wendy_pki_work_available(void);
/* One pending/running callback. Context belongs to the caller until callback
 * completion; false means nothing was retained. Callback must not await a
 * second callback on this same worker. The initiating allocation scope follows
 * the job; the worker restores its previous scope after callback completion. */
bool wendy_pki_work_submit(void (*callback)(void *),void *context);
/* Called by the dedicated task when started, otherwise the registered server.
 * Actor calls fail; while dedicated, other tasks cannot steal its callback. */
bool wendy_pki_work_poll(void);

/* Dedicated preemptible mesh crypto worker, default priority3 (actor4).
 * Existing CPU polling is bypassed once started. Completion wakes the actor's
 * outer I/O. Idempotent only with the same wake function. Returns false during
 * stop, an active fallback/inline callback, or task-allocation failure; an outer
 * driver may retry after those calls complete. No worker is created at OFF. */
bool wendy_pki_work_start(void (*wake)(void));
/* First quiesce mesh submissions and lend no new contexts, then poll stop from
 * the outer driver. False means accepted CPU/I/O/inline work or the task still
 * drains; new submissions are rejected during that interval. True means the
 * old worker and completion wake are quiescent. Baseline work_run is inline;
 * a registered firmware-lifetime server resumes CPU polling. Without one,
 * submissions remain disabled. Stop never creates/replaces an I/O task.
 * True precedes FreeRTOS idle reaping: also wait for the common runtime ledger
 * to drain before closing/reopening its owner, as required by the task helper. */
bool wendy_pki_work_stop(void);

bool wendy_pki_work_idle(void);
/* True only on the task/thread currently executing this queue's callback. */
bool wendy_pki_work_is_current(void);

#include <stdint.h>
struct wendy_pki_work_metrics {uint64_t jobs,total_us,max_us;unsigned stack_free;bool running;};
void wendy_pki_work_metrics(struct wendy_pki_work_metrics *);
/* Existing server polling provider. These callbacks may wait for network I/O;
 * their CPU-heavy TLS steps use work_run, never occupy the crypto queue while
 * waiting for bytes. No additional task is created for this provider. The
 * server must keep polling throughout accepted I/O and mesh shutdown; the actor
 * and crypto task cannot poll this queue. Quiesce producers before stop(). */
bool wendy_pki_io_work_submit(void (*)(void *),void *);
bool wendy_pki_io_work_poll(void);
bool wendy_pki_io_work_idle(void);
/* Synchronous facade for existing non-actor callers. Actor use is rejected;
 * on the crypto task itself this invokes directly, so nested CPU helpers are
 * safe. Caller retains its arguments until completion. NULL callbacks fail.
 * When no dedicated task exists baseline callers keep the inline path; this
 * does not add a task or serialize unrelated baseline work while mesh is OFF. */
int wendy_pki_work_run(void (*)(void *),void *);
void wendy_pki_work_bind_actor(void);
/* Retained heavyweight context lifetime, separate from one CPU callback.
 * SRAM has one shared slot; PSRAM has two mesh slots plus a reserved baseline
 * slot. Mesh allocation scopes cannot use that reserve. Baseline callers try
 * it first, then idle shared slots. TLS holds admission across I/O waits;
 * SRAM-only math jobs also hold it until temporary allocations are released.
 * Established TLS I/O on other contexts keeps running. Each owner/context is
 * exclusive to its initiating caller while claiming/transferring/releasing;
 * these helpers do not make concurrent access to one TLS context valid. */
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
