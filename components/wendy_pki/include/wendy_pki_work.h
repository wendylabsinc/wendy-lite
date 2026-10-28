#pragma once
#include <stdbool.h>
#include <stdint.h>
/* Inactive staging API for the later serialized worker. No task or queue is
 * created in this layer. Native actor activation is compile-time rejected. */
void wendy_pki_work_enable(void);
bool wendy_pki_work_available(void); /* Always false. */
bool wendy_pki_work_submit(void (*)(void *),void *); /* False; retains nothing. */
bool wendy_pki_work_poll(void);
bool wendy_pki_work_start(void (*wake)(void)); /* False. */
bool wendy_pki_work_stop(void); /* True; nothing is running. */
bool wendy_pki_work_idle(void);
bool wendy_pki_work_is_current(void);
struct wendy_pki_work_metrics {uint64_t jobs,total_us,max_us;unsigned stack_free;bool running;};
void wendy_pki_work_metrics(struct wendy_pki_work_metrics *); /* Zero metrics. */
bool wendy_pki_io_work_submit(void (*)(void *),void *); /* False. */
bool wendy_pki_io_work_poll(void);
bool wendy_pki_io_work_idle(void);
/* Existing baseline callers execute synchronously on their own stack. The
 * callback has completed when this returns; a NULL callback returns -1. */
int wendy_pki_work_run(void (*)(void *),void *);
void wendy_pki_work_bind_actor(void); /* Inactive. */
/* Compatibility placeholders only. They do not serialize callers, account for
 * admission, or provide a cross-task context loan. A non-NULL claim succeeds;
 * release is a no-op. The worker layer must implement those contracts before
 * any native actor can be activated. */
bool wendy_pki_handshake_claim(void *);
bool wendy_pki_handshake_owned(void *);
void wendy_pki_handshake_release(void *);
bool wendy_pki_handshake_available(void);
unsigned wendy_pki_handshake_mesh_limit(void);
bool wendy_pki_handshake_transfer(void *,void *);
bool wendy_pki_handshake_busy(void);
