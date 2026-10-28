/* Mesh state transitions and buffered BIO: no OS, clock, socket or task API. */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
/* Build-level ABI shared by every consumer; independent of TLS record/MTU limits. */
#ifndef WNA_IO_BYTES
#define WNA_IO_BYTES 512
#endif
#if WNA_IO_BYTES < 256 || WNA_IO_BYTES > 512
#error "actor BIO geometry outside configured range"
#endif
struct wna_buffer { uint8_t bytes[WNA_IO_BYTES];size_t offset,size; };
struct wna_channel {struct wna_buffer input,output;bool eof,failed;};
ssize_t wna_read(void *,void *,size_t);
ssize_t wna_write(void *,const void *,size_t);
size_t wna_buffer_space(struct wna_buffer *);
void wna_buffer_consume(struct wna_buffer *,size_t);
/* Context ownership is an explicit state, not an advisory mutex. Every actor
 * branch checks it before touching TLS/BIO state. Cancellation is deferred. */
enum wna_phase {WNA_PREPARE,WNA_HANDSHAKE,WNA_READY,WNA_FAILED,WNA_CLOSED};
struct wna_session {
    enum wna_phase phase;
    bool lent,cancel;
    int need;
    uint64_t deadline,retry_at;
};
enum wna_effect {WNA_NONE,WNA_CRYPTO_PREPARE,WNA_CRYPTO_STEP,WNA_IO_READ,WNA_IO_WRITE,WNA_CLOSE};
enum wna_effect wna_next(struct wna_session *,uint64_t now,bool input,bool output_space);
void wna_lend(struct wna_session *);
void wna_completed(struct wna_session *,int result);
/* Actor cancellation only. A lent TLS context remains worker-owned until its
 * normal completion; callers collect that completion before disposal. */
bool wna_yield_guest_setup(struct wna_session *,bool constrained,bool outbound,
                          bool established,bool owns_workspace);
