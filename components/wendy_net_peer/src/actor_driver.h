#pragma once
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif
#include "wendy_net_actor.h"
#include "wendy_pki_mesh.h"
#include <sys/select.h>
/* Outer I/O only. Every adapter call is nonblocking; wait is the sole sleep. */
int wnad_start(void);
void wnad_stop(void);
void wnad_wake(void);
int wnad_wake_fd(void);
void wnad_drain_wake(void);
int wnad_channel_io(struct wna_channel *,int fd,const struct wendy_pki_stream *);
/* Validate select capacity and make accepted/outbound TCP sockets nonblocking. */
bool wnad_prepare_socket(int fd);
int wnad_connect(const char *,unsigned,bool *connecting);
int wnad_connected(int fd);
int wnad_no_wait(void *,bool,int64_t);
/* Count/byte admission precedes heavy TLS allocation, independently of CPU
 * serialization. Waiting peers retain only bounded transport/BIO buffers. */
bool wnad_handshake_claim(void *owner);
void wnad_handshake_release(void *owner);
/* Native management asks the actor to yield only a guest's unestablished
 * outgoing TLS setup when it owns the sole constrained-memory workspace. */
bool wendy_net_app_yield_setup(void);

uint64_t wnad_io_during_crypto(void);
