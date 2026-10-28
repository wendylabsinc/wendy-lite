/* Single-producer/single-consumer plaintext pipe. No OS, I/O or allocation. */
#pragma once
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
struct wnap_ring {atomic_uint produced,consumed;unsigned capacity;uint8_t *bytes;};
/* Backing storage is capacity+1 bytes; the spare index distinguishes full from
 * empty without 64-bit atomics or requiring a power-of-two configuration. */
void wnap_init(struct wnap_ring *,uint8_t *,unsigned capacity);
size_t wnap_available(const struct wnap_ring *);
size_t wnap_space(const struct wnap_ring *);
size_t wnap_read_span(struct wnap_ring *,const uint8_t **);
size_t wnap_write_span(struct wnap_ring *,uint8_t **);
void wnap_consume(struct wnap_ring *,size_t);
void wnap_produce(struct wnap_ring *,size_t);
size_t wnap_read(struct wnap_ring *,void *,size_t);
size_t wnap_write(struct wnap_ring *,const void *,size_t);
