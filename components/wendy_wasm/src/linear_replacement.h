#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Serialized lifecycle control thread only. No guest may execute between begin
 * and finish. A generation scopes the sole old main-module mapping. */
uint32_t wwlr_begin(void *old_base);
void wwlr_finish(uint32_t generation);

typedef void (*wwlr_release_fn)(void *, uint64_t, uint64_t);
/* Optional explicit WAMR linear-memory port hooks; generic mmap is unaffected. */
bool wendy_wasm_retain_linear_mapping(void *base, uint64_t commit_size,
                                     uint64_t map_size, wwlr_release_fn release);
bool wendy_wasm_reuse_linear_mapping(void **base, uint64_t commit_size,
                                    uint64_t map_size);
