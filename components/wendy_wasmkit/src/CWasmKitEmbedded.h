// CWasmKitEmbedded.h — embedded-safe wrapper for _CWasmKit.
//
// The upstream _CWasmKit.h includes <stdio.h>, which pulls in the ESP-IDF
// newlib stdio wrapper.  That wrapper uses #include_next, which fails when
// Clang doesn't know about the sysroot.  Since mprotect bound-checking and
// the trap-guard are disabled on bare-metal (WASMKIT_MPROTECT_BOUND_CHECKING=0),
// we only need the atomics, size_t, and the Platform.h constants.

#pragma once

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "Platform.h"

// ── Inline atomic helpers (copied verbatim from _CWasmKit.h) ────────────────

#define WASMKIT_DEFINE_ATOMICS(WIDTH, CTYPE) \
static inline CTYPE wasmkit_atomic_load_##WIDTH(const void *_Nonnull ptr) { \
    return __atomic_load_n((const CTYPE *)ptr, __ATOMIC_SEQ_CST); \
} \
static inline void wasmkit_atomic_store_##WIDTH(void *_Nonnull ptr, CTYPE val) { \
    __atomic_store_n((CTYPE *)ptr, val, __ATOMIC_SEQ_CST); \
} \
static inline CTYPE wasmkit_atomic_add_##WIDTH(void *_Nonnull ptr, CTYPE val) { \
    return __atomic_fetch_add((CTYPE *)ptr, val, __ATOMIC_SEQ_CST); \
} \
static inline CTYPE wasmkit_atomic_sub_##WIDTH(void *_Nonnull ptr, CTYPE val) { \
    return __atomic_fetch_sub((CTYPE *)ptr, val, __ATOMIC_SEQ_CST); \
} \
static inline CTYPE wasmkit_atomic_and_##WIDTH(void *_Nonnull ptr, CTYPE val) { \
    return __atomic_fetch_and((CTYPE *)ptr, val, __ATOMIC_SEQ_CST); \
} \
static inline CTYPE wasmkit_atomic_or_##WIDTH(void *_Nonnull ptr, CTYPE val) { \
    return __atomic_fetch_or((CTYPE *)ptr, val, __ATOMIC_SEQ_CST); \
} \
static inline CTYPE wasmkit_atomic_xor_##WIDTH(void *_Nonnull ptr, CTYPE val) { \
    return __atomic_fetch_xor((CTYPE *)ptr, val, __ATOMIC_SEQ_CST); \
} \
static inline _Bool wasmkit_atomic_cmpxchg_weak_##WIDTH(void *_Nonnull ptr, CTYPE *_Nonnull expected, CTYPE desired) { \
    return __atomic_compare_exchange_n((CTYPE *)ptr, expected, desired, 1, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); \
} \
static inline _Bool wasmkit_atomic_cmpxchg_strong_##WIDTH(void *_Nonnull ptr, CTYPE *_Nonnull expected, CTYPE desired) { \
    return __atomic_compare_exchange_n((CTYPE *)ptr, expected, desired, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); \
}

WASMKIT_DEFINE_ATOMICS(8,  uint8_t)
WASMKIT_DEFINE_ATOMICS(16, uint16_t)
WASMKIT_DEFINE_ATOMICS(32, uint32_t)
WASMKIT_DEFINE_ATOMICS(64, uint64_t)
#undef WASMKIT_DEFINE_ATOMICS

// ── Address sanitizer stub ───────────────────────────────────────────────────

static inline int wasmkit_address_sanitizer_enabled(void) {
    return WASMKIT_ADDRESS_SANITIZER_ENABLED;
}

// ── InlineCode.h (copied verbatim from _CWasmKit/InlineCode.h) ──────────────
// This header is imported separately in WasmKit as `import _CWasmKit.InlineCode`.
// We include it here so the module builds correctly.
#include "InlineCode.h"
