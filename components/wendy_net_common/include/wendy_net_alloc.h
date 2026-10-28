#pragma once

#include "wendy_net_memory.h"
#include <stdlib.h>
#include <string.h>
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Runtime-wide mesh ledger. Open before creating any mesh state/tasks; close
 * rejects admissions, and all loans/tasks must drain before a later reopen.
 * No arena is allocated. PSRAM is selected strictly when available on ESP.
 * PSRAM nodes may own up to 2 MiB. SRAM endpoints use the configured ceiling
 * (160 KiB for constrained C6); physical/SDK headroom is checked separately. */
#ifndef CONFIG_WENDY_NET_INTERNAL_MEMORY_LIMIT_KIB
#define CONFIG_WENDY_NET_INTERNAL_MEMORY_LIMIT_KIB 1024
#endif
#define WENDY_NET_RUNTIME_INTERNAL_MEMORY_LIMIT \
    ((size_t)CONFIG_WENDY_NET_INTERNAL_MEMORY_LIMIT_KIB * 1024)
#define WENDY_NET_RUNTIME_EXTERNAL_MEMORY_LIMIT ((size_t)2 * 1024 * 1024)
/* Available while OFF as well, for management capability reporting. */
size_t wendy_net_runtime_memory_limit(void);
bool wendy_net_runtime_memory_open(void);
void wendy_net_runtime_memory_close(void);
bool wendy_net_runtime_memory_drained(void);
void wendy_net_runtime_memory_snapshot(wendy_net_memory_snapshot_t *out);
wendy_net_memory_t *wendy_net_runtime_memory_ledger(void);
wendy_net_memory_scope_t wendy_net_runtime_scope_enter(void);

#if defined(ESP_PLATFORM) || defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
/* ESP always uses the ledger: there is no libc fallback while closed/full.
 * INTERNAL variants are available for SDK/task-affine state; ordinary protocol
 * objects use strict PSRAM on equipped devices, otherwise strict internal RAM.
 * Only matching ownership pointers may be passed to these free/realloc calls. */
void *wendy_net_malloc(size_t bytes);
void *wendy_net_calloc(size_t count, size_t bytes);
void *wendy_net_realloc(void *ptr, size_t bytes);
void wendy_net_free(void *ptr);
void *wendy_net_internal_malloc(size_t bytes);
void *wendy_net_rtc_malloc(size_t bytes);
void *wendy_net_internal_calloc(size_t count, size_t bytes);
char *wendy_net_strdup(const char *text);
#else
/* Portable components retain their libc ownership ABI on host. Their existing
 * standalone tests and custom allocator callbacks do not need runtime startup
 * or a link dependency on the ESP ledger. */
static inline void *wendy_net_malloc(size_t bytes) { return malloc(bytes); }
static inline void *wendy_net_calloc(size_t count, size_t bytes) { return calloc(count, bytes); }
static inline void *wendy_net_realloc(void *ptr, size_t bytes) { return realloc(ptr, bytes); }
static inline void wendy_net_free(void *ptr) { free(ptr); }
static inline void *wendy_net_internal_malloc(size_t bytes) { return malloc(bytes); }
static inline void *wendy_net_rtc_malloc(size_t bytes) { return malloc(bytes); }
static inline void *wendy_net_internal_calloc(size_t count, size_t bytes) { return calloc(count, bytes); }
static inline char *wendy_net_strdup(const char *text)
{
    if (!text) return NULL;
    size_t size = strlen(text) + 1;
    char *copy = malloc(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}
#endif

#ifdef __cplusplus
}
#endif
