#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Admission over validated WASM/WAMR 2.4 AOT memory dimensions. Configured pages
 * mean 64 KiB; AOT may internally represent a fixed multi-MiB memory as one page.
 * Zero preserves the existing uncapped policy. No allocation or file I/O. */
bool wendy_wasm_memory_limit(const void *bytes,size_t size,uint32_t limit_pages,
    uint32_t host_heap_bytes,uint32_t *runtime_max_pages,char *error,size_t error_size);
