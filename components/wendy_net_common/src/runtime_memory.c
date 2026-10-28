#include "wendy_net_alloc.h"

#ifdef ESP_PLATFORM
#include "esp_heap_caps.h"
#endif

static wendy_net_memory_t runtime_memory = WENDY_NET_MEMORY_INITIALIZER;

static bool external_available(void)
{
    bool external = false;
#ifdef ESP_PLATFORM
    external = heap_caps_get_total_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != 0;
#endif
    return external;
}

size_t wendy_net_runtime_memory_limit(void)
{
    return external_available() ? WENDY_NET_RUNTIME_EXTERNAL_MEMORY_LIMIT :
                                  WENDY_NET_RUNTIME_INTERNAL_MEMORY_LIMIT;
}

bool wendy_net_runtime_memory_open(void)
{
    return wendy_net_memory_open(&runtime_memory, wendy_net_runtime_memory_limit(),
                                 external_available());
}

void wendy_net_runtime_memory_close(void)
{
    wendy_net_memory_close(&runtime_memory);
}

bool wendy_net_runtime_memory_drained(void)
{
    return wendy_net_memory_drained(&runtime_memory);
}

void wendy_net_runtime_memory_snapshot(wendy_net_memory_snapshot_t *out)
{
    wendy_net_memory_snapshot(&runtime_memory, out);
}

wendy_net_memory_t *wendy_net_runtime_memory_ledger(void)
{
    return &runtime_memory;
}

static wendy_net_memory_placement_t default_placement(void)
{
    wendy_net_memory_snapshot_t state;
    wendy_net_memory_snapshot(&runtime_memory, &state);
    return state.external_enabled ? WENDY_NET_MEMORY_EXTERNAL : WENDY_NET_MEMORY_INTERNAL;
}

wendy_net_memory_scope_t wendy_net_runtime_scope_enter(void)
{
    return wendy_net_memory_scope_enter(&runtime_memory, default_placement());
}

#if defined(ESP_PLATFORM) || defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
void *wendy_net_malloc(size_t bytes)
{
    return wendy_net_memory_malloc(&runtime_memory, bytes, default_placement());
}

void *wendy_net_calloc(size_t count, size_t bytes)
{
    return wendy_net_memory_calloc(&runtime_memory, count, bytes, default_placement());
}

void *wendy_net_realloc(void *ptr, size_t bytes)
{
    return wendy_net_memory_realloc(&runtime_memory, ptr, bytes, default_placement());
}

void wendy_net_free(void *ptr)
{
    wendy_net_memory_free(ptr);
}

void *wendy_net_rtc_malloc(size_t bytes)
{
    return wendy_net_memory_malloc(&runtime_memory, bytes, WENDY_NET_MEMORY_RTC);
}

void *wendy_net_internal_malloc(size_t bytes)
{
    return wendy_net_memory_malloc(&runtime_memory, bytes, WENDY_NET_MEMORY_INTERNAL);
}

void *wendy_net_internal_calloc(size_t count, size_t bytes)
{
    return wendy_net_memory_calloc(&runtime_memory, count, bytes, WENDY_NET_MEMORY_INTERNAL);
}

char *wendy_net_strdup(const char *text)
{
    if (!text) return NULL;
    size_t size = strlen(text) + 1;
    char *copy = wendy_net_malloc(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}
#endif
