#include "linear_replacement.h"
#include <stddef.h>
#include <string.h>
#if defined(ESP_PLATFORM)
#include "esp_log.h"
#endif

#if !defined(ESP_PLATFORM) || (CONFIG_SPIRAM && CONFIG_WENDY_WASM_USE_PSRAM)

static struct {
    void *expected, *retained;
    uint64_t commit_size, map_size;
    wwlr_release_fn release;
    uint32_t generation, next_generation;
} replacement;

static void release_retained(void)
{
    void *base = replacement.retained;
    wwlr_release_fn release = replacement.release;
    uint64_t commit_size = replacement.commit_size, map_size = replacement.map_size;
    replacement.retained = NULL;
    replacement.release = NULL;
    if (base) release(base, commit_size, map_size);
}

uint32_t wwlr_begin(void *old_base)
{
    /* A nested transaction must not replace the only owner of an earlier loan. */
    if (!old_base || replacement.generation) return 0;
    if (!++replacement.next_generation) ++replacement.next_generation;
    replacement.generation = replacement.next_generation;
    replacement.expected = old_base;
    return replacement.generation;
}

void wwlr_finish(uint32_t generation)
{
    if (!generation || generation != replacement.generation) return;
    release_retained();
    replacement.expected = NULL;
    replacement.generation = 0;
}

bool wendy_wasm_retain_linear_mapping(void *base, uint64_t commit_size,
                                     uint64_t map_size, wwlr_release_fn release)
{
    if (!replacement.generation || base != replacement.expected || !release ||
        replacement.retained || !commit_size || !map_size) return false;
    replacement.expected = NULL;
    replacement.retained = base;
    replacement.commit_size = commit_size;
    replacement.map_size = map_size;
    replacement.release = release;
    return true;
}

bool wendy_wasm_reuse_linear_mapping(void **base, uint64_t commit_size,
                                    uint64_t map_size)
{
    if (!replacement.generation || !replacement.retained || !base) return false;
    /* The original mapping remains opaque: equal dimensions consume it once.
     * A different guest frees it before normal allocation, including shrink. */
    if (commit_size != replacement.commit_size || map_size != replacement.map_size ||
        commit_size > SIZE_MAX) {
        release_retained();
        return false;
    }
    *base = replacement.retained;
#if defined(ESP_PLATFORM)
    ESP_LOGI("wendy_wasm", "reusing replacement linear mapping: bytes=%llu",
             (unsigned long long)commit_size);
#endif
    replacement.retained = NULL;
    replacement.release = NULL;
    memset(*base, 0, (size_t)commit_size);
    return true;
}

#else
uint32_t wwlr_begin(void *old_base) { (void)old_base; return 0; }
void wwlr_finish(uint32_t generation) { (void)generation; }
bool wendy_wasm_retain_linear_mapping(void *base, uint64_t commit_size,
                                     uint64_t map_size, wwlr_release_fn release)
{
    (void)base; (void)commit_size; (void)map_size; (void)release;
    return false;
}
bool wendy_wasm_reuse_linear_mapping(void **base, uint64_t commit_size,
                                    uint64_t map_size)
{
    (void)base; (void)commit_size; (void)map_size;
    return false;
}
#endif
