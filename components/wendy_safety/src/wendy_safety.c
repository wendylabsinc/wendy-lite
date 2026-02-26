#include "wendy_safety.h"

#include "wasm_export.h"
#include "esp_timer.h"
#include "esp_log.h"

#include <string.h>

static const char *TAG = "wendy_safety";

bool wendy_safety_check_ptr(void *exec_env, uint32_t app_offset, uint32_t len)
{
    wasm_module_inst_t inst =
        wasm_runtime_get_module_inst((wasm_exec_env_t)exec_env);
    if (!inst) {
        return false;
    }
    return wasm_runtime_validate_app_addr(inst, app_offset, len);
}

void *wendy_safety_get_native_ptr(void *exec_env, uint32_t app_offset, uint32_t len)
{
    wasm_module_inst_t inst =
        wasm_runtime_get_module_inst((wasm_exec_env_t)exec_env);
    if (!inst) {
        return NULL;
    }
    if (!wasm_runtime_validate_app_addr(inst, app_offset, len)) {
        ESP_LOGW(TAG, "invalid WASM ptr: offset=%lu len=%lu",
                 (unsigned long)app_offset, (unsigned long)len);
        return NULL;
    }
    return wasm_runtime_addr_app_to_native(inst, app_offset);
}

/* ── Simple rate limiter ──────────────────────────────────────────────── */

#define MAX_RATE_CATEGORIES 8

typedef struct {
    char name[24];
    int64_t last_reset_us;
    int count;
    int max_per_sec;
} rate_bucket_t;

static rate_bucket_t s_buckets[MAX_RATE_CATEGORIES];
static int s_bucket_count = 0;

bool wendy_safety_rate_check(const char *category, int max_per_sec)
{
    int64_t now = esp_timer_get_time();

    /* Find or create bucket */
    rate_bucket_t *bucket = NULL;
    for (int i = 0; i < s_bucket_count; i++) {
        if (strncmp(s_buckets[i].name, category, sizeof(s_buckets[i].name) - 1) == 0) {
            bucket = &s_buckets[i];
            break;
        }
    }
    if (!bucket) {
        if (s_bucket_count >= MAX_RATE_CATEGORIES) {
            ESP_LOGW(TAG, "rate limiter full, allowing %s", category);
            return true;
        }
        bucket = &s_buckets[s_bucket_count++];
        strncpy(bucket->name, category, sizeof(bucket->name) - 1);
        bucket->name[sizeof(bucket->name) - 1] = '\0';
        bucket->last_reset_us = now;
        bucket->count = 0;
        bucket->max_per_sec = max_per_sec;
    }

    /* Reset bucket every second */
    if (now - bucket->last_reset_us >= 1000000) {
        bucket->count = 0;
        bucket->last_reset_us = now;
    }

    if (bucket->count >= max_per_sec) {
        return false;
    }
    bucket->count++;
    return true;
}
