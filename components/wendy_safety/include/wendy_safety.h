#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Validate that a WASM app pointer range [ptr, ptr+len) falls within
 * the module's linear memory.
 *
 * @param exec_env   WAMR execution environment
 * @param app_offset WASM-side pointer (offset in linear memory)
 * @param len        Length in bytes
 * @return true if valid, false if out of bounds
 */
bool wendy_safety_check_ptr(void *exec_env, uint32_t app_offset, uint32_t len);

/**
 * Validate and convert a WASM pointer to a native pointer.
 * Returns NULL if validation fails.
 *
 * @param exec_env   WAMR execution environment
 * @param app_offset WASM-side pointer
 * @param len        Length in bytes
 * @return native pointer, or NULL if invalid
 */
void *wendy_safety_get_native_ptr(void *exec_env, uint32_t app_offset, uint32_t len);

/**
 * Simple rate limiter. Returns true if the action is allowed.
 * Uses a token-bucket approach per category.
 *
 * @param category   String identifier (e.g. "storage_write", "uart_write")
 * @param max_per_sec Maximum calls per second
 * @return true if allowed
 */
bool wendy_safety_rate_check(const char *category, int max_per_sec);

#ifdef __cplusplus
}
#endif
