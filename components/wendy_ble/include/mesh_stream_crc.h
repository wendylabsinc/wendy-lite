/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define WBLE_CRC_STRIDE UINT64_C(4096)
/* Diagnostic-only, two directions, no retained payload or allocation. */
struct wble_stream_crc {
    uint64_t bytes[2];
    uint32_t crc[2], boundary_crc[2], first_crc[2];
};
_Static_assert(sizeof(struct wble_stream_crc)==40,"bounded stream probe");
void wble_stream_crc_accept(struct wble_stream_crc *,unsigned direction,
                            const void *,size_t);
bool wble_stream_crc_self_test(void);
