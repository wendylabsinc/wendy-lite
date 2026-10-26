#pragma once
/* TEST-ONLY heap diagnostics for the XIAO mesh ESP_ERR_NO_MEM investigation. */
#include "esp_heap_caps.h"
#include "esp_log.h"

#define WENDY_HEAP_DIAG(tag, where)                                                            \
    ESP_LOGW(tag,                                                                              \
        "heapdiag[%s] internal free=%u largest=%u min=%u | dma free=%u largest=%u | "          \
        "spiram free=%u largest=%u",                                                           \
        (where),                                                                               \
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),              \
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),     \
        (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),      \
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA),                                     \
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DMA),                            \
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),                                  \
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM))

/* Same, through the ROM printf: app logs before wendy_core_init() go to UART0 only. */
#define WENDY_HEAP_DIAG_EARLY(tag, where)                                                      \
    ESP_EARLY_LOGW(tag,                                                                        \
        "heapdiag[%s] internal free=%u largest=%u min=%u | dma free=%u largest=%u | "          \
        "spiram free=%u largest=%u",                                                           \
        (where),                                                                               \
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),              \
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),     \
        (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),      \
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA),                                     \
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DMA),                            \
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),                                  \
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM))
