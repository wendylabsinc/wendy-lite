#pragma once
#include "esp_err.h"
#include <stddef.h>
#include <stdint.h>
typedef int esp_partition_subtype_t;
typedef int esp_partition_mmap_handle_t;
typedef struct
{
    size_t size, erase_size;
} esp_partition_t;
#define ESP_PARTITION_TYPE_DATA 1
#define ESP_PARTITION_MMAP_DATA 0
const esp_partition_t *esp_partition_find_first(int, esp_partition_subtype_t, const char *);
esp_err_t esp_partition_mmap(const esp_partition_t *, size_t, size_t, int, const void **,
                             esp_partition_mmap_handle_t *);
void esp_partition_munmap(esp_partition_mmap_handle_t);
esp_err_t esp_partition_erase_range(const esp_partition_t *, size_t, size_t);
esp_err_t esp_partition_write(const esp_partition_t *, size_t, const void *, size_t);
