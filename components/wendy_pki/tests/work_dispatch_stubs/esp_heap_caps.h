#pragma once
#include <stddef.h>
#define MALLOC_CAP_8BIT 1
#define MALLOC_CAP_SPIRAM 2
size_t heap_caps_get_total_size(unsigned);
