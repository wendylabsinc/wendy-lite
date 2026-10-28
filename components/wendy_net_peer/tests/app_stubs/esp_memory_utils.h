#pragma once
#include <stdbool.h>
static inline bool esp_ptr_external_ram(const void *pointer){(void)pointer;return false;}
