#pragma once
#include <stddef.h>
static inline void mbedtls_platform_zeroize(void *p, size_t n) {
    volatile unsigned char *s = p;
    while (n--) *s++ = 0;
}
