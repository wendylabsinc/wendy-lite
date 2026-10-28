#pragma once
#include <stddef.h>
static inline void mbedtls_platform_zeroize(void *buffer,size_t size)
{volatile unsigned char *bytes=buffer;while(size--)*bytes++=0;}
