#pragma once
#include "wendy_net_memory.h"
/* Match the production universal allocator ABI without linking a TLS engine. */
#define mbedtls_calloc wendy_net_memory_scoped_calloc
#define mbedtls_free wendy_net_memory_scoped_free
