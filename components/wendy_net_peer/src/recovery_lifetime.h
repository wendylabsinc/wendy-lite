#pragma once
#include <stdint.h>

/* A temporary carrier outage must not remove the mesh address before the
 * logical application's recovery allowance ends. Promoted TCP sockets also
 * depend on that address. Shared by address retention and direct sessions. */
#define WN_RECOVERY_GRACE_US INT64_C(120000000)
