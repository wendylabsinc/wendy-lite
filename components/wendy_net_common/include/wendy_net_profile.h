/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#endif
/* Resource bounds and forwarding/discovery policy are independent. The lab
 * transit profile keeps CONFIG_WENDY_NET_CONSTRAINED_PROFILE resource guards:
 * eight verified keys, demand services, DER retirement and pending-eight. */
#if CONFIG_WENDY_NET_CONSTRAINED_PROFILE
#define WENDY_NET_SMALL_RESOURCES 1
#else
#define WENDY_NET_SMALL_RESOURCES 0
#endif
#if WENDY_NET_SMALL_RESOURCES && !CONFIG_WENDY_NET_TEST_C6_BLE_TRANSIT
#define WENDY_NET_NON_TRANSIT 1
#else
#define WENDY_NET_NON_TRANSIT 0
#endif
