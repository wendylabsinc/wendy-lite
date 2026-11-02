/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#endif
/* The constrained endpoint profile uses bounded resource policies and does
 * not advertise transit service. */
#if CONFIG_WENDY_NET_CONSTRAINED_PROFILE
#define WENDY_NET_SMALL_RESOURCES 1
#else
#define WENDY_NET_SMALL_RESOURCES 0
#endif
#define WENDY_NET_NON_TRANSIT WENDY_NET_SMALL_RESOURCES
