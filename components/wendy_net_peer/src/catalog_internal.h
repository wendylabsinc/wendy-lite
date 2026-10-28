/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "catalog_node.h"
struct wnsc_node {
 struct wnsc_config config;
 struct wns_store records;
 char principal[106];
 uint8_t self[16];
};
