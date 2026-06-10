#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "wendy_conf.pb.h"

/**
 * A view into a byte span within the wendy-conf partition.
 * Please note that data is not NUL-terminated, even when representing strings.
 */
struct wendy_conf_span {
    const void *data;
    size_t      size;
};

/**
 * Read and decode the wendy_conf partition.  All errors are logged; call once
 * at startup before any getter.
 *
 * Partition layout:
 *   Offset 0x00: magic "WYC0" (4 bytes)
 *   Offset 0x04: protobuf data size, little-endian uint32
 *   Offset 0x08: protobuf-encoded WendyConf message
 */
void wendy_conf_init(void);

struct wendy_conf_span wendy_conf_get_device_name(void);

struct wendy_conf_span wendy_conf_get_network_ssid(void);
struct wendy_conf_span wendy_conf_get_network_password(void);
int32_t wendy_conf_get_network_priority(void);
bool wendy_conf_get_network_hidden(void);
WendyConfWifiSecurity wendy_conf_get_network_security(void);

bool wendy_conf_get_enrolled(void);
int32_t wendy_conf_get_org_id(void);
int32_t wendy_conf_get_asset_id(void);
struct wendy_conf_span wendy_conf_get_cloud_host(void);
struct wendy_conf_span wendy_conf_get_private_key(void);
struct wendy_conf_span wendy_conf_get_certificate(void);
struct wendy_conf_span wendy_conf_get_chain_of_trust(void);


