#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "wendy_conf.pb.h"

enum wendy_conf_write_mode {
    WENDY_CONF_WRITE_MODE_REPLACE = 0,
    WENDY_CONF_WRITE_MODE_UPDATE = 1,
};

/**
 * A view into a byte span within the wendy-conf partition.
 * Please note that data is not NUL-terminated, even when representing strings.
 */
struct wendy_conf_span {
    const void *data;
    size_t      size;
};

/**
 * Read and decode the wendy_conf partition. All errors are logged; call once
 * at startup before any getter.
 *
 * Partition layout:
 *   Offset 0x00: magic "WYC0" (4 bytes)
 *   Offset 0x04: protobuf data size, little-endian uint32
 *   Offset 0x08: protobuf-encoded WendyConf message
 */
void wendy_conf_init(void);

/**
 * Write a protobuf-encoded WendyConf message to the wendy_conf partition.
 * The message must not exceed the maximum size returned by
 * wendy_conf_get_max_size().
 *
 * In REPLACE mode the given message becomes the whole configuration. In
 * UPDATE mode, any root property of WendyConf (device_name, wifi,
 * provisioning) absent from the given message is kept from the current
 * configuration.
 *
 * Writing invalidates the in-RAM configuration: from that point on the
 * getters return empty spans / zero values. The new configuration takes
 * effect after reboot.
 *
 * The two resolved-name getters below are the exception: they are decided at
 * init and a write does not disturb them.
 */
esp_err_t wendy_conf_write(const void *pb_data, size_t pb_size, enum wendy_conf_write_mode mode);

/**
 * Largest protobuf-encoded WendyConf message the wendy_conf partition can
 * hold.
 */
size_t wendy_conf_get_max_size(void);

/**
 * An ID specific to this device, coming from the hardware rather than from
 * the configuration. It is therefore fixed for the life of the board: it does
 * not change when the device is reprovisioned or renamed, and it is available
 * even when the conf partition is missing or corrupt.
 *
 * Today, the ID is built from the factory MAC address burned into eFuse,
 * rendered as 12 lowercase hex digits ("98a3167e5f2c"). NUL-terminated and
 * never NULL, unlike the spans below. Built once during wendy_conf_init().
 */
const char *wendy_conf_get_device_id(void);

struct wendy_conf_span wendy_conf_get_device_name(void);

/**
 * The device name to advertise: the configured name when there is one, and
 * "<prefix>-xxxx" otherwise, where xxxx is an hex number derived from the
 * device ID.
 *
 * NUL-terminated and never NULL, unlike the spans above. Built once during
 * wendy_conf_init() and fixed for the life of the boot: a wendy_conf_write()
 * does not change it, and a new name takes effect only after reboot. Callers
 * may hold the pointer, and every subsystem that asks gets the same answer.
 */
const char *wendy_conf_get_resolved_device_name(void);

/**
 * The name to show a person. WendyConf carries no separate display name yet,
 * so this answers exactly like wendy_conf_get_resolved_device_name(); it
 * exists so callers that mean "shown to a person" — a BLE GATT read, an mDNS
 * service instance — say so, and keep saying so once the two diverge.
 */
const char *wendy_conf_get_resolved_device_display_name(void);

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

/**
 * True when the device carries everything mutual TLS needs: a private key, a
 * certificate, and a chain of trust to verify peers against. Transports use
 * it to decide between real mTLS and the unauthenticated fallback below, so
 * they all answer the question the same way.
 */
bool wendy_conf_is_provisioned(void);

/**
 * The self-signed certificate and key compiled into the firmware, served by
 * every transport when the device is not provisioned. They authenticate
 * nothing — they exist so a fresh device is still reachable.
 */
struct wendy_conf_span wendy_conf_get_default_certificate(void);
struct wendy_conf_span wendy_conf_get_default_private_key(void);

void wendy_conf_copy_span(char *dest, size_t dest_size, struct wendy_conf_span src);
