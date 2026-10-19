#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "wendy_conf.pb.h"

enum wendy_conf_write_mode {
    WENDY_CONF_WRITE_MODE_REPLACE = 0,
    WENDY_CONF_WRITE_MODE_UPDATE = 1,
    WENDY_CONF_WRITE_MODE_WIFI_ONLY = 2, // UPDATE accepting only the wifi root field
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

/* False while configuration is missing, unreadable, or awaiting reboot after
 * a write. Enrolled sessions must stop using a cached policy in this state. */
bool wendy_conf_is_current(void);

/* Copies only public enrollment identifiers, never credentials. Empty when
 * configuration is absent or awaiting reboot. */
void wendy_conf_enrollment_identity(char tenant[37], char device[65]);

/**
 * Write a protobuf-encoded WendyConf message to the wendy_conf partition.
 * The message must not exceed the maximum size returned by
 * wendy_conf_get_max_size().
 *
 * In REPLACE mode the given message becomes the whole configuration. In
 * UPDATE mode, any root property of WendyConf (device_name, wifi,
 * enrollment) absent from the given message is kept from the current
 * configuration. WIFI_ONLY applies UPDATE semantics but rejects every root
 * field except wifi, including unknown fields and duplicate wifi fields.
 *
 * Writing invalidates the in-RAM configuration: from that point on the
 * getters return empty spans / zero values. The new configuration takes
 * effect after reboot.
 * The enrollment authentication requirement remains active during writes,
 * including failed writes. Only a completed reset can clear it within a boot.
 *
 * The two resolved-name getters below are the exception: they are decided at
 * init and a write does not disturb them.
 */
esp_err_t wendy_conf_write(const void *pb_data, size_t pb_size, enum wendy_conf_write_mode mode);

/**
 * Remove enrollment, including retired credential fields, from persisted configuration,
 * preserving every other root field verbatim. Reloads the configuration after
 * success and is safe to call repeatedly. The application partition is untouched.
 *
 * The caller must initialize the wendy_pki NVS partition and persist a reset
 * marker that blocks identity use before calling this function. Retained fields
 * are committed in that partition's separate conf_recovery namespace before
 * erasing configuration. A retry, including after reboot, recovers from this
 * journal and removes it only after verifying the persisted configuration.
 * Callers must check success before erasing identity keys. Missing or unreadable
 * configuration without a recovery journal returns an error without erasing it.
 */
esp_err_t wendy_conf_clear_enrollment(void);

/**
 * Largest protobuf-encoded WendyConf message the wendy_conf partition can
 * hold.
 */
size_t wendy_conf_get_max_size(void);

/**
 * An ID specific to this device, coming from the hardware rather than from
 * the configuration. It is therefore fixed for the life of the board: it does
 * not change when the device is enrolled again or renamed, and it is available
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

/**
 * The embedded self-signed certificate and key used for anonymous TLS on
 * unenrolled devices. These do not authenticate clients or establish trust.
 */
struct wendy_conf_span wendy_conf_get_default_certificate(void);
struct wendy_conf_span wendy_conf_get_default_private_key(void);

void wendy_conf_copy_span(char *dest, size_t dest_size, struct wendy_conf_span src);

/**
 * True when stored configuration requires an enrolled identity. This does not
 * imply that certificate issuance has completed or the certificate is valid.
 * Retired credential fields also require enrollment authentication, so a
 * firmware upgrade cannot silently enable anonymous access. Such devices need
 * USB enrollment or reset before network access can resume.
 */
bool wendy_conf_has_enrollment(void);
#define WENDY_CONF_MAX_TRUST_BUNDLE 16384
#define WENDY_CONF_MAX_ENROLLMENT_DATA 65536
struct wendy_conf_enrollment_data {
    struct wendy_conf_span signed_time, device_roots, tsa_roots, https_roots;
    uint8_t *storage;
};
/* The caller frees data->storage. All spans survive configuration writes. */
esp_err_t wendy_conf_copy_enrollment(WendyConfEnrollment *config,
                                     struct wendy_conf_enrollment_data *data);
