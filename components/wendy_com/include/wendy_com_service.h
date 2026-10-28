#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WCOM_SERVICE_NAME "_wendy-lite"
#define WCOM_SERVICE_PROTOCOL "_tcp"
#define WCOM_SERVICE_TYPE WCOM_SERVICE_NAME "." WCOM_SERVICE_PROTOCOL
#define WCOM_SERVICE_TXT_MAX 8
struct wcom_service_txt {const char *key,*value;};
struct wcom_service {
    const char *instance;
    uint16_t port;
    size_t count;
    struct wcom_service_txt txt[WCOM_SERVICE_TXT_MAX];
    char tenant[37],device[65],principal[106];
};
/* Physical LAN management advertisement. The signed mesh router manifest
 * carries the same device name/platform/capabilities without a service blob.
 * Strings borrow immutable configuration except the owned identity fields. */
int wcom_service_snapshot(struct wcom_service *);
/* Flatten TXT fields for clients which need the physical advertisement. */
int wcom_service_txt(const struct wcom_service *,const char **out,char *bytes,size_t capacity);
