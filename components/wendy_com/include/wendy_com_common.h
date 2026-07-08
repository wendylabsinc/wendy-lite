#ifndef WENDY_COM_COMMON_H
#define WENDY_COM_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "wendy_com_msg.pb.h"

struct wcom_app_delegate {
    WendyComResult (*on_app_push_begin)(size_t size, WendyComAppType app_type);
    WendyComResult (*on_app_push_data)(size_t offset, const uint8_t *data, size_t size);
    WendyComResult (*on_app_push_end)(void);
    void (*on_app_push_abort)(void);
    WendyComResult (*on_app_start)(void);
    WendyComResult (*on_app_stop)(void);
    WendyComResult (*on_reboot)(void);
    void (*on_get_device_identity)(const char **id, const char **name, const char **display_name);
    void (*on_get_device_info)(const char **os, const char **os_version,
                               const char **cpu_architecture, const char **board,
                               bool *wasm_app_support, bool *native_app_support);
};

struct wcom_operation {
    void(* func)(struct wcom_operation *op);
    struct wcom_operation *next;
};

#endif
