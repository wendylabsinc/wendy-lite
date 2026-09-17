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
    WendyComResult (*on_conf_push_begin)(size_t size, WendyComConfPushMode mode);
    WendyComResult (*on_conf_push_data)(size_t offset, const uint8_t *data, size_t size);
    WendyComResult (*on_conf_push_end)(void);
    void (*on_conf_push_abort)(void);
    WendyComResult (*on_app_start)(void);
    WendyComResult (*on_app_stop)(void);
    WendyComResult (*on_reboot)(bool app_auto_start, uint32_t app_auto_start_delay_ms);
    void (*on_get_device_identity)(const char **id, const char **name, const char **display_name);
    void (*on_get_device_info)(const char **os, const char **os_version,
                               const char **cpu_architecture, const char **target,
                               bool *wasm_app_support, bool *native_app_support);
};

// An operation to run on the com task. Set `func`; `next` belongs to the queue
// and is never read from the caller. Once queued, the node is the queue's until
// its `func` starts running: until then, do not modify any part of it, nor any
// payload embedded around it. See wcom_core_exec() in wendy_com_link.h.
struct wcom_operation {
    void(* func)(struct wcom_operation *op);
    struct wcom_operation *next;
};

#endif
