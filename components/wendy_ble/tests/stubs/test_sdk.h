#ifndef TEST_SDK_H
#define TEST_SDK_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_NOT_SUPPORTED 0x106
static inline const char *esp_err_to_name(esp_err_t err) { return "stub"; }
#define ESP_LOGI(tag, ...) ((void)(tag))
#define ESP_LOGW(tag, ...) ((void)(tag))
#define ESP_LOGE(tag, ...) ((void)(tag))
#define ESP_LOGD(tag, ...) ((void)(tag))
#define MALLOC_CAP_8BIT 1
static inline size_t heap_caps_get_free_size(int caps) { return 100000; }
static inline size_t heap_caps_get_largest_free_block(int caps) { return 100000; }
static inline void esp_system_abort(const char *reason) { abort(); }

typedef unsigned TickType_t;
typedef void *SemaphoreHandle_t;
#define portMAX_DELAY UINT32_MAX
#define pdPASS 1
extern bool test_fail_semaphore, test_fail_task;
extern unsigned test_semaphore_calls, test_semaphores_allocated, test_semaphores_deleted;
extern unsigned test_task_calls, test_tasks_created, test_task_stack;
static inline SemaphoreHandle_t xSemaphoreCreateBinary(void) {
    ++test_semaphore_calls;
    if (test_fail_semaphore) return NULL;
    void *sem = malloc(1);
    assert(sem);
    ++test_semaphores_allocated;
    return sem;
}
static inline int xSemaphoreGive(SemaphoreHandle_t sem) { return 1; }
static inline int xSemaphoreTake(SemaphoreHandle_t sem, TickType_t timeout) { return 1; }
static inline void vSemaphoreDelete(SemaphoreHandle_t sem) {
    assert(sem);
    ++test_semaphores_deleted;
    free(sem);
}
static inline int xTaskCreatePinnedToCore(void (*fn)(void *), const char *name,
        unsigned stack, void *arg, int priority, void *handle, int core) {
    ++test_task_calls;
    test_task_stack = stack;
    if (test_fail_task) return 0;
    ++test_tasks_created;
    return pdPASS;
}

struct wendy_conf_span { const void *data; size_t size; };
extern bool test_enrolled, test_reset, test_current;
extern char test_enrollment_device_id[65];
static inline bool wendy_conf_has_enrollment(void) { return test_enrolled; }
static inline bool wendy_conf_is_current(void) { return test_current; }
static inline void wendy_conf_enrollment_identity(char tenant[37], char device[65]) {
    tenant[0] = device[0] = '\0';
    if (test_current && test_enrolled) {
        strcpy(tenant, "11111111-2222-3333-4444-555555555555");
        strcpy(device, test_enrollment_device_id);
    }
}
static inline bool wendy_pki_reset_in_progress(void) { return test_reset; }
static inline const char *wendy_conf_get_device_id(void) { return "lite-123"; }
static inline const char *wendy_conf_get_resolved_device_name(void) { return "wendy-lite-123"; }
static inline const char *wendy_conf_get_resolved_device_display_name(void) { return "Test Lite"; }

typedef struct { uint8_t type; } ble_uuid_t;
typedef struct { ble_uuid_t u; uint8_t value[16]; } ble_uuid128_t;
#define BLE_UUID128_INIT(...) { .u = { 128 }, .value = { __VA_ARGS__ } }
struct os_mbuf { uint8_t data[128]; size_t len; };
static inline int os_mbuf_append(struct os_mbuf *buf, const void *data, uint16_t len) {
    assert(buf->len + len <= sizeof(buf->data));
    memcpy(buf->data + buf->len, data, len); buf->len += len; return 0;
}
struct ble_gatt_access_ctxt { uint8_t op; struct os_mbuf *om; };
struct ble_gatt_chr_def {
    const ble_uuid_t *uuid;
    int (*access_cb)(uint16_t, uint16_t, struct ble_gatt_access_ctxt *, void *);
    void *arg;
    int flags;
};
struct ble_gatt_svc_def {
    int type;
    const ble_uuid_t *uuid;
    const struct ble_gatt_chr_def *characteristics;
};
#define BLE_GATT_CHR_F_READ 1
#define BLE_GATT_SVC_TYPE_PRIMARY 1
#define BLE_GATT_ACCESS_OP_READ_CHR 1
#define BLE_ATT_ERR_UNLIKELY 14
#define BLE_ATT_ERR_INSUFFICIENT_RES 17
#define BLE_HS_ADV_F_DISC_GEN 2
#define BLE_HS_ADV_F_BREDR_UNSUP 4
#define BLE_GAP_CONN_MODE_UND 2
#define BLE_GAP_DISC_MODE_GEN 2
#define BLE_GAP_ADV_ITVL_MS(ms) (ms)
#define BLE_HS_FOREVER INT32_MAX
#define BLE_HS_EALREADY 2
#define BLE_GAP_EVENT_CONNECT 1
#define BLE_GAP_EVENT_DISCONNECT 2
#define BLE_GAP_EVENT_ADV_COMPLETE 3
#define BLE_GAP_EVENT_MTU 4
struct ble_hs_adv_fields {
    uint8_t flags;
    const ble_uuid128_t *uuids128;
    uint8_t num_uuids128, uuids128_is_complete;
    const uint8_t *mfg_data;
    uint8_t mfg_data_len;
    const uint8_t *name;
    uint8_t name_len, name_is_complete;
};
struct ble_gap_adv_params { int conn_mode, disc_mode, itvl_min, itvl_max; };
struct ble_gap_event {
    int type;
    struct { int status; uint16_t conn_handle; } connect;
    struct { int reason; } disconnect;
    struct { int value; } mtu;
};
struct test_hs_cfg { void (*sync_cb)(void); void (*reset_cb)(int); };
extern struct test_hs_cfg ble_hs_cfg;
extern struct ble_hs_adv_fields test_adv, test_rsp;
extern const struct ble_gatt_svc_def *test_services;
extern unsigned test_adv_starts;
static inline int ble_gap_adv_set_fields(const struct ble_hs_adv_fields *fields) {
    test_adv = *fields; return 0;
}
static inline int ble_gap_adv_rsp_set_fields(const struct ble_hs_adv_fields *fields) {
    test_rsp = *fields; return 0;
}
static inline int ble_gap_adv_start(uint8_t type, const void *addr, int duration,
        const struct ble_gap_adv_params *params,
        int (*cb)(struct ble_gap_event *, void *), void *arg) {
    ++test_adv_starts; return 0;
}
static inline int ble_hs_util_ensure_addr(int privacy) { return 0; }
static inline int ble_hs_id_infer_auto(int privacy, uint8_t *type) { *type = 0; return 0; }
static inline int ble_hs_synced(void) { return 1; }
extern bool test_nimble_initialized;
static inline esp_err_t nimble_port_init(void) {
    test_nimble_initialized = true;
    return ESP_OK;
}
static inline void nimble_port_run(void) {}
static inline void nimble_port_freertos_deinit(void) {}
static inline void nimble_port_freertos_init(void (*fn)(void *)) {}
static inline void ble_svc_gap_init(void) {}
static inline void ble_svc_gatt_init(void) {}
static inline int ble_gatts_count_cfg(const struct ble_gatt_svc_def *svcs) { return 0; }
static inline int ble_gatts_add_svcs(const struct ble_gatt_svc_def *svcs) {
    test_services = svcs; return 0;
}
static inline int ble_svc_gap_device_name_set(const char *name) {
    // NimBLE takes its host mutex here, which only exists after port init.
    assert(test_nimble_initialized);
    return 0;
}

enum wcom_interruption_reason { WCOM_INTERRUPTION_CONNECTION_CLOSED };
struct wcom_operation { void (*func)(struct wcom_operation *); };
struct wcom_stream_ops {
    ssize_t (*read)(void *, void *, size_t);
    ssize_t (*write)(void *, const void *, size_t);
    int (*wakeup_fd)(void *);
    bool (*can_read)(void *);
    bool (*can_write)(void *);
};
#define WCOM_STREAM_ERR_UNKNOWN -1
#define WCOM_STREAM_ERR_WANT_READ -2
#define WCOM_STREAM_ERR_WANT_WRITE -3
static inline void wcom_remove_link(int id) {}
static inline int wcom_add_stream_link(const struct wcom_stream_ops *ops, void *ctx,
        void (*cb)(int, enum wcom_interruption_reason)) { return 0; }
static inline void wcom_core_exec(struct wcom_operation *op) {}

#endif
