#ifndef WENDY_BLECONN_DARWIN_H
#define WENDY_BLECONN_DARWIN_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    WBLE_OK = 0,
    WBLE_ERR_TIMEOUT = 1,
    WBLE_ERR_NOT_FOUND = 2,
    WBLE_ERR_CONNECT = 3,
    WBLE_ERR_DISCOVER = 4,
    WBLE_ERR_READ = 5,
    WBLE_ERR_L2CAP = 6,
    WBLE_ERR_DISCONNECTED = 7,
    WBLE_ERR_UNAUTHORIZED = 8,
    WBLE_ERR_POWERED_OFF = 9,
    WBLE_ERR_INTERNAL = 10,
} wble_err;

#define WBLE_STR_CAP 64

/* One advertising device seen during a scan. */
typedef struct {
    char identifier[WBLE_STR_CAP]; /* per-host CoreBluetooth UUID, not a MAC */
    char local_name[WBLE_STR_CAP]; /* from the scan response */
    char device_id[WBLE_STR_CAP];  /* from the manufacturer data */
    int  rssi;
} wble_scan_item;

/* Scan for wendy-lite peripherals. Returns the number written to items, or -1
 * on error (err is set). Duplicates are allowed while scanning: the first
 * report for a device carries only the advertising payload, and the scan
 * response merges in from the second report on. */
int wble_scan(int timeout_ms, wble_scan_item *items, int max_items, wble_err *err);

typedef void *wble_conn;

/* Connect by CoreBluetooth identifier (as returned by wble_scan). */
wble_conn wble_connect(const char *identifier, int timeout_ms, wble_err *err);

/* Read the whole GATT info service in one go. Every out parameter is
 * optional; string buffers must be at least WBLE_STR_CAP bytes. */
wble_err wble_read_info(wble_conn c, int timeout_ms,
                        uint16_t *psm, uint8_t *mtls,
                        char *device_id, char *device_name, char *display_name);

wble_err wble_open_l2cap(wble_conn c, uint16_t psm, int timeout_ms);

/* Returns bytes written (may be short), or -1 on error. */
int wble_send(wble_conn c, const uint8_t *data, int len);

/* Returns bytes read, 0 on timeout, or -1 at end of stream / on error. */
int wble_recv(wble_conn c, uint8_t *buf, int cap, int timeout_ms);

void wble_close(wble_conn c);

#endif
