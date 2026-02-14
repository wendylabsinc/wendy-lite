#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Wire Protocol ──────────────────────────────────────────────────── */

/**
 * All messages are framed as:
 *   [MAGIC:2][TYPE:1][SEQ:1][LENGTH:4][PAYLOAD:LENGTH][CRC32:4]
 *
 * Total overhead: 12 bytes per message.
 */

#define WENDY_USB_MAGIC          0x5759  /* 'WY' */
#define WENDY_USB_HEADER_SIZE    8
#define WENDY_USB_CRC_SIZE       4

/* Message types (CLI → Device) */
#define WENDY_MSG_PING           0x01
#define WENDY_MSG_UPLOAD_START   0x10
#define WENDY_MSG_UPLOAD_CHUNK   0x11
#define WENDY_MSG_UPLOAD_DONE    0x12
#define WENDY_MSG_RUN            0x20
#define WENDY_MSG_STOP           0x21
#define WENDY_MSG_RESET          0x30
#define WENDY_MSG_DEBUG_ATTACH   0x40

/* Message types (Device → CLI) */
#define WENDY_MSG_DEVICE_INFO    0x81
#define WENDY_MSG_ACK            0x82
#define WENDY_MSG_NACK           0x83
#define WENDY_MSG_STDOUT         0x90
#define WENDY_MSG_MEM_STATS      0x91

/* ── Message header (on the wire) ───────────────────────────────────── */

typedef struct __attribute__((packed)) {
    uint16_t magic;      /* WENDY_USB_MAGIC */
    uint8_t  type;       /* Message type */
    uint8_t  seq;        /* Sequence number */
    uint32_t length;     /* Payload length (excludes header and CRC) */
} wendy_usb_header_t;

/* ── PING payload ───────────────────────────────────────────────────── */

typedef struct __attribute__((packed)) {
    uint8_t  protocol_version;
} wendy_usb_ping_t;

/* ── DEVICE_INFO payload (response to PING) ─────────────────────────── */

typedef struct __attribute__((packed)) {
    uint8_t  protocol_version;
    uint8_t  fw_version_major;
    uint8_t  fw_version_minor;
    uint8_t  fw_version_patch;
    uint8_t  board_type;         /* 0=unknown, 1=ESP32, 2=ESP32-S3, 3=RP2040, 4=ESP32-C6 */
    uint8_t  capabilities;       /* bitmask: bit0=wasm, bit1=native, bit2=wifi, bit3=ble */
    uint32_t flash_free;         /* bytes available for WASM binary */
    uint32_t sram_free;          /* bytes of free SRAM */
    uint8_t  wasm_slot_active;   /* 0=A, 1=B */
    uint8_t  has_wasm_loaded;    /* 1 if a WASM binary is present */
} wendy_usb_device_info_t;

/* ── UPLOAD_START payload ───────────────────────────────────────────── */

typedef struct __attribute__((packed)) {
    uint32_t total_size;      /* Total WASM binary size */
    uint32_t crc32;           /* CRC32 of the complete binary */
    uint8_t  slot;            /* Target slot: 0=A, 1=B */
} wendy_usb_upload_start_t;

/* ── UPLOAD_CHUNK payload ───────────────────────────────────────────── */

typedef struct __attribute__((packed)) {
    uint32_t offset;          /* Byte offset within the binary */
    /* Followed by chunk data bytes */
} wendy_usb_upload_chunk_t;

/* ── Callbacks for protocol events ──────────────────────────────────── */

typedef struct {
    /** Called when a valid WASM binary has been fully uploaded. */
    void (*on_upload_complete)(const uint8_t *data, uint32_t len, uint8_t slot);

    /** Called when the CLI sends RUN. */
    void (*on_run)(void);

    /** Called when the CLI sends STOP. */
    void (*on_stop)(void);

    /** Called when the CLI sends RESET. */
    void (*on_reset)(void);
} wendy_usb_callbacks_t;

/* ── Public API ─────────────────────────────────────────────────────── */

/**
 * Initialize the USB CDC protocol handler.
 * Starts a background task that reads from USB and dispatches messages.
 */
esp_err_t wendy_usb_init(const wendy_usb_callbacks_t *callbacks);

/**
 * Send stdout data to the CLI.
 */
esp_err_t wendy_usb_send_stdout(const char *data, uint32_t len);

/**
 * Send memory statistics to the CLI.
 */
esp_err_t wendy_usb_send_mem_stats(uint32_t heap_total, uint32_t heap_used,
                                    uint32_t stack_peak);

/**
 * Deinitialize USB protocol handler.
 */
void wendy_usb_deinit(void);

#ifdef __cplusplus
}
#endif
