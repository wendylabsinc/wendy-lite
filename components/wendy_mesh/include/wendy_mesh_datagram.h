#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* ESP-NOW v1-compatible wire format. All integers are big endian.
 * 4 magic + 1 kind + 8 source epoch + 8 destination epoch + 4 sequence.
 * Kind 1 opens an epoch, 2 acknowledges it, 3 carries bytes, 4 acknowledges bytes.
 * This layer provides ordering only. TLS authenticates the byte stream. */
#define WM_DG_HEADER 25
#define WM_DG_PAYLOAD 225
#define WM_DG_MAX 250
#define WM_DG_BUFFER 65536
struct wm_datagram {
    uint64_t local, remote;
    uint32_t tx_seq, rx_seq;
    uint8_t tx[WM_DG_PAYLOAD], ring[WM_DG_BUFFER];
    size_t tx_size, head, size;
    int64_t last_tx, pending_since;
    bool connected, failed;
};
typedef int (*wm_datagram_send)(void*, const uint8_t*, size_t);
void wm_datagram_init(struct wm_datagram*, uint64_t epoch);
/* Receive and tick may emit frames. Call from one task, never a Wi-Fi callback. */
void wm_datagram_receive(struct wm_datagram*, const uint8_t*, size_t,
    wm_datagram_send, void*);
int wm_datagram_tick(struct wm_datagram*, int64_t now_us, wm_datagram_send, void*);
int wm_datagram_read(struct wm_datagram*, void*, size_t);
int wm_datagram_write(struct wm_datagram*, const void*, size_t, int64_t now_us);
