#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define WN_DIRECT_WIRE_VERSION 1
#define WN_DIRECT_CAP_VERSION UINT32_C(2)
#define WN_DIRECT_CAP_TLS (UINT32_C(1) << 8)
#define WN_DIRECT_CAP_QUIC (UINT32_C(1) << 9)
/* Profile 2 requires retirement, lane reuse and capacity records. Only upper
 * transport varies. Development profile 1 falls back to ordinary upper TLS. */
static inline uint32_t wn_direct_selected_transport(uint32_t selected)
{
    return selected == (WN_DIRECT_CAP_VERSION | WN_DIRECT_CAP_TLS) ||
                   selected == (WN_DIRECT_CAP_VERSION | WN_DIRECT_CAP_QUIC)
               ? selected : 0;
}
#define WN_DIRECT_MAX_DATA 512
#define WN_DIRECT_MAX_STATES 4
#define WN_DIRECT_MAX_FRAME 533
enum wn_direct_frame_kind {
    WN_DIRECT_DATA = 1,
    WN_DIRECT_STATE,
    WN_DIRECT_FIN,
    WN_DIRECT_OPEN,
    WN_DIRECT_OPEN_RESULT,
    WN_DIRECT_OPEN_CREDIT,
    WN_DIRECT_DATAGRAM,
    WN_DIRECT_RESET,
    WN_DIRECT_CLOSE_ACK,
    WN_DIRECT_DATAGRAM_LIMIT,
    WN_DIRECT_EPOCH_IDLE
};
enum wn_direct_service {
    WN_DIRECT_TCP = 1,
    WN_DIRECT_UDP,
    WN_DIRECT_WENDYCOM,
    WN_DIRECT_GRPC_ADMIN
};
struct wn_direct_state_entry {
    uint32_t flow_id;
    uint64_t received, limit;
    bool fin_seen;
};
/* Actor-owned bounded record. Decode borrows payload from input; reserve/copy
 * receive storage before ACK, and do not retain across input-buffer reuse.
 * value: FIN offset, cumulative OPEN credit, or datagram ID.
 * DATAGRAM_LIMIT uses datagram_size for the attachment-scoped maximum for new
 * UDP OPENs (zero disables); it has no flow_id.
 * Only use after negotiated capability and authenticated attachment commit. */
struct wn_direct_frame {
    uint8_t kind, state_count, service;
    uint32_t attachment_id, flow_id;
    uint64_t value;
    uint16_t port, datagram_size, fragment_offset, code;
    const uint8_t *payload;
    size_t payload_size;
    struct wn_direct_state_entry states[WN_DIRECT_MAX_STATES];
};
/* All integers big endian. Enclosing lane supplies exact record length.
 * Encode destination must not overlap payload. Invalid/short encode writes
 * nothing. Decode clears output on error. Both functions allocate nothing. */
int wn_direct_frame_size(const struct wn_direct_frame *, size_t *);
int wn_direct_frame_encode(const struct wn_direct_frame *, uint8_t *, size_t, size_t *);
int wn_direct_frame_decode(const uint8_t *, size_t, struct wn_direct_frame *);
