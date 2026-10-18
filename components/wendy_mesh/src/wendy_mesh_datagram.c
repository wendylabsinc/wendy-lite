#include "wendy_mesh_datagram.h"
#include <limits.h>
#include <string.h>
static uint64_t get(const uint8_t* p, unsigned n)
{
    uint64_t v = 0;
    while (n--)
        v = v << 8 | *p++;
    return v;
}
static void put(uint8_t* p, uint64_t v, unsigned n)
{
    while (n) {
        p[--n] = v;
        v >>= 8;
    }
}
static void emit(struct wm_datagram* s, uint8_t kind, uint32_t seq,
    const uint8_t* data, size_t n, wm_datagram_send send, void* ctx)
{
    uint8_t frame[WM_DG_MAX] = { 'W', 'M', 'N', '3', kind };
    put(frame + 5, s->local, 8);
    put(frame + 13, kind == 1 ? 0 : s->remote, 8);
    put(frame + 21, seq, 4);
    if (n)
        memcpy(frame + WM_DG_HEADER, data, n);
    /* Queue pressure is handled by retransmission, never by losing bytes. */
    (void)send(ctx, frame, WM_DG_HEADER + n);
}
void wm_datagram_init(struct wm_datagram* s, uint64_t epoch)
{
    memset(s, 0, sizeof *s);
    s->local = epoch;
    s->tx_seq = s->rx_seq = 1;
    s->failed = epoch == 0;
    s->last_tx = -150000;
}
void wm_datagram_receive(struct wm_datagram* s, const uint8_t* p, size_t n,
    wm_datagram_send send, void* ctx)
{
    if (s->failed || n < WM_DG_HEADER || n > WM_DG_MAX || memcmp(p, "WMN3", 4))
        return;
    uint8_t kind = p[4];
    uint64_t source = get(p + 5, 8), dest = get(p + 13, 8);
    uint32_t seq = get(p + 21, 4);
    size_t count = n - WM_DG_HEADER;
    if (!source || source == s->local || kind < 1 || kind > 4)
        return;
    if (kind == 1 || kind == 2) {
        if (count || seq || (kind == 1 ? dest != 0 : dest != s->local))
            return;
        if (s->remote && s->remote != source)
            return;
        s->remote = source;
        if (kind == 1)
            emit(s, 2, 0, NULL, 0, send, ctx);
        else
            s->connected = true;
        return;
    }
    if (!s->remote || source != s->remote || dest != s->local)
        return;
    /* DATA can arrive before our HELLO_ACK. Both epochs prove it belongs
     * to this connection, and the TLS handshake still authenticates peers. */
    s->connected = true;
    if (kind == 4) {
        if (!count && s->tx_size && seq == s->tx_seq) {
            s->tx_size = 0;
            if (++s->tx_seq == 0)
                s->failed = true;
        }
        return;
    }
    if (!count || !seq)
        return;
    if (seq == s->rx_seq && count <= WM_DG_BUFFER - s->size) {
        for (size_t i = 0; i < count; ++i)
            s->ring[(s->head + s->size + i) % WM_DG_BUFFER] = p[WM_DG_HEADER + i];
        s->size += count;
        if (++s->rx_seq == 0)
            s->failed = true;
    }
    /* A full receiver withholds ACK; duplicates are ACKed but never copied. */
    if (seq == s->rx_seq - 1)
        emit(s, 4, seq, NULL, 0, send, ctx);
}
int wm_datagram_tick(struct wm_datagram* s, int64_t now, wm_datagram_send send, void* ctx)
{
    if (s->failed)
        return -1;
    if (s->tx_size && now - s->pending_since >= INT64_C(5000000)) {
        s->failed = true;
        return -1;
    }
    if (now - s->last_tx < 150000)
        return 0;
    if (!s->connected)
        emit(s, 1, 0, NULL, 0, send, ctx);
    else if (s->tx_size)
        emit(s, 3, s->tx_seq, s->tx, s->tx_size, send, ctx);
    s->last_tx = now;
    return 0;
}
int wm_datagram_read(struct wm_datagram* s, void* buffer, size_t n)
{
    if (s->failed)
        return -1;
    if (!n)
        return 0;
    if (!s->size)
        return -2;
    if (n > s->size)
        n = s->size;
    uint8_t* out = buffer;
    for (size_t i = 0; i < n; ++i)
        out[i] = s->ring[(s->head + i) % WM_DG_BUFFER];
    s->head = (s->head + n) % WM_DG_BUFFER;
    s->size -= n;
    return (int)n;
}
int wm_datagram_write(struct wm_datagram* s, const void* buffer, size_t n, int64_t now)
{
    if (s->failed)
        return -1;
    if (!n)
        return 0;
    if (!s->connected || s->tx_size)
        return -3;
    if (n > WM_DG_PAYLOAD)
        n = WM_DG_PAYLOAD;
    memcpy(s->tx, buffer, n);
    s->tx_size = n;
    s->pending_since = now;
    s->last_tx = now - 150000;
    return (int)n;
}
