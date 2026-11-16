#include "wendy_net_direct_records.h"
#include <string.h>
static bool reserve(struct wn_direct_records *r, bool tx, size_t size)
{
    uint8_t **bytes = tx ? &r->tx : &r->rx;
    size_t *capacity = tx ? &r->tx_capacity : &r->rx_capacity;
    if (*capacity >= size)
        return true;
    void *next = r->resize(*bytes, size);
    if (!next)
        return false;
    *bytes = next;
    *capacity = size;
    return true;
}
static void retire(struct wn_direct_records *r, bool tx)
{
    uint8_t **bytes = tx ? &r->tx : &r->rx;
    size_t *capacity = tx ? &r->tx_capacity : &r->rx_capacity;
    (void)r->resize(*bytes, 0);
    *bytes = NULL;
    *capacity = 0;
}
static bool again(int n)
{
    return n == -2 || n == -3;
}
int wn_direct_records_poll(struct wn_direct_records *r, struct wn_direct_session *s, uint64_t token,
                           const struct wn_direct_upper *io, int64_t now,
                           int (*open)(void *, uint32_t), void *arg)
{
    if (!r || !r->resize || !s || !io || !io->read || !io->write || !open ||
        s->closed || !s->attached || s->token != token)
        return -1;
    int progress = 0;
    if (!r->queued) {
        const uint8_t *wire;
        size_t size;
        int ready = wn_direct_session_next(s, now, &wire, &size);
        if (ready < 0)
            return -1;
        if (ready) {
            if (!size || size > WN_DIRECT_MAX_FRAME || !reserve(r, true, size + 2))
                return -1;
            r->tx[0] = (uint8_t)(size >> 8);
            r->tx[1] = (uint8_t)size;
            memcpy(r->tx + 2, wire, size);
            r->queued = size + 2;
            r->sent = 0;
            if (wn_direct_session_accepted(s))
                return -1;
        }
    }
    if (r->queued) {
        size_t left = r->queued - r->sent;
        int n = io->write(io->context, r->tx + r->sent, left);
        if (n > 0) {
            if ((size_t)n > left)
                return -1;
            r->sent += (size_t)n;
            progress = 1;
            if (r->sent == r->queued) {
                r->sent = r->queued = 0;
                retire(r, true);
            }
        } else if (!again(n))
            return -1;
    }
    if (!r->wanted)
        r->wanted = 2;
    if (!reserve(r, false, r->wanted))
        return -1;
    size_t left = r->wanted - r->received;
    int n = io->read(io->context, r->rx + r->received, left);
    if (n > 0) {
        if ((size_t)n > left)
            return -1;
        r->received += (size_t)n;
        progress = 1;
        if (r->received == r->wanted) {
            if (r->wanted == 2) {
                size_t size = ((size_t)r->rx[0] << 8) | r->rx[1];
                if (!size || size > WN_DIRECT_MAX_FRAME)
                    return -1;
                r->wanted = size + 2;
            } else {
                uint32_t id = 0;
                if (wn_direct_session_receive(s, token, r->rx + 2, r->wanted - 2, now, &id) ||
                    (id && open(arg, id)))
                    return -1;
                r->received = 0;
                r->wanted = 2;
                retire(r, false);
            }
        }
    } else if (!again(n))
        return -1;
    return progress;
}
