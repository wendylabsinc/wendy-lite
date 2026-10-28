#include "wendy_net_peer_protocol.h"
#include <string.h>
int wn_assemble(struct wn_assembler *s, const uint8_t *p, size_t n, int64_t now)
{
    if (n < 10 || n > WN_DATAGRAM_MAX || p[0] != 1)
        return -1;
    uint32_t id = wn_get32(p + 1);
    uint16_t total = wn_get16(p + 5), offset = wn_get16(p + 7);
    size_t count = n - 9;
    if (total < 40 || total > WN_MTU || (offset != 0 && offset != 1091) || offset >= total ||
        count != (size_t)(total - offset < 1091 ? total - offset : 1091))
        return -1;
    if (!s->parts || now >= s->deadline_us || s->id != id)
    {
        memset(s, 0, sizeof *s);
        s->id = id;
        s->total = total;
        s->deadline_us = now + INT64_C(2000000);
    }
    unsigned part = offset ? 2 : 1;
    if (s->total != total || (s->parts & part))
    {
        s->parts = 0;
        return -1;
    }
    memcpy(s->packet + offset, p + 9, count);
    s->received += count;
    s->parts |= part;
    if (s->received != total)
        return 0;
    s->parts = 0;
    return (s->packet[0] >> 4) == 6 && wn_get16(s->packet + 4) == total - 40 ? total : -1;
}
size_t wn_fragment(uint8_t out[WN_DATAGRAM_MAX], const uint8_t *p, size_t n, uint32_t id,
                   size_t offset)
{
    if (!(p && n >= 40 && n <= WN_MTU && (p[0] >> 4) == 6 && wn_get16(p + 4) == n - 40) ||
        (offset != 0 && offset != 1091) || offset >= n)
        return 0;
    size_t count = n - offset;
    if (count > 1091)
        count = 1091;
    out[0] = 1;
    wn_put32(out + 1, id);
    wn_put16(out + 5, n);
    wn_put16(out + 7, offset);
    memcpy(out + 9, p + offset, count);
    return count + 9;
}
