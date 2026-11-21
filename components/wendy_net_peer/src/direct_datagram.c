#include "wendy_net_direct_datagram.h"
#include <string.h>
int wn_direct_datagram_init(struct wn_direct_datagram *r, uint32_t flow, uint8_t *storage,
                            size_t capacity)
{
    if (!r || !flow || !storage || !capacity || capacity > UINT16_MAX)
        return -1;
    *r = (struct wn_direct_datagram){.flow = flow, .storage = storage, .capacity = capacity};
    return 0;
}
int wn_direct_datagram_bind(struct wn_direct_datagram *r, uint64_t generation, uint32_t alias)
{
    if (!r || !r->storage || !generation || generation <= r->generation || !alias)
        return -1;
    r->generation = generation;
    r->alias = alias;
    r->active = false;
    return 0;
}
void wn_direct_datagram_suspend(struct wn_direct_datagram *r)
{
    if (r) {
        r->alias = 0;
        r->active = false;
    }
}
int wn_direct_datagram_receive(struct wn_direct_datagram *r, uint64_t generation,
                               const struct wn_direct_frame *f, const uint8_t **out, size_t *size)
{
    if (!out || !size)
        return -1;
    *out = NULL;
    *size = 0;
    if (!r || !r->storage || !f)
        return -1;
    if (!r->alias || generation != r->generation || f->attachment_id != r->alias)
        return 0;
    size_t encoded;
    if (f->kind != WN_DIRECT_DATAGRAM || f->flow_id != r->flow || wn_direct_frame_size(f, &encoded))
        return -1;
    if (f->value < r->last_id || (f->value == r->last_id && !r->active))
        return 0;
    if (f->value > r->last_id) {
        r->last_id = f->value;
        r->active = false;
        if (f->fragment_offset || f->datagram_size > r->capacity)
            return 0;
        r->total = f->datagram_size;
        r->received = 0;
        r->active = true;
    }
    if (f->datagram_size != r->total || f->fragment_offset != r->received) {
        r->active = false;
        return 0;
    }
    if (f->payload_size)
        memmove(r->storage + r->received, f->payload, f->payload_size);
    r->received += f->payload_size;
    if (r->received != r->total)
        return 0;
    r->active = false;
    *out = r->storage;
    *size = r->total;
    return 1;
}

int wn_direct_datagram_sender_init(struct wn_direct_datagram_sender *s, uint32_t flow,
                                   uint8_t *storage, size_t capacity)
{
    if (!s || !flow || !storage || !capacity || capacity > UINT16_MAX)
        return -1;
    *s = (struct wn_direct_datagram_sender){.flow = flow, .storage = storage, .capacity = capacity};
    return 0;
}
void wn_direct_datagram_sender_suspend(struct wn_direct_datagram_sender *s)
{
    if (s) {
        s->alias = 0;
        s->active = false;
        s->pending = false;
    }
}
int wn_direct_datagram_sender_bind(struct wn_direct_datagram_sender *s, uint64_t generation,
                                   uint32_t alias)
{
    if (!s || !s->storage || !generation || generation <= s->generation || !alias)
        return -1;
    wn_direct_datagram_sender_suspend(s);
    s->generation = generation;
    s->alias = alias;
    return 0;
}
int wn_direct_datagram_queue(struct wn_direct_datagram_sender *s, const uint8_t *data, size_t size)
{
    if (!s || !s->storage || !s->alias || (size && !data) || size > s->capacity ||
        s->last_id == UINT64_MAX)
        return -1;
    if (s->active)
        return -2;
    if (size)
        memmove(s->storage, data, size);
    s->last_id++;
    s->total = size;
    s->offset = 0;
    s->active = true;
    return 0;
}
int wn_direct_datagram_prepare(struct wn_direct_datagram_sender *s, struct wn_direct_frame *f)
{
    if (!f)
        return -1;
    memset(f, 0, sizeof *f);
    if (!s || !s->storage)
        return -1;
    if (!s->active || !s->alias)
        return 0;
    size_t n = s->total - s->offset;
    if (n > WN_DIRECT_MAX_DATA)
        n = WN_DIRECT_MAX_DATA;
    s->pending = true;
    s->pending_size = n;
    *f = (struct wn_direct_frame){.kind = WN_DIRECT_DATAGRAM,
                                  .attachment_id = s->alias,
                                  .flow_id = s->flow,
                                  .value = s->last_id,
                                  .datagram_size = (uint16_t)s->total,
                                  .fragment_offset = (uint16_t)s->offset,
                                  .payload = s->storage + s->offset,
                                  .payload_size = n};
    return 1;
}
int wn_direct_datagram_accepted(struct wn_direct_datagram_sender *s, uint64_t generation,
                                uint64_t id, uint16_t offset)
{
    if (!s || !s->pending || !s->alias || generation != s->generation || id != s->last_id ||
        offset != s->offset)
        return -1;
    s->offset += s->pending_size;
    s->pending = false;
    if (s->offset == s->total)
        s->active = false;
    return 0;
}
