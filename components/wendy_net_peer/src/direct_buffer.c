#include "wendy_net_direct_buffer.h"
#include <string.h>

int wn_direct_pool_init_dynamic(struct wn_direct_pool *p, struct wn_direct_slot *slots,
                                uint32_t count, void *(*allocate)(size_t), void (*release)(void *))
{
    if (!p || !slots || !count || count == WN_DIRECT_NONE || !allocate || !release)
        return WN_DIRECT_BOUNDS;
    *p = (struct wn_direct_pool){.slots = slots,
                                 .count = count,
                                 .available = count,
                                 .allocate = allocate,
                                 .release = release};
    for (uint32_t i = 0; i < count; i++)
        slots[i] = (struct wn_direct_slot){.next = i + 1};
    slots[count - 1].next = WN_DIRECT_NONE;
    return 0;
}
static uint32_t *next_slot(struct wn_direct_pool *p, uint32_t i)
{
    return &p->slots[i].next;
}
static uint8_t *payload(struct wn_direct_pool *p, uint32_t i)
{
    return p->slots[i].bytes;
}
void wn_direct_buffer_init(struct wn_direct_buffer *b, struct wn_direct_pool *p)
{
    *b = (struct wn_direct_buffer){.pool = p, .head = WN_DIRECT_NONE, .tail = WN_DIRECT_NONE};
}
int wn_direct_reserve(struct wn_direct_buffer *b, uint64_t through)
{
    if (through <= b->limit)
        return 0;
    if (through > UINT64_MAX - (WN_DIRECT_CHUNK - 1))
        return WN_DIRECT_BOUNDS;
    through = (through + WN_DIRECT_CHUNK - 1) / WN_DIRECT_CHUNK * WN_DIRECT_CHUNK;
    uint64_t count = (through - b->limit) / WN_DIRECT_CHUNK;
    if (count > b->pool->available)
        return WN_DIRECT_CAPACITY;
    /* Allocate the whole extension before changing the free list or the
     * advertised limit. Roll back only this attempt on physical/ledger pressure. */
    {
        struct wn_direct_pool *p = b->pool;
        uint32_t i = p->free;
        for (uint64_t n = 0; n < count; n++, i = p->slots[i].next) {
            p->slots[i].bytes = p->allocate(WN_DIRECT_CHUNK);
            if (!p->slots[i].bytes) {
                for (uint32_t j = p->free; j != i; j = p->slots[j].next) {
                    p->release(p->slots[j].bytes);
                    p->slots[j].bytes = NULL;
                }
                return WN_DIRECT_CAPACITY;
            }
        }
    }
    while (b->limit < through) {
        uint32_t i = b->pool->free;
        b->pool->free = *next_slot(b->pool, i);
        b->pool->available--;
        *next_slot(b->pool, i) = WN_DIRECT_NONE;
        if (b->tail == WN_DIRECT_NONE)
            b->head = i;
        else
            *next_slot(b->pool, b->tail) = i;
        b->tail = i;
        b->limit += WN_DIRECT_CHUNK;
    }
    return 0;
}
static uint32_t chunk_at(const struct wn_direct_buffer *b, uint64_t offset)
{
    uint32_t i = b->head;
    for (uint64_t n = offset / WN_DIRECT_CHUNK - b->start / WN_DIRECT_CHUNK; n; n--)
        i = *next_slot(b->pool, i);
    return i;
}
int wn_direct_append(struct wn_direct_buffer *b, const void *data, size_t size)
{
    if (size > b->limit - b->end)
        return WN_DIRECT_CAPACITY;
    if (!size)
        return 0;
    if (!data)
        return WN_DIRECT_BOUNDS;
    uint32_t i = chunk_at(b, b->end);
    size_t offset = b->end % WN_DIRECT_CHUNK;
    const uint8_t *input = data;
    while (size) {
        size_t n = WN_DIRECT_CHUNK - offset;
        if (n > size)
            n = size;
        memcpy(payload(b->pool, i) + offset, input, n);
        b->end += n;
        input += n;
        size -= n;
        i = *next_slot(b->pool, i);
        offset = 0;
    }
    return 0;
}
int wn_direct_copy(const struct wn_direct_buffer *b, uint64_t offset, void *data, size_t size,
                   size_t *copied)
{
    *copied = 0;
    if (offset < b->start || offset > b->end || (size && !data))
        return WN_DIRECT_BOUNDS;
    if (size > b->end - offset)
        size = (size_t)(b->end - offset);
    if (!size)
        return 0;
    uint32_t i = chunk_at(b, offset);
    size_t within = offset % WN_DIRECT_CHUNK;
    uint8_t *output = data;
    while (size) {
        size_t n = WN_DIRECT_CHUNK - within;
        if (n > size)
            n = size;
        memcpy(output, payload(b->pool, i) + within, n);
        output += n;
        *copied += n;
        size -= n;
        i = *next_slot(b->pool, i);
        within = 0;
    }
    return 0;
}
static void release_head(struct wn_direct_buffer *b)
{
    uint32_t i = b->head;
    b->head = *next_slot(b->pool, i);
    memset(payload(b->pool, i), 0, WN_DIRECT_CHUNK);
    b->pool->release(b->pool->slots[i].bytes);
    b->pool->slots[i].bytes = NULL;
    *next_slot(b->pool, i) = b->pool->free;
    b->pool->free = i;
    b->pool->available++;
    if (b->head == WN_DIRECT_NONE)
        b->tail = WN_DIRECT_NONE;
}
int wn_direct_release(struct wn_direct_buffer *b, uint64_t through)
{
    if (through < b->start || through > b->end)
        return WN_DIRECT_BOUNDS;
    for (uint64_t n = through / WN_DIRECT_CHUNK - b->start / WN_DIRECT_CHUNK; n; n--)
        release_head(b);
    b->start = through;
    return 0;
}
void wn_direct_close(struct wn_direct_buffer *b)
{
    while (b->head != WN_DIRECT_NONE)
        release_head(b);
    b->start = b->end = b->limit = 0;
}
int wn_direct_trim(struct wn_direct_buffer *b)
{
    if (!b || !b->pool || b->start > b->end || b->end > b->limit ||
        b->end > UINT64_MAX - (WN_DIRECT_CHUNK - 1))
        return WN_DIRECT_BOUNDS;
    uint64_t target = (b->end + WN_DIRECT_CHUNK - 1) / WN_DIRECT_CHUNK * WN_DIRECT_CHUNK;
    uint64_t keep = (target - b->start / WN_DIRECT_CHUNK * WN_DIRECT_CHUNK) / WN_DIRECT_CHUNK;
    if (!keep) {
        while (b->head != WN_DIRECT_NONE)
            release_head(b);
    } else {
        uint32_t last = b->head;
        for (uint64_t i = 1; i < keep; i++) {
            if (last == WN_DIRECT_NONE)
                return WN_DIRECT_BOUNDS;
            last = *next_slot(b->pool, last);
        }
        if (last == WN_DIRECT_NONE)
            return WN_DIRECT_BOUNDS;
        struct wn_direct_buffer suffix = {
            .pool = b->pool, .head = *next_slot(b->pool, last), .tail = b->tail};
        *next_slot(b->pool, last) = WN_DIRECT_NONE;
        b->tail = last;
        while (suffix.head != WN_DIRECT_NONE)
            release_head(&suffix);
    }
    b->limit = target;
    return 0;
}
int wn_direct_send_accept(struct wn_direct_sender *s, const void *data, size_t size,
                          uint64_t window)
{
    if (s->finished || size > UINT64_MAX - s->buffer.end || (size && !data))
        return WN_DIRECT_BOUNDS;
    uint64_t end = s->buffer.end + size;
    if (end - s->buffer.start > window)
        return WN_DIRECT_CAPACITY;
    int r = wn_direct_reserve(&s->buffer, end);
    return r ? r : wn_direct_append(&s->buffer, data, size);
}
int wn_direct_send_offer(struct wn_direct_sender *s, uint64_t offset, void *data, size_t size,
                         size_t *copied)
{
    *copied = 0;
    if (offset > s->offered || offset > s->remote_limit)
        return WN_DIRECT_BOUNDS;
    if (size > s->remote_limit - offset)
        size = (size_t)(s->remote_limit - offset);
    int r = wn_direct_copy(&s->buffer, offset, data, size, copied);
    if (!r && offset + *copied > s->offered)
        s->offered = offset + *copied;
    return r;
}
int wn_direct_send_state(struct wn_direct_sender *s, uint64_t received, uint64_t limit)
{
    if (received < s->buffer.start || received > s->offered || limit < received ||
        limit < s->remote_limit)
        return WN_DIRECT_BOUNDS;
    int r = wn_direct_release(&s->buffer, received);
    if (!r)
        s->remote_limit = limit;
    return r;
}
uint64_t wn_direct_send_finish(struct wn_direct_sender *s)
{
    if (!s->finished) {
        s->finished = true;
        s->final = s->buffer.end;
    }
    return s->final;
}
int wn_direct_receive(struct wn_direct_receiver *r, const void *data, size_t size)
{
    if (r->finished && size > r->final - r->buffer.end)
        return WN_DIRECT_BOUNDS;
    return wn_direct_append(&r->buffer, data, size);
}
int wn_direct_receive_finish(struct wn_direct_receiver *r, uint64_t final)
{
    if (final < r->buffer.end || (r->finished && r->final != final))
        return WN_DIRECT_BOUNDS;
    r->final = final;
    r->finished = true;
    return 0;
}
bool wn_direct_receive_eof(const struct wn_direct_receiver *r)
{
    return r->finished && r->buffer.start == r->final;
}
