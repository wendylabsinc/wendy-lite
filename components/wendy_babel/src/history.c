/* SPDX-License-Identifier: Apache-2.0 */
#include "storage.h"
#include "wendy_babel.h"
#include <string.h>
static void put64(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++)
        p[7 - i] = (uint8_t)(v >> (8 * i));
}
static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++)
        v = v << 8 | p[i];
    return v;
}
static void put16(uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v;
}
static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)((unsigned)p[0] << 8 | p[1]);
}
static void put_prefix(uint8_t *p, const struct wb_prefix *pre)
{
    memcpy(p, pre->bytes, 16);
    p[16] = pre->bits;
    p[17] = pre->family;
}
static bool get_prefix(const uint8_t *p, struct wb_prefix *pre)
{
    memcpy(pre->bytes, p, 16);
    pre->bits = p[16];
    pre->family = p[17];
    return wb_prefix_valid(pre);
}
int wb_save(const struct wb_engine *e, uint8_t *out, size_t cap)
{
    if (!e || (out && cap < 40) || e->stopped)
        return WB_INVALID;
    if (out)
    {
        memset(out, 0, 40);
        memcpy(out, "WBC1", 4);
        put64(out + 4, e->config.router);
        put16(out + 12, e->seqno);
        put64(out + 14, e->last_link);
    }
    uint16_t sources = 0, drops = 0;
    size_t n = 40;
    for (unsigned i = 0; i < e->sources_capacity; i++)
        if (e->sources[i].used)
        {
            if (out && cap - n < 30)
                return WB_LIMIT;
            const struct wb_source *s = &e->sources[i];
            if (out)
            {
                put_prefix(out + n, &s->prefix);
                put64(out + n + 18, s->router);
                put16(out + n + 26, s->seqno);
                put16(out + n + 28, s->metric);
            }
            n += 30;
            sources++;
        }
    /* All selected prefixes enter suppression after reboot, including those
     * already unreachable. Expired drops cannot be forgotten prematurely. */
    for (size_t i = 0; i < e->route_count; i++)
    {
        if (out && cap - n < 18)
            return WB_LIMIT;
        if (out)
            put_prefix(out + n, &e->routes[i].prefix);
        n += 18;
        drops++;
    }
    for (unsigned i = 0; i < e->drops_capacity; i++)
        if (e->drops[i].used)
        {
            bool found = false;
            for (size_t j = 0; j < e->route_count; j++)
                found |=
                    wb_prefix_equal(&e->drops[i].prefix, &e->routes[j].prefix);
            if (found)
                continue;
            if (drops == WB_ROUTES || (out && cap - n < 18))
                return WB_LIMIT;
            if (out)
                put_prefix(out + n, &e->drops[i].prefix);
            n += 18;
            drops++;
        }
    if (!out)
        return (int)n;
    put16(out + 22, sources);
    put16(out + 24, drops);
    /* Persist lifetimes as configuration, never trust wall-clock downtime. */
    out[26] = (uint8_t)(e->config.source_ms >> 24);
    out[27] = (uint8_t)(e->config.source_ms >> 16);
    out[28] = (uint8_t)(e->config.source_ms >> 8);
    out[29] = (uint8_t)e->config.source_ms;
    uint32_t drop_ms = e->config.update_ms * 7 / 2;
    for (unsigned i = 0; i < e->drops_capacity; i++)
        if (e->drops[i].used && e->drops[i].expires > e->now &&
            e->drops[i].expires - e->now > drop_ms)
            drop_ms = (uint32_t)(e->drops[i].expires - e->now);
    out[30] = (uint8_t)(drop_ms >> 24);
    out[31] = (uint8_t)(drop_ms >> 16);
    out[32] = (uint8_t)(drop_ms >> 8);
    out[33] = (uint8_t)drop_ms;
    return (int)n;
}
int wb_restore(struct wb_engine *e, const struct wb_config *config,
               const uint8_t *data, size_t size)
{
    if (!e || !config || !data || size < 40 || memcmp(data, "WBC1", 4) ||
        get64(data + 4) != config->router || data[34] || data[35] || data[36] ||
        data[37] || data[38] || data[39])
        return WB_INVALID;
    unsigned sources = get16(data + 22), drops = get16(data + 24);
    if (sources > WB_SOURCES || drops > WB_ROUTES ||
        size != 40 + sources * 30 + drops * 18)
        return WB_INVALID;
    uint32_t source_ms = (uint32_t)data[26] << 24 | (uint32_t)data[27] << 16 |
                         (uint32_t)data[28] << 8 | data[29];
    if (source_ms < 180000 || source_ms > 86400000)
        return WB_INVALID;
    uint32_t drop_ms = (uint32_t)data[30] << 24 | (uint32_t)data[31] << 16 |
                       (uint32_t)data[32] << 8 | data[33];
    if (!drop_ms || drop_ms > 86400000)
        return WB_INVALID;
    struct wb_config c = *config;
    c.seqno = get16(data + 12);
    if (c.source_ms < source_ms)
        c.source_ms = source_ms;
    int r = wb_init(e, &c);
    if (r)
        return r;
    if (!wb_reserve_sources(e, sources) || !wb_reserve_drops(e, drops))
    {
        e->stopped = true;
        return WB_LIMIT;
    }
    e->last_link = get64(data + 14);
    size_t n = 40;
    for (unsigned i = 0; i < sources; i++, n += 30)
    {
        struct wb_source *s = &e->sources[i];
        if (!get_prefix(data + n, &s->prefix))
            goto invalid;
        s->router = get64(data + n + 18);
        s->seqno = get16(data + n + 26);
        s->metric = get16(data + n + 28);
        if (!s->router || s->router == UINT64_MAX || s->metric == WB_INFINITY)
            goto invalid;
        for (unsigned j = 0; j < i; j++)
            if (s->router == e->sources[j].router &&
                wb_prefix_equal(&s->prefix, &e->sources[j].prefix))
                goto invalid;
        s->used = true;
        s->expires = e->config.source_ms;
    }
    for (unsigned i = 0; i < drops; i++, n += 18)
    {
        struct wb_drop *d = &e->drops[i];
        if (!get_prefix(data + n, &d->prefix))
            goto invalid;
        for (unsigned j = 0; j < i; j++)
            if (wb_prefix_equal(&d->prefix, &e->drops[j].prefix))
                goto invalid;
        d->used = true;
        d->expires = drop_ms > e->config.update_ms * 7 / 2
                         ? drop_ms
                         : e->config.update_ms * 7 / 2;
    }
    return WB_OK;
invalid:
    e->stopped = true;
    return WB_INVALID;
}
