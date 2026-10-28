/* SPDX-License-Identifier: Apache-2.0
 * Lazy bounded tables. No reservation for maximum mesh size at startup.
 */
#include "storage.h"
#include "wendy_net_alloc.h"
#include <stdlib.h>
#include <string.h>

static void release(struct wb_engine *e, void *p, size_t bytes)
{
    if (!p)
        return;
    if (e->config.deallocate)
        e->config.deallocate(e->config.memory_context, p);
    else
        wendy_net_free(p);
    e->allocated_bytes -= bytes;
}
static void *resize(struct wb_engine *e, void *old, size_t old_count, size_t count, size_t item)
{
    if (!count)
    {
        release(e, old, old_count * item);
        return NULL;
    }
    if (count > SIZE_MAX / item)
        return NULL;
    size_t bytes = count * item;
    void *p =
        e->config.allocate ? e->config.allocate(e->config.memory_context, bytes) : wendy_net_malloc(bytes);
    if (!p)
    {
        e->counters.allocation_failures++;
        return NULL;
    }
    memset(p, 0, bytes);
    e->allocated_bytes += bytes;
    if (e->allocated_bytes > e->peak_bytes)
        e->peak_bytes = e->allocated_bytes;
    if (old)
        memcpy(p, old, (old_count < count ? old_count : count) * item);
    release(e, old, old_count * item);
    return p;
}

#define TABLE_STORAGE(field, maximum)                                                              \
    bool wb_reserve_##field(struct wb_engine *e, size_t count)                                     \
    {                                                                                              \
        if (count > maximum)                                                                       \
            return false;                                                                          \
        if (count <= e->field##_capacity)                                                          \
            return true;                                                                           \
        size_t cap = e->field##_capacity ? e->field##_capacity : 1;                                \
        while (cap < count)                                                                        \
            cap = cap > maximum / 2 ? maximum : cap * 2;                                           \
        void *p = resize(e, e->field, e->field##_capacity, cap, sizeof *e->field);                 \
        if (!p)                                                                                    \
            return false;                                                                          \
        e->field = p;                                                                              \
        e->field##_capacity = cap;                                                                 \
        return true;                                                                               \
    }                                                                                              \
    void wb_free_##field(struct wb_engine *e)                                                      \
    {                                                                                              \
        release(e, e->field, e->field##_capacity * sizeof *e->field);                              \
        e->field = NULL;                                                                           \
        e->field##_capacity = 0;                                                                   \
    }
TABLE_STORAGE(links, WB_LINKS)
TABLE_STORAGE(candidates, WB_CANDIDATES)
TABLE_STORAGE(sources, WB_SOURCES)
TABLE_STORAGE(local, WB_ROUTES)
TABLE_STORAGE(drops, WB_ROUTES)
TABLE_STORAGE(requests, WB_REQUESTS)
TABLE_STORAGE(routes, WB_ROUTES)
TABLE_STORAGE(before, WB_ROUTES)
TABLE_STORAGE(scratch, WB_ROUTES)
TABLE_STORAGE(messages, WB_MESSAGES)
#undef TABLE_STORAGE

void wb_deinit(struct wb_engine *e)
{
    if (!e)
        return;
    wb_free_links(e);
    wb_free_candidates(e);
    wb_free_sources(e);
    wb_free_local(e);
    wb_free_drops(e);
    wb_free_requests(e);
    wb_free_routes(e);
    wb_free_before(e);
    wb_free_scratch(e);
    wb_free_messages(e);
    memset(e, 0, sizeof *e);
}
struct wb_memory wb_memory(const struct wb_engine *e)
{
    return (struct wb_memory){sizeof *e + e->allocated_bytes, sizeof *e + e->peak_bytes};
}
#define COLLECT(field, live)                                                                       \
    do                                                                                             \
    {                                                                                              \
        size_t n = 0;                                                                              \
        for (size_t i = 0; i < e->field##_capacity; i++)                                           \
            if (e->field[i].live)                                                                  \
                e->field[n++] = e->field[i];                                                       \
        if (n < e->field##_capacity)                                                               \
            memset(e->field + n, 0, (e->field##_capacity - n) * sizeof *e->field);                 \
        if (!n)                                                                                    \
            wb_free_##field(e);                                                                    \
        else if (n <= e->field##_capacity / 2)                                                     \
        {                                                                                          \
            void *p = resize(e, e->field, e->field##_capacity, n, sizeof *e->field);               \
            if (p)                                                                                 \
            {                                                                                      \
                e->field = p;                                                                      \
                e->field##_capacity = n;                                                           \
            }                                                                                      \
        }                                                                                          \
    } while (0)
void wb_collect(struct wb_engine *e)
{
    COLLECT(links, config.id);
    COLLECT(candidates, used);
    COLLECT(sources, used);
    COLLECT(local, used);
    COLLECT(drops, used);
    COLLECT(requests, used);
    if (!e->route_count)
        wb_free_routes(e);
    else if (e->route_count <= e->routes_capacity / 2)
    {
        void *p = resize(e, e->routes, e->routes_capacity, e->route_count, sizeof *e->routes);
        if (p)
        {
            e->routes = p;
            e->routes_capacity = e->route_count;
        }
    }
    /* Do not allocate/free two routing snapshots on every steady tick while
     * TLS and radio tasks compete for contiguous heap. Retain only observed
     * route-sized workspaces, shrink with the live topology, and release all
     * scratch space when no neighbour remains. Required protocol history is
     * independent and keeps its normal expiry. */
#define COLLECT_WORKSPACE(field)                                                               \
    do                                                                                        \
    {                                                                                         \
        if (!e->links_capacity || !e->route_count)                                            \
            wb_free_##field(e);                                                               \
        else if (e->route_count <= e->field##_capacity / 2)                                   \
        {                                                                                     \
            void *p = resize(e, e->field, e->field##_capacity, e->route_count,                 \
                             sizeof *e->field);                                               \
            if (p)                                                                            \
            {                                                                                 \
                e->field = p;                                                                 \
                e->field##_capacity = e->route_count;                                         \
            }                                                                                 \
        }                                                                                     \
    } while (0)
    COLLECT_WORKSPACE(before);
    COLLECT_WORKSPACE(scratch);
#undef COLLECT_WORKSPACE
}

#undef COLLECT
