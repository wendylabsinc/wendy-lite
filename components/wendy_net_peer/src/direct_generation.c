#include "wendy_net_direct_generation.h"
#include <string.h>
static bool mode_valid(enum wn_direct_mode mode)
{
    return mode == WN_DIRECT_BLE || mode == WN_DIRECT_PROMOTED;
}
int wn_direct_generation_init(struct wn_direct_generation *g, uint64_t generation, uint64_t token,
                              enum wn_direct_mode mode)
{
    if (!g || !generation || !token || !mode_valid(mode))
        return -1;
    memset(g, 0, sizeof *g);
    g->initialized = true;
    g->phase = WN_DIRECT_ACTIVE;
    g->mode = mode;
    g->generation = generation;
    g->reserved = generation;
    g->token = token;
    g->promotion = mode == WN_DIRECT_PROMOTED;
    return 0;
}
bool wn_direct_generation_next(const struct wn_direct_generation *g, uint64_t *next)
{
    if (!g || !next || !g->initialized || g->phase == WN_DIRECT_CLOSED || g->reserved == UINT64_MAX)
        return false;
    *next = g->reserved + 1;
    return true;
}
bool wn_direct_generation_allows(const struct wn_direct_generation *g, uint64_t token,
                                 uint64_t generation)
{
    return g && g->initialized && token && generation && g->phase == WN_DIRECT_ACTIVE &&
           token == g->token && generation == g->generation;
}
int wn_direct_generation_frozen(struct wn_direct_generation *g, uint64_t token)
{
    if (!g || !g->initialized || !token || g->phase != WN_DIRECT_ACTIVE || token != g->token ||
        g->mode == WN_DIRECT_PROMOTED)
        return -1;
    g->phase = WN_DIRECT_SUSPENDED;
    g->token = 0;
    return 0;
}
int wn_direct_generation_reserve(struct wn_direct_generation *g, uint64_t token,
                                 uint64_t generation, enum wn_direct_mode mode)
{
    if (!g || !g->initialized || !token || !mode_valid(mode))
        return -1;
    if (g->phase == WN_DIRECT_NEGOTIATING && g->pending_token == token &&
        g->pending_generation == generation && g->pending_mode == mode)
        return 0;
    if (g->phase != WN_DIRECT_SUSPENDED || generation <= g->reserved ||
        (g->promotion && mode != WN_DIRECT_PROMOTED))
        return -1;
    g->reserved = generation;
    g->pending_generation = generation;
    g->pending_token = token;
    g->pending_mode = mode;
    g->promotion = g->promotion || mode == WN_DIRECT_PROMOTED;
    g->phase = WN_DIRECT_NEGOTIATING;
    return 0;
}
int wn_direct_generation_begin(struct wn_direct_generation *g, uint64_t token, uint64_t generation,
                               enum wn_direct_mode mode, const uint8_t context[32])
{
    if (!g || !g->initialized || !context)
        return -1;
    if (token && token == g->pending_token && generation == g->pending_generation &&
        mode == g->pending_mode && !memcmp(context, g->context, 32) &&
        ((g->phase >= WN_DIRECT_PREPARING && g->phase <= WN_DIRECT_COMMITTING) ||
         (g->phase == WN_DIRECT_ACTIVE && g->generation == generation)))
        return 0;
    if (wn_direct_generation_reserve(g, token, generation, mode))
        return -1;
    memcpy(g->context, context, 32);
    g->phase = WN_DIRECT_PREPARING;
    return 0;
}
static bool matches(const struct wn_direct_generation *g, uint64_t token, uint64_t generation)
{
    return g && g->initialized && token && token == g->pending_token &&
           generation == g->pending_generation;
}
int wn_direct_generation_ready(struct wn_direct_generation *g, uint64_t token, uint64_t generation)
{
    if (!matches(g, token, generation))
        return -1;
    if (g->phase == WN_DIRECT_PREPARING) {
        g->phase = WN_DIRECT_READY;
        return 0;
    }
    return g->phase == WN_DIRECT_READY || g->phase == WN_DIRECT_COMMITTING ||
                   (g->phase == WN_DIRECT_ACTIVE && g->generation == generation)
               ? 0
               : -1;
}
int wn_direct_generation_commit(struct wn_direct_generation *g, uint64_t token, uint64_t generation)
{
    if (!matches(g, token, generation))
        return -1;
    if (g->phase == WN_DIRECT_READY) {
        g->phase = WN_DIRECT_COMMITTING;
        return 0;
    }
    return g->phase == WN_DIRECT_COMMITTING ||
                   (g->phase == WN_DIRECT_ACTIVE && g->generation == generation)
               ? 0
               : -1;
}
int wn_direct_generation_activate(struct wn_direct_generation *g, uint64_t token,
                                  uint64_t generation)
{
    if (!matches(g, token, generation))
        return -1;
    if (g->phase == WN_DIRECT_ACTIVE && g->generation == generation)
        return 0;
    if (g->phase != WN_DIRECT_COMMITTING)
        return -1;
    g->phase = WN_DIRECT_ACTIVE;
    g->generation = generation;
    g->token = token;
    g->mode = g->pending_mode;
    return 0;
}
bool wn_direct_generation_lost(struct wn_direct_generation *g, uint64_t token)
{
    if (!g)
        return false;
    bool active = g->phase == WN_DIRECT_ACTIVE && token && token == g->token;
    bool pending = g->phase >= WN_DIRECT_NEGOTIATING && g->phase <= WN_DIRECT_COMMITTING && token &&
                   token == g->pending_token;
    if (!active && !pending)
        return false;
    bool terminal =
        (active && g->mode == WN_DIRECT_PROMOTED) ||
        (pending && g->pending_mode == WN_DIRECT_PROMOTED && g->phase == WN_DIRECT_COMMITTING);
    g->phase = terminal ? WN_DIRECT_CLOSED : WN_DIRECT_SUSPENDED;
    g->token = 0;
    g->pending_token = 0;
    return true;
}
void wn_direct_generation_close(struct wn_direct_generation *g)
{
    if (!g)
        return;
    g->phase = WN_DIRECT_CLOSED;
    g->token = 0;
    g->pending_token = 0;
}

int wn_direct_generation_init_pending(struct wn_direct_generation *g)
{
    if (!g)
        return -1;
    memset(g, 0, sizeof *g);
    g->initialized = true;
    g->phase = WN_DIRECT_SUSPENDED;
    return 0;
}
