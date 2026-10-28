#include "wendy_net_peer_protocol.h"
#include <limits.h>
#include <string.h>

#define CANDIDATE_LIFETIME_MS 30000
#define FAILURE_PENALTY_MS 30000
#define FAILURE_RETRY_MS 5000

bool wn_link_replaces(const char *self, const char *peer,
                      bool incumbent_incoming, bool replacement_incoming)
{
    return incumbent_incoming != replacement_incoming &&
           replacement_incoming == (strcmp(self, peer) > 0);
}

void wn_selection_init(struct wn_selection *s)
{
    memset(s, 0, sizeof *s);
    s->active = -1;
}

static bool live(const struct wn_candidate *c, int64_t now)
{
    return c->address[0] && now >= c->seen_ms && now - c->seen_ms < CANDIDATE_LIFETIME_MS;
}

static bool recent_failure(const struct wn_candidate *c,int64_t now)
{
    return c->failures && now>=c->failed_ms && now-c->failed_ms<FAILURE_PENALTY_MS;
}
static bool replaceable(const struct wn_selection *s,unsigned i,int64_t now)
{
    const struct wn_candidate *c=&s->candidates[i];
    return (int)i!=s->active && !c->holds && now>=c->retry_ms && !recent_failure(c,now);
}
int wn_candidate_seen(struct wn_selection *s, const struct wn_candidate *hint, int64_t now)
{
    if (!s || !hint || now < 0 || now > INT64_MAX - 120000 ||
        !hint->address[0] || !memchr(hint->address, 0, sizeof hint->address) ||
        !memchr(hint->device, 0, sizeof hint->device) || !hint->port || !hint->cost ||
        hint->cost == UINT16_MAX || (hint->medium != WN_LAN && hint->medium != WN_BLE && hint->medium != WN_NAN)) return -1;
    uint8_t uuid[16];
    if (hint->device[0] && wn_uuid_parse(hint->device, uuid)) return -1;
    int slot = -1,fifo=-1;
    for (unsigned i = 0; i < WN_CANDIDATES; ++i) {
        struct wn_candidate *c = &s->candidates[i];
        if (c->medium == hint->medium && c->port == hint->port && !strcmp(c->address, hint->address)) {
            /* Repeated unauthenticated advertisements cannot erase cooldowns
             * or change the identity/cost of the currently selected path. */
            c->seen_ms = now;
            c->ble_capabilities=hint->ble_capabilities;
            if ((int)i != s->active && !c->holds) {
                /* BLE advertisements carry a short hint, not a full UUID.
                 * Preserve the expected TLS peer learned at this radio address
                 * so ordinary repeated reports do not trigger redundant dials.
                 * This cached name never bypasses certificate verification. */
                if(hint->device[0])memcpy(c->device, hint->device, sizeof c->device);
                c->cost = hint->cost;
                c->passive = hint->passive;
            }
            return (int)i;
        }
        if(replaceable(s,i,now)){
            if(!live(c,now) && (slot<0 || c->seen_ms<s->candidates[slot].seen_ms))slot=(int)i;
            if(fifo<0 || c->seen_ms<s->candidates[fifo].seen_ms)fifo=(int)i;
        }
    }
    /* Discovery refreshes cannot pin an unsuitable fresh hint forever.
     * Prefer empty/expired rows, then the oldest unconnected hint, preserving
     * actual physical owners and outstanding retry/failure receipts. */
    if(slot<0)slot=fifo;
    if (slot < 0) return -1;
    s->candidates[slot] = *hint;
    s->candidates[slot].seen_ms = now;
    s->candidates[slot].retry_ms = 0;
    s->candidates[slot].failed_ms = 0;
    s->candidates[slot].failures = 0;
    s->candidates[slot].holds = 0;
    return slot;
}

static uint32_t shuffle_random(uint32_t *state)
{
    /* Deterministic local generator, seeded once by the outer driver. This
     * shuffle is scheduling only and never supplies identity or key material. */
    uint32_t x=*state;x^=x<<13;x^=x>>17;x^=x<<5;*state=x;return x;
}
static bool failure_after(const struct wn_candidate *a,const struct wn_candidate *b,int64_t now)
{
    bool af=recent_failure(a,now),bf=recent_failure(b,now);
    return af!=bf ? af:af && a->failed_ms>b->failed_ms;
}
unsigned wn_candidate_order(const struct wn_selection *s,int64_t now,uint32_t random,
    unsigned out[WN_CANDIDATES])
{
    if(!s || !out || now<0)return 0;
    unsigned count=0;
    for(unsigned i=0;i<WN_CANDIDATES;i++){
        const struct wn_candidate *c=&s->candidates[i];
        if((int)i!=s->active && !c->holds && !c->passive && (c->medium!=WN_BLE || (c->ble_capabilities&WN_BLE_NATIVE_ACCEPTING)) && live(c,now) && now>=c->retry_ms)
            out[count++]=i;
    }
    uint32_t state=random ? random:UINT32_C(0x6d2b79f5);
    for(unsigned n=count;n>1;n--){
        unsigned at=shuffle_random(&state)%n,value=out[n-1];
        out[n-1]=out[at];out[at]=value;
    }
    /* Stable insertion sort matches CandidateQueue.Order's shuffle followed
     * by healthy-first/oldest-failure-first ordering. Bound is eight entries. */
    for(unsigned i=1;i<count;i++){
        unsigned value=out[i],at=i;
        while(at && failure_after(&s->candidates[out[at-1]],&s->candidates[value],now)){
            out[at]=out[at-1];at--;
        }
        out[at]=value;
    }
    return count;
}
int wn_candidate_next(const struct wn_selection *s,int64_t now)
{
    unsigned order[WN_CANDIDATES],count=wn_candidate_order(s,now,0,order);
    int best=-1;
    for(unsigned at=0;at<count;at++){
        unsigned i=order[at];const struct wn_candidate *c=&s->candidates[i];
        if(s->active>=0 && c->cost>=s->candidates[s->active].cost)continue;
        if(best<0 || c->cost<s->candidates[best].cost)best=(int)i;
    }
    return best;
}

int wn_candidate_time(const struct wn_selection *selection,int64_t now,unsigned cursor)
{
    if(!selection || now<0)return -1;
    for(unsigned step=0;step<WN_CANDIDATES;step++){
        unsigned i=(cursor+step)%WN_CANDIDATES;const struct wn_candidate *c=&selection->candidates[i];
        if(c->medium==WN_BLE && (c->ble_capabilities&WN_BLE_TIME_RELAY) && live(c,now))return (int)i;
    }
    return -1;
}
void wn_candidate_failed(struct wn_selection *s, unsigned slot, int64_t now)
{
    if (!s || slot >= WN_CANDIDATES || now < 0 || now > INT64_MAX - FAILURE_RETRY_MS) return;
    struct wn_candidate *c = &s->candidates[slot];
    if(!c->address[0])return;
    if (c->failures < 7) ++c->failures;
    c->failed_ms=now;
    c->retry_ms = now + FAILURE_RETRY_MS;
    if (s->active == (int)slot) s->active = -1;
}

int wn_candidate_authenticated(struct wn_selection *s,unsigned slot,const char *peer)
{
    uint8_t uuid[16];
    if(!s || slot>=WN_CANDIDATES || !s->candidates[slot].address[0] || wn_uuid_parse(peer,uuid))return -1;
    struct wn_candidate *c=&s->candidates[slot];
    if(c->device[0] && strcmp(c->device,peer))return -1;
    memcpy(c->device,peer,sizeof c->device);return 0;
}
int wn_candidate_commit(struct wn_selection *s, unsigned slot, const char *peer)
{
    if(wn_candidate_authenticated(s,slot,peer))return -1;
    struct wn_candidate *c=&s->candidates[slot];
    c->failures = 0;
    c->failed_ms = 0;
    c->retry_ms = 0;
    s->active = (int)slot;
    return 0;
}

int wn_candidate_hold(struct wn_selection *s,unsigned slot)
{
    if(!s || slot>=WN_CANDIDATES || !s->candidates[slot].address[0] ||
       s->candidates[slot].holds==UINT16_MAX)return -1;
    s->candidates[slot].holds++;return 0;
}
void wn_candidate_release(struct wn_selection *s,unsigned slot)
{
    if(s && slot<WN_CANDIDATES && s->candidates[slot].holds)s->candidates[slot].holds--;
}
